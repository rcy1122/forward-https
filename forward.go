// Package https a demo forward plugin.
package forward_https

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"net/http/httputil"
	"net/url"
	"os"
	"strings"
	"time"
)

const (
// services = "services"
// port     = "port"
)

type FileOrContent string

func (f FileOrContent) String() string {
	return string(f)
}

// IsPath returns true if the FileOrContent is a file path, otherwise returns false.
func (f FileOrContent) IsPath() bool {
	_, err := os.Stat(f.String())
	return err == nil
}

func (f FileOrContent) Read() ([]byte, error) {
	var content []byte
	if f.IsPath() {
		var err error
		content, err = ioutil.ReadFile(f.String())
		if err != nil {
			return nil, err
		}
	} else {
		content = []byte(f)
	}
	return content, nil
}

// Config the plugin configuration.
type Config struct {
	RootCA      FileOrContent `json:"rootCA, omitempty"`
	AuthAddress string        `json:"authAddress, omitempty"`
	Port        string        `json:"port, omitempty"`
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		RootCA:      "",
		AuthAddress: "",
		Port:        "17051",
	}
}

type Forward struct {
	name         string
	next         http.Handler
	config       *Config
	client       *http.Client
	tr           http.RoundTripper
	errorHandler func(http.ResponseWriter, *http.Request, error)
}

func New(ctx context.Context, next http.Handler, config *Config, name string) (http.Handler, error) {
	if len(config.RootCA) == 0 {
		return nil, fmt.Errorf("add CA file or content for plugin ")
	}

	fa := &Forward{
		name:   name,
		config: config,
		next:   next,
	}

	if config.RootCA.IsPath() {
		log.Printf("root ca path: %s", config.RootCA.String())
	}

	fa.client = &http.Client{
		// CheckRedirect: func(r *http.Request, via []*http.Request) error {
		// 	return http.ErrUseLastResponse
		// },
		Timeout: 30 * time.Second,
	}

	tlsConfig, err := fa.createTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("create tls config: %w", err)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsConfig

	fa.client.Transport = tr

	rtr, err := createRoundtripper(tlsConfig)
	if err != nil {
		return nil, fmt.Errorf("create roundtripper: %w", err)
	}

	fa.tr = rtr
	fa.errorHandler = func(w http.ResponseWriter, request *http.Request, err error) {
		statusCode := http.StatusInternalServerError

		switch {
		case errors.Is(err, io.EOF):
			statusCode = http.StatusBadGateway
		case errors.Is(err, context.Canceled):
			statusCode = StatusClientClosedRequest
		default:
			var netErr net.Error
			if errors.As(err, &netErr) {
				if netErr.Timeout() {
					statusCode = http.StatusGatewayTimeout
				} else {
					statusCode = http.StatusBadGateway
				}
			}
		}

		fmt.Printf("'%d %s' caused by: %v \n", statusCode, statusText(statusCode), err)
		w.WriteHeader(statusCode)
		_, werr := w.Write([]byte(statusText(statusCode)))
		if werr != nil {
			fmt.Println("Error while writing status code", werr)
		}
	}
	log.Println("config.AuthAddress: ", fa.config.AuthAddress)
	return fa, nil
}

func (fa *Forward) createTLSConfig() (*tls.Config, error) {
	ca, err := fa.config.RootCA.Read()
	if err != nil {
		return nil, fmt.Errorf("failed to read CA: %w", err)
	}
	caPool := x509.NewCertPool()
	if !caPool.AppendCertsFromPEM(ca) {
		return nil, fmt.Errorf("failed to parse CA")
	}

	return &tls.Config{
		RootCAs:            caPool,
		InsecureSkipVerify: false,
	}, nil
}

func (fa *Forward) createProxy(rw http.ResponseWriter, req *http.Request) *httputil.ReverseProxy {
	host, port := fa.queryForwardAddressPort(req)
	if port == "" {
		port = fa.config.Port
	}
	remote, err := url.Parse(fmt.Sprintf("h2://%s:%s", host, port))
	if err != nil {
		logMessage := fmt.Sprintf("error assembly request %s. Cause: %s", req.URL.Path, err)
		log.Printf(logMessage)
		rw.WriteHeader(http.StatusBadRequest)
		return nil
	}
	log.Printf("forward to %v\n", remote)
	proxy := httputil.NewSingleHostReverseProxy(remote)
	proxy.Transport = fa.tr
	proxy.FlushInterval = 100 * time.Millisecond
	proxy.ErrorHandler = fa.errorHandler
	return proxy
}

func (fa *Forward) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	start := time.Now()
	defer func() {
		log.Println("Plugin ServeHTTP spend time", time.Since(start))
	}()
	log.Println("\nreceive request: ", req.URL.String(), req.Host, req.URL.Path, req.Header.Get("content-type"))
	allow, err := fa.authorityAuthentication(req)
	if err != nil {
		logMessage := fmt.Sprintf("error calling authorization service: %s. Cause: %s", fa.config.AuthAddress, err)
		log.Printf(logMessage)
		rw.WriteHeader(http.StatusNetworkAuthenticationRequired)
		return
	}
	if allow == false {
		rw.WriteHeader(http.StatusForbidden)
		return
	}

	log.Println("start forward request: ", req.URL.String(), req.Host, req.URL.Path)
	log.Printf("forward header: %v \n", req.Header)
	proxy := fa.createProxy(rw, req)

	if proxy != nil {
		proxy.ServeHTTP(rw, req)
	}
}

func (fa *Forward) authorityAuthentication(req *http.Request) (bool, error) {
	if len(fa.config.AuthAddress) == 0 {
		return false, errors.New("specify authentication link ")
	}

	if req.TLS == nil {
		return false, errors.New("conn tls state is nil")
	}
	allow, err := fa.requestAuthorization(req)
	if err != nil {
		return false, fmt.Errorf("authorization: %w", err)
	}
	return allow, nil
}

type Enforce struct {
	Data *Data `description:"Response detail. data = {} . " json:"data"`
}

type Data struct {
	Allow bool `description:"allow in access control."  json:"allow"`
}

func (fa *Forward) requestAuthorization(req *http.Request) (bool, error) {
	forwardReq, err := http.NewRequest(http.MethodGet, fa.config.AuthAddress, nil)
	if err != nil {
		return false, fmt.Errorf("new request: %w ", err)
	}
	conn := req.TLS
	sub := ""
	log.Printf("VerifiedChains len: %d", len(conn.VerifiedChains))
	for _, k := range conn.VerifiedChains {
		for _, v := range k {
			log.Printf("Issuer: %v, Subject: %v", v.Issuer, v.Subject)
			for _, k := range v.OCSPServer {
				log.Println("k ocsp server", k)
			}
			if len(v.Subject.Organization) == 1 {
				sub = v.Subject.Organization[0]
			}
			if sub != "" {
				break
			}
		}
	}
	if sub == "" {
		log.Println("no sub info")
		return false, nil
	}
	objs := strings.Split(req.Host, ".")
	q := req.URL.Query()
	q.Set("sub", sub)
	q.Set("obj", objs[0])
	q.Set("act", "conn")
	forwardReq.URL.RawQuery = q.Encode()

	resp, err := fa.client.Do(forwardReq)
	if err != nil {
		return false, fmt.Errorf("calling request %s, err: %w ", fa.config.AuthAddress, err)
	}
	defer resp.Body.Close()
	b, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("read body: %w", err)
	}

	var o Enforce
	if err := json.Unmarshal(b, &o); err != nil {
		return false, fmt.Errorf("unmarshal: %w", err)
	}
	log.Printf("Authorization Request: %s, %s, %s ---> %v", q.Get("sub"), q.Get("obj"), "conn", o.Data.Allow)
	return o.Data.Allow, nil
}

func (fa *Forward) queryForwardAddressPort(req *http.Request) (string, string) {
	host, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		log.Printf("Unable to split host and port: %v. Fallback to request host.", err)
		host = req.Host
	}
	return host, port
}
