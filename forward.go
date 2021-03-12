// Package https a demo forward plugin.
package forward_https

import (
	"bytes"
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
	name   string
	next   http.Handler
	config *Config
	client *http.Client
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
		Timeout: 60 * time.Second,
	}

	tlsConfig, err := fa.createTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("create tls config: %w", err)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsConfig

	fa.client.Transport = tr
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

func (fa *Forward) ServeHTTP(rw http.ResponseWriter, req *http.Request) {
	start := time.Now()
	defer func() {
		log.Println("Plugin ServeHTTP spend time", time.Since(start))
	}()
	log.Println("receive request: ", req.URL.String(), req.Host, req.URL.Path, req.Header.Get("content-type"))
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
	forwardReq, err := fa.forwardRequest(req)
	if err != nil {
		logMessage := fmt.Sprintf("error assembly request %s. Cause: %s", req.URL.Path, err)
		log.Printf(logMessage)
		rw.WriteHeader(http.StatusBadRequest)
		return
	}

	forwardResponse, forwardErr := fa.client.Do(forwardReq)
	log.Println("end forward request: ", forwardReq.URL.String(), forwardReq.Host, forwardReq.URL.Path)
	if forwardErr != nil {
		logMessage := fmt.Sprintf("error forward request %s. Cause: %s", forwardReq.URL.String(), forwardErr)
		log.Println(logMessage)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	log.Printf("end forward header: %v \n", forwardResponse.Header)

	var body strings.Builder
	buf := make([]byte, 256)
	for {
		n, err := forwardResponse.Body.Read(buf)
		if err != nil {
			if err != io.EOF {
				fmt.Println("read error:", err)
			}
			break
		}
		body.Write(buf[:n])
	}

	// body := make([]byte, 4096)
	// r := bufio.NewReader(forwardResponse.Body)
	// _, readError := r.Read(body)
	// if readError != nil {
	//
	// 	// }
	//
	// body, readError := ioutil.ReadAll(forwardResponse.Body)
	// if readError != nil {
	// 	log.Printf("end forward header: %v \n", forwardResponse.Header)
	// 	//
	// 	logMessage := fmt.Sprintf("error reading body %s. Cause: %s", forwardReq.URL.String(), readError)
	// 	log.Println(logMessage)
	// 	rw.WriteHeader(http.StatusInternalServerError)
	// 	return
	// }

	defer forwardResponse.Body.Close()
	log.Printf("resp: %s, body: %s \n", forwardReq.URL.String(), body.String())

	for k, v := range forwardResponse.Header {
		log.Printf("resp: %s, hk: %s, v: %s \n", forwardReq.URL.String(), k, v)
		for _, vv := range v {
			rw.Header().Add(k, vv)
		}
	}

	log.Printf("resp: %s, forwardResponse.Trailer => %s \n", forwardReq.URL.String(), forwardResponse.Trailer)
	for k, v := range forwardResponse.Trailer {
		log.Printf("resp: %s, tk: %s, v: %s \n", forwardReq.URL.String(), k, v)
		for _, vv := range v {
			rw.Header().Add(http.TrailerPrefix+k, vv)
		}
	}

	if _, err = rw.Write([]byte(body.String())); err != nil {
		logMessage := fmt.Sprintf("error write to client. Cause: %s", err)
		log.Println(logMessage)
		return
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

func (fa *Forward) forwardRequest(r1 *http.Request) (*http.Request, error) {
	// r2 := r1.Clone(context.Background())
	// r2.Body = ioutil.NopCloser(bytes.NewBuffer(reqData))
	// r1.Body = ioutil.NopCloser(bytes.NewBuffer(reqData))
	//
	// r2.URL, err = url.Parse(r1.URL.String())
	// if err != nil {
	// 	return nil , fmt.Errorf("parse r1 url, %w", err)
	// }

	host, port := fa.queryForwardAddressPort(r1)
	u := bytes.Buffer{}
	// if port == "" {
	// 	port = fa.config.Port
	// }
	// if port == "80" {
	// 	u.WriteString("http://")
	// } else {

	u.WriteString("https://")

	// }
	u.WriteString(host)
	u.WriteString(fmt.Sprintf(":%s", port))
	u.WriteString(r1.URL.Path)
	//
	forwardUrl := u.String()
	log.Println("forward to => ", forwardUrl)

	r2, err := http.NewRequest(r1.Method, forwardUrl, r1.Body)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	r2.Header = r1.Header
	return r2, nil
}

func (fa *Forward) queryForwardAddressPort(req *http.Request) (string, string) {
	host, port, err := net.SplitHostPort(req.Host)
	if err != nil {
		log.Printf("Unable to split host and port: %v. Fallback to request host.", err)
		host = req.Host
	}
	return host, port
}
