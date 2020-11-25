// Package https a demo forward plugin.
package forward_https

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"fmt"
	"io/ioutil"
	"log"
	"net/http"
	"net/url"
	"os"
	"time"
)

const (
	services = "services"
	port     = "port"
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
}

// CreateConfig creates the default plugin configuration.
func CreateConfig() *Config {
	return &Config{
		RootCA:      "",
		AuthAddress: "",
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
		CheckRedirect: func(r *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
		Timeout: 30 * time.Second,
	}

	tlsConfig, err := fa.createTLSConfig()
	if err != nil {
		return nil, fmt.Errorf("create tls config: %w", err)
	}
	tr := http.DefaultTransport.(*http.Transport).Clone()
	tr.TLSClientConfig = tlsConfig

	fa.client.Transport = tr
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
	log.Println("receive request: ", req.URL.Path)

	if err := fa.authorityAuthentication(req); err != nil {
		logMessage := fmt.Sprintf("error calling authorization service %s. Cause: %s", fa.config.AuthAddress, err)
		log.Printf(logMessage)
		rw.WriteHeader(http.StatusNetworkAuthenticationRequired)
		return
	}

	forwardReq, err := fa.forwardRequest(req)
	if err != nil {
		logMessage := fmt.Sprintf("error assembly request %s. Cause: %s", req.URL.Path, err)
		log.Printf(logMessage)
		return
	}
	log.Println("forward request path: ", forwardReq.URL.Path)

	_, forwardErr := fa.client.Do(forwardReq)
	if forwardErr != nil {
		logMessage := fmt.Sprintf("error forward request %s. Cause: %s", forwardReq.URL.String(), forwardErr)
		log.Println(logMessage)
		rw.WriteHeader(http.StatusInternalServerError)
		return
	}
	// body, readError := ioutil.ReadAll(forwardResponse.Body)
	// if readError != nil {
	// 	logMessage := fmt.Sprintf("error reading body %s. Cause: %s", forwardReq.URL.String(), readError)
	// 	log.Println(logMessage)
	// 	rw.WriteHeader(http.StatusInternalServerError)
	// 	return
	// }
	// defer forwardResponse.Body.Close()
	// if _, err = rw.Write(body); err != nil {
	// 	logMessage := fmt.Sprintf("error write to client. Cause: %s", readError)
	// 	log.Println(logMessage)
	// 	return
	// }
	req.RequestURI = forwardReq.URL.RequestURI()
	fa.next.ServeHTTP(rw, req)
}

func (fa *Forward) authorityAuthentication(req *http.Request) error {
	if req.TLS != nil {
		log.Printf("receive requet tls ver %v", req.TLS.VerifiedChains)
		log.Printf("receive requet tls verify length %v", len(req.TLS.VerifiedChains))
		log.Printf("receive requet handleshake %v", req.TLS.HandshakeComplete)
	}
	if len(fa.config.AuthAddress) == 0 {
		return errors.New("specify authentication link ")
	}
	return nil
}

func (fa *Forward) forwardRequest(req *http.Request) (*http.Request, error) {
	m, err := url.ParseQuery(req.URL.RawQuery)
	if err != nil {
		return nil, fmt.Errorf("parse query from url: %w", err)
	}
	if _, ok := m[services]; !ok {
		return nil, fmt.Errorf("the parameter is missing the service name ")
	}
	if _, ok := m[port]; !ok {
		return nil, fmt.Errorf("the parameter is missing the service port ")
	}

	u := bytes.Buffer{}
	u.WriteString("https://")
	u.WriteString(m[services][0])
	u.WriteString(fmt.Sprintf(":%v", m[port][0]))
	u.WriteString(req.URL.Path)
	r, err := http.NewRequest(req.Method, u.String(), req.Body)
	if err != nil {
		return nil, fmt.Errorf("new request: %w", err)
	}
	r.Header = req.Header
	return r, nil
}
