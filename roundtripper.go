package forward_https

// modified from traefik
import (
	"crypto/tls"
	"golang.org/x/net/http/httpguts"
	"golang.org/x/net/http2"
	"net"
	"net/http"
	"time"
)

type h2cTransportWrapper struct {
	*http2.Transport
}

func (t *h2cTransportWrapper) RoundTrip(req *http.Request) (*http.Response, error) {
	req.URL.Scheme = "https"
	return t.Transport.RoundTrip(req)
}

// createRoundtripper creates an http.Roundtripper configured with the Transport configuration settings.
// For the settings that can't be configured in Traefik it uses the default http.Transport settings.
// An exception to this is the MaxIdleConns setting as we only provide the option MaxIdleConnsPerHost
// in Traefik at this point in time. Setting this value to the default of 100 could lead to confusing
// behavior and backwards compatibility issues.
func createRoundtripper(tlsConfig *tls.Config) (http.RoundTripper, error) {
	dialer := &net.Dialer{
		Timeout:   30 * time.Second,
		KeepAlive: 30 * time.Second,
		DualStack: true,
	}

	transport := &http.Transport{
		Proxy:                 http.ProxyFromEnvironment,
		DialContext:           dialer.DialContext,
		MaxIdleConnsPerHost:   40,
		IdleConnTimeout:       90 * time.Second,
		TLSHandshakeTimeout:   10 * time.Second,
		ExpectContinueTimeout: 1 * time.Second,
	}
	transport.TLSClientConfig = tlsConfig
	transport.RegisterProtocol("h2", &h2cTransportWrapper{
		Transport: &http2.Transport{
			TLSClientConfig: tlsConfig,
			AllowHTTP:       false,
		},
	})

	smartTransport, err := newSmartRoundTripper(transport)
	if err != nil {
		return nil, err
	}

	return smartTransport, nil
}

func newSmartRoundTripper(transport *http.Transport) (http.RoundTripper, error) {
	transportHTTP1 := transport.Clone()

	err := http2.ConfigureTransport(transport)
	if err != nil {
		return nil, err
	}

	return &smartRoundTripper{
		http2: transport,
		http:  transportHTTP1,
	}, nil
}

type smartRoundTripper struct {
	http2 *http.Transport
	http  *http.Transport
}

// smartRoundTripper implements RoundTrip while making sure that HTTP/2 is not used
// with protocols that start with a Connection Upgrade, such as SPDY or Websocket.
func (m *smartRoundTripper) RoundTrip(req *http.Request) (*http.Response, error) {
	// If we have a connection upgrade, we don't use HTTP/2
	if httpguts.HeaderValuesContainsToken(req.Header["Connection"], "Upgrade") {
		return m.http.RoundTrip(req)
	}
	return m.http2.RoundTrip(req)
}

// StatusClientClosedRequest non-standard HTTP status code for client disconnection.
const StatusClientClosedRequest = 499

// StatusClientClosedRequestText non-standard HTTP status for client disconnection.
const StatusClientClosedRequestText = "Client Closed Request"

func statusText(statusCode int) string {
	if statusCode == StatusClientClosedRequest {
		return StatusClientClosedRequestText
	}
	return http.StatusText(statusCode)
}