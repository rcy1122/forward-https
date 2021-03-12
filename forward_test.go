package forward_https

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

const (
	services = "services"
	port     = "port"
)

func TestNew(t *testing.T) {
	cfg := CreateConfig()
	cfg.RootCA = "../example/root-ca.crt"
	cfg.AuthAddress = "https://localhost/health?" + services + "=server&" + port + ":443"
	ctx := context.Background()

	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	handler, err := New(ctx, next, cfg, "forward-https")
	if err != nil {
		t.Fatal(err)
	}
	recorder := httptest.NewRecorder()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, "http://localhost:1992/adsf", strings.NewReader("Hello"))
	if err != nil {
		t.Fatal(err)
	}
	handler.ServeHTTP(recorder, req)
}
