package auth

import (
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func NewBearerTokenFileClient(tokenFile, caFile string, timeout time.Duration) (*http.Client, error) {
	tokenBytes, err := os.ReadFile(tokenFile)
	if err != nil {
		return nil, fmt.Errorf("read token file %q: %w", tokenFile, err)
	}
	return NewBearerTokenClient(strings.TrimSpace(string(tokenBytes)), caFile, timeout)
}

func NewBearerTokenClient(token, caFile string, timeout time.Duration) (*http.Client, error) {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	if strings.TrimSpace(caFile) != "" {
		caBytes, err := os.ReadFile(caFile)
		if err != nil {
			return nil, fmt.Errorf("read ca file %q: %w", caFile, err)
		}
		pool := x509.NewCertPool()
		if !pool.AppendCertsFromPEM(caBytes) {
			return nil, fmt.Errorf("append CA from %q failed", caFile)
		}
		transport.TLSClientConfig = &tls.Config{RootCAs: pool}
	}

	return &http.Client{
		Timeout: timeout,
		Transport: &bearerAuthTransport{
			token:      token,
			underlying: transport,
		},
	}, nil
}

type bearerAuthTransport struct {
	token      string
	underlying http.RoundTripper
}

func (t *bearerAuthTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	clone := req.Clone(req.Context())
	clone.Header.Set("Authorization", "Bearer "+t.token)
	return t.underlying.RoundTrip(clone)
}
