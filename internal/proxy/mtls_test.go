package proxy_test

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log"
	"math/big"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"aiproxy/internal/proxy"
	"aiproxy/internal/rules"
)

// generateTestCA creates a throwaway self-signed CA certificate and
// private key, entirely in memory — everything needed to both build a
// ClientCAPool (via its PEM-encoded certificate) and sign client
// certificates (via its private key) for a real mTLS handshake in a
// test, with no external dependency beyond the standard library.
func generateTestCA(t *testing.T) (certPEM []byte, cert *x509.Certificate, key *rsa.PrivateKey) {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "aiproxy test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	return pemBytes, caCert, priv
}

// signClientCert issues a client-auth certificate signed by caCert/caKey
// — a real tls.Certificate ready to plug into a test http.Client's own
// TLSClientConfig.Certificates for a genuine mTLS handshake.
func signClientCert(t *testing.T, commonName string, caCert *x509.Certificate, caKey *rsa.PrivateKey) tls.Certificate {
	t.Helper()

	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate client key: %v", err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: commonName},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, caCert, &priv.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create client certificate: %v", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(priv)})
	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("build tls.Certificate: %v", err)
	}
	return cert
}

// newMTLSTestServer starts a real aiproxy listener with server TLS and
// ClientCAPool both configured, returning the listening address and a
// cleanup func. clientCAPool may be nil to test the requires-TLSCertFile
// validation boundary elsewhere; every test here sets a real one.
func newMTLSTestServer(t *testing.T, targetURL *url.URL, clientCAPool *x509.CertPool, configure func(*proxy.Server)) (addr string, stop func()) {
	t.Helper()

	certFile, keyFile := generateSelfSignedCert(t)
	addr = freeLoopbackAddr(t)

	srv := proxy.New(addr, targetURL, rules.NewEngine(rules.Allow))
	srv.Logger = log.New(io.Discard, "", 0)
	srv.TLSCertFile = certFile
	srv.TLSKeyFile = keyFile
	srv.ClientCAPool = clientCAPool
	if configure != nil {
		configure(srv)
	}

	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- srv.ListenAndServe(ctx) }()
	waitForServerUp(t, addr, time.Second)

	return addr, func() {
		cancel()
		select {
		case <-done:
		case <-time.After(2 * time.Second):
			t.Fatal("ListenAndServe did not shut down in time")
		}
	}
}

// httpsClient builds an *http.Client for a real TLS/mTLS handshake
// against a test server using a self-signed (untrusted) server
// certificate — certs, if non-empty, are presented as the client's own
// certificate.
func httpsClient(certs ...tls.Certificate) *http.Client {
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true,
		Certificates:       certs,
	}}}
}

// TestServer_MTLS_RejectsConnectionWithNoClientCertificate proves the
// core mechanism: once ClientCAPool is set, a client that presents no
// certificate at all is refused during the TLS handshake itself — the
// request never even reaches ServeHTTP.
func TestServer_MTLS_RejectsConnectionWithNoClientCertificate(t *testing.T) {
	var upstreamHit bool
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamHit = true
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	_, caCert, _ := generateTestCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)

	addr, stop := newMTLSTestServer(t, targetURL, pool, nil)
	defer stop()

	client := httpsClient() // no client certificate at all
	_, err = client.Get("https://" + addr + "/endpoint")
	if err == nil {
		t.Fatal("request with no client certificate succeeded, want a TLS handshake failure")
	}
	if upstreamHit {
		t.Fatal("upstream was reached despite the missing client certificate")
	}
}

// TestServer_MTLS_AcceptsConnectionWithValidClientCertificateSignedByTrustedCA
// proves the positive case: a client certificate genuinely signed by
// the configured CA is accepted, and the request proceeds normally.
func TestServer_MTLS_AcceptsConnectionWithValidClientCertificateSignedByTrustedCA(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte("ok"))
	}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	_, caCert, caKey := generateTestCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	clientCert := signClientCert(t, "trusted-client", caCert, caKey)

	addr, stop := newMTLSTestServer(t, targetURL, pool, nil)
	defer stop()

	resp, err := httpsClient(clientCert).Get("https://" + addr + "/endpoint")
	if err != nil {
		t.Fatalf("request with a valid client certificate failed: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
	body, _ := io.ReadAll(resp.Body)
	if string(body) != "ok" {
		t.Fatalf("body = %q, want %q", body, "ok")
	}
}

// TestServer_MTLS_RejectsClientCertificateSignedByAnUntrustedCA proves
// ClientCAPool is genuinely enforced, not just "any certificate will
// do" — a certificate that's otherwise well-formed but signed by a
// DIFFERENT CA (not in the configured pool) is still refused.
func TestServer_MTLS_RejectsClientCertificateSignedByAnUntrustedCA(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	_, trustedCACert, _ := generateTestCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(trustedCACert)

	// A second, independent CA that the server never trusts.
	_, untrustedCACert, untrustedCAKey := generateTestCA(t)
	untrustedClientCert := signClientCert(t, "untrusted-client", untrustedCACert, untrustedCAKey)

	addr, stop := newMTLSTestServer(t, targetURL, pool, nil)
	defer stop()

	_, err = httpsClient(untrustedClientCert).Get("https://" + addr + "/endpoint")
	if err == nil {
		t.Fatal("request with a certificate from an untrusted CA succeeded, want a TLS handshake failure")
	}
}

// TestServer_MTLS_ComposesWithProxyAPIKey_BothRequired proves mTLS and
// proxy_api_key are genuinely independent, additive gates — presenting
// a valid client certificate satisfies the TLS handshake but must not
// exempt the request from also needing a valid Proxy-Authorization key
// once one is configured.
func TestServer_MTLS_ComposesWithProxyAPIKey_BothRequired(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	_, caCert, caKey := generateTestCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	clientCert := signClientCert(t, "trusted-client", caCert, caKey)

	addr, stop := newMTLSTestServer(t, targetURL, pool, func(s *proxy.Server) {
		s.ProxyAPIKey = "s3cr3t"
	})
	defer stop()

	// Valid client certificate, but no Proxy-Authorization header at
	// all: the TLS handshake succeeds (mTLS is satisfied), but the
	// HTTP-level request must still be rejected.
	resp, err := httpsClient(clientCert).Get("https://" + addr + "/endpoint")
	if err != nil {
		t.Fatalf("request with a valid client certificate (no proxy key): %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusProxyAuthRequired {
		t.Fatalf("status = %d, want %d (mTLS must not exempt a request from proxy_api_key)", resp.StatusCode, http.StatusProxyAuthRequired)
	}

	// Both satisfied together: the request goes through.
	req, err := http.NewRequest(http.MethodGet, "https://"+addr+"/endpoint", nil)
	if err != nil {
		t.Fatalf("build request: %v", err)
	}
	req.Header.Set("Proxy-Authorization", "Bearer s3cr3t")
	resp2, err := httpsClient(clientCert).Do(req)
	if err != nil {
		t.Fatalf("request with both a valid client certificate and proxy key: %v", err)
	}
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200 once both gates are satisfied", resp2.StatusCode)
	}
}

// TestServer_MTLS_AdminAddrAlsoRequiresClientCertificate proves
// ClientCAPool protects AdminAddr's own listener exactly like the main
// one — "both listeners end up on equal footing" per ClientCAPool's own
// doc comment, the same reasoning TLSCertFile/TLSKeyFile already follow.
func TestServer_MTLS_AdminAddrAlsoRequiresClientCertificate(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	defer upstream.Close()
	targetURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	_, caCert, caKey := generateTestCA(t)
	pool := x509.NewCertPool()
	pool.AddCert(caCert)
	clientCert := signClientCert(t, "trusted-client", caCert, caKey)

	adminAddr := freeLoopbackAddr(t)
	_, stop := newMTLSTestServer(t, targetURL, pool, func(s *proxy.Server) {
		s.AdminAddr = adminAddr
	})
	defer stop()
	waitForServerUp(t, adminAddr, time.Second)

	if _, err := httpsClient().Get("https://" + adminAddr + "/_aiproxy/stats"); err == nil {
		t.Fatal("admin surface accepted a connection with no client certificate, want a TLS handshake failure")
	}

	resp, err := httpsClient(clientCert).Get("https://" + adminAddr + "/_aiproxy/stats")
	if err != nil {
		t.Fatalf("admin surface request with a valid client certificate: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d, want 200", resp.StatusCode)
	}
}
