package main

import (
	"context"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/auxk0rd03/AutoD0rker/gateway/cmd/gateway/secguard"
)

// startSSRFSafeSPAProxy starts an ephemeral loopback-only HTTP + CONNECT forward proxy
// for headless Chromium / Playwright Stage-0 hydration, validating every destination host/IP
// against secguard SSRF policy before dialing outbound.
func startSSRFSafeSPAProxy(allowLocalStaging bool) (proxyURL string, shutdown func(), err error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", nil, err
	}

	dialSafe := func(ctx context.Context, network, addr string) (net.Conn, error) {
		host, port, splitErr := net.SplitHostPort(addr)
		if splitErr != nil {
			host = addr
			port = "443"
		}
		checkURL := fmt.Sprintf("https://%s/", net.JoinHostPort(host, port))
		if ssrfErr := secguard.ValidateTargetSSRF(checkURL, allowLocalStaging); ssrfErr != nil {
			return nil, ssrfErr
		}
		ips, dnsErr := net.LookupIP(host)
		if dnsErr != nil || len(ips) == 0 {
			return nil, fmt.Errorf("DNS failed for %s: %v", host, dnsErr)
		}
		var chosen net.IP
		for _, ip := range ips {
			if secguard.IsBlockedIP(ip, allowLocalStaging) {
				return nil, fmt.Errorf("SSRF blocked IP %s for %s", ip, host)
			}
			if chosen == nil || ip.To4() != nil {
				chosen = ip
			}
			if ip.To4() != nil {
				break
			}
		}
		if chosen == nil {
			return nil, fmt.Errorf("no permissible IP for %s", host)
		}
		d := &net.Dialer{Timeout: 12 * time.Second}
		return d.DialContext(ctx, "tcp", net.JoinHostPort(chosen.String(), port))
	}

	transport := &http.Transport{
		DialContext:           dialSafe,
		TLSHandshakeTimeout:   10 * time.Second,
		ResponseHeaderTimeout: 15 * time.Second,
	}

	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.EqualFold(r.Method, http.MethodConnect) {
			destConn, dialErr := dialSafe(r.Context(), "tcp", r.Host)
			if dialErr != nil {
				http.Error(w, "SSRF Proxy Blocked CONNECT", http.StatusForbidden)
				return
			}
			hij, ok := w.(http.Hijacker)
			if !ok {
				_ = destConn.Close()
				http.Error(w, "Hijacking unsupported", http.StatusInternalServerError)
				return
			}
			clientConn, _, hijErr := hij.Hijack()
			if hijErr != nil {
				_ = destConn.Close()
				return
			}
			_, _ = io.WriteString(clientConn, "HTTP/1.1 200 Connection Established\r\n\r\n")
			go func() {
				defer destConn.Close()
				defer clientConn.Close()
				_, _ = io.Copy(destConn, clientConn)
			}()
			go func() {
				defer destConn.Close()
				defer clientConn.Close()
				_, _ = io.Copy(clientConn, destConn)
			}()
			return
		}

		if r.URL == nil || (r.URL.Scheme != "http" && r.URL.Scheme != "https") {
			http.Error(w, "Absolute http/https target URL required", http.StatusBadRequest)
			return
		}
		if ssrfErr := secguard.ValidateTargetSSRF(r.URL.String(), allowLocalStaging); ssrfErr != nil {
			http.Error(w, "SSRF Proxy Blocked Request", http.StatusForbidden)
			return
		}

		outReq := r.Clone(r.Context())
		outReq.RequestURI = ""
		resp, rtErr := transport.RoundTrip(outReq)
		if rtErr != nil {
			http.Error(w, "Upstream error", http.StatusBadGateway)
			return
		}
		defer resp.Body.Close()
		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)
		_, _ = io.Copy(w, resp.Body)
	})

	srv := &http.Server{
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
	}
	go func() {
		_ = srv.Serve(ln)
	}()

	stop := func() {
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = srv.Shutdown(ctx)
		_ = ln.Close()
	}
	return "http://" + ln.Addr().String(), stop, nil
}
