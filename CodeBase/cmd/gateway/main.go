//go:debug fips140=on

package main

import (
	"context"
	"crypto/fips140"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"syscall"
	"time"
)

func strictLocalSecurityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set(
			"Content-Security-Policy",
			"default-src 'self'; style-src 'self' 'unsafe-inline'; script-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'",
		)
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("Referrer-Policy", "no-referrer")
		next.ServeHTTP(w, r)
	})
}

func acquireLoopbackListener(preferred string) (net.Listener, string, error) {
	if err := enforceLoopbackAddress(preferred); err != nil {
		return nil, "", err
	}
	if ln, err := net.Listen("tcp", preferred); err == nil {
		return ln, preferred, nil
	}

	host, _, _ := net.SplitHostPort(preferred)
	for port := 8000; port <= 8100; port++ {
		cand := net.JoinHostPort(host, strconv.Itoa(port))
		if err := enforceLoopbackAddress(cand); err != nil {
			continue
		}
		if ln, err := net.Listen("tcp", cand); err == nil {
			return ln, cand, nil
		}
	}
	return nil, "", fmt.Errorf("no available loopback port in 8000-8100")
}

func main() {
	bindFlag := flag.String("bind", "", "Loopback bind address (default 127.0.0.1:8090)")
	flag.Parse()

	bindAddr := *bindFlag
	if bindAddr == "" {
		bindAddr = os.Getenv("AUTODORKER_BIND_ADDR")
	}
	if bindAddr == "" {
		bindAddr = "127.0.0.1:8090"
	}

	if err := enforceLoopbackAddress(bindAddr); err != nil {
		log.Fatalf("[ERR_HALT] %v", err)
	}

	paths := resolveAppPaths()
	_ = os.MkdirAll(paths.OutputDir, 0750)
	_ = os.MkdirAll(paths.BackupDir, 0750)

	// Ensure DorkSet.csv is seeded on startup if DB is empty
	state := fetchDashboardState(paths)
	if state.DorkCount == 0 {
		if _, err := os.Stat(paths.DorkSetCSV); err == nil {
			_, _, _ = runSubprocess(
				context.Background(),
				15*time.Second,
				paths,
				resolveSpiderBin(paths),
				"--ingest-csv", paths.DorkSetCSV,
				"--db", paths.DBPath,
			)
		}
	}

	hub := NewSSEHub()
	mux := http.NewServeMux()
	registerRoutes(mux, paths, hub)

	ln, actualAddr, err := acquireLoopbackListener(bindAddr)
	if err != nil {
		log.Fatalf("[ERR_HALT] %v", err)
	}

	srv := &http.Server{
		Addr:              actualAddr,
		Handler:           strictLocalSecurityHeaders(mux),
		ReadHeaderTimeout: 5 * time.Second,
		WriteTimeout:      90 * time.Second,
		IdleTimeout:       120 * time.Second,
	}

	fipsState := "STANDARD"
	if fips140.Enabled() {
		fipsState = "FIPS-140-3_ACTIVE"
	}

	log.Printf("[SYS.01-AUTODORKER] Listening strictly on http://%s (Loopback Sovereignty // %s)", actualAddr, fipsState)
	hub.BroadcastLog(fmt.Sprintf("[OK] Gateway online at http://%s (%s)", actualAddr, fipsState))

	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		if srvErr := srv.Serve(ln); srvErr != nil && srvErr != http.ErrServerClosed {
			log.Fatalf("[ERR_HALT] Server failure: %v", srvErr)
		}
	}()

	<-stopCh
	log.Printf("[SYS.01-AUTODORKER] Graceful shutdown initiated...")
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	_ = srv.Shutdown(ctx)
}
