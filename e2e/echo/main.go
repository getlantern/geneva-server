// Command echo is a minimal stand-in for the proxy in the e2e test. It serves a
// deterministic byte payload of a configurable size over HTTP, so the client
// can assert byte-for-byte integrity after the sidecar has manipulated the
// connection's packets. It is not part of the shipped sidecar.
package main

import (
	"context"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"strconv"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

type connectionKey struct{}

func setConnectionMark(r *http.Request) error {
	value := r.URL.Query().Get("mark")
	if value == "" {
		return nil
	}
	mark, err := strconv.ParseUint(value, 0, 32)
	if err != nil {
		return fmt.Errorf("parse mark: %w", err)
	}
	conn, ok := r.Context().Value(connectionKey{}).(net.Conn)
	if !ok {
		return fmt.Errorf("request connection unavailable")
	}
	raw, ok := conn.(syscallConn)
	if !ok {
		return fmt.Errorf("connection has no syscall access")
	}
	rc, err := raw.SyscallConn()
	if err != nil {
		return err
	}
	var setErr error
	if err := rc.Control(func(fd uintptr) {
		setErr = unix.SetsockoptInt(int(fd), unix.SOL_SOCKET, unix.SO_MARK, int(mark))
	}); err != nil {
		return err
	}
	return setErr
}

type syscallConn interface {
	SyscallConn() (syscall.RawConn, error)
}

func main() {
	addr := flag.String("addr", ":8080", "listen address")
	size := flag.Int("size", 1<<20, "payload size in bytes served at /")
	emit := flag.Bool("emit", false, "write the payload to stdout and exit (for integrity comparison)")
	flag.Parse()

	// Deterministic payload: byte i is i mod 251 (prime, so the pattern does not
	// align with common block sizes and any dropped/duplicated slice is visible).
	payload := make([]byte, *size)
	for i := range payload {
		payload[i] = byte(i % 251)
	}

	if *emit {
		if _, err := os.Stdout.Write(payload); err != nil {
			log.Fatal(err)
		}
		return
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		if err := setConnectionMark(r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		_, _ = w.Write(payload)
	})
	mux.HandleFunc("/hold", func(w http.ResponseWriter, r *http.Request) {
		if err := setConnectionMark(r); err != nil {
			http.Error(w, err.Error(), http.StatusBadRequest)
			return
		}
		duration, err := time.ParseDuration(r.URL.Query().Get("duration"))
		if err != nil || duration <= 0 || duration > time.Minute {
			http.Error(w, "duration must be between 1ns and 1m", http.StatusBadRequest)
			return
		}
		flusher, ok := w.(http.Flusher)
		if !ok {
			http.Error(w, "streaming unsupported", http.StatusInternalServerError)
			return
		}
		deadline := time.Now().Add(duration)
		for time.Now().Before(deadline) {
			_, _ = w.Write([]byte("held\n"))
			flusher.Flush()
			time.Sleep(100 * time.Millisecond)
		}
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("echo listening on %s serving %d bytes", *addr, *size)
	srv := &http.Server{
		Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second,
		ConnContext: func(ctx context.Context, conn net.Conn) context.Context {
			return context.WithValue(ctx, connectionKey{}, conn)
		},
	}
	log.Fatal(srv.ListenAndServe())
}
