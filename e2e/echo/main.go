// Command echo is a minimal stand-in for the proxy in the e2e test. It serves a
// deterministic byte payload of a configurable size over HTTP, so the client
// can assert byte-for-byte integrity after the sidecar has manipulated the
// connection's packets. It is not part of the shipped sidecar.
package main

import (
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"
	"time"
)

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
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", fmt.Sprint(len(payload)))
		_, _ = w.Write(payload)
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("echo listening on %s serving %d bytes", *addr, *size)
	srv := &http.Server{Addr: *addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 30 * time.Second}
	log.Fatal(srv.ListenAndServe())
}
