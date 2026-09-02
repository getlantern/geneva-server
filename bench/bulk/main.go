// Command bulk is the load generator for the sidecar benchmark. It is both the
// server and the client so that a single image covers both ends, and it streams
// from a reused buffer rather than materializing the payload: the benchmark
// moves gigabytes, and a payload held in memory would measure the allocator.
//
// It deliberately speaks plain HTTP. The sidecar only ever manipulates outer
// IPv4/TCP headers, so wrapping the stream in TLS would add proxy-side crypto
// cost to every number without changing a single packet the sidecar sees.
package main

import (
	"crypto/rand"
	"flag"
	"fmt"
	"io"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

const chunkSize = 256 << 10

func main() {
	serve := flag.String("serve", "", "serve bulk data on this address (e.g. :8080)")
	get := flag.String("get", "", "fetch bulk data from this base URL (e.g. http://server:8080)")
	bytes := flag.Int64("bytes", 2<<30, "bytes to transfer per stream")
	streams := flag.Int("streams", 1, "concurrent streams")
	flag.Parse()

	switch {
	case *serve != "":
		runServer(*serve)
	case *get != "":
		if err := runClient(*get, *bytes, *streams); err != nil {
			// Exit non-zero rather than printing a throughput figure: a
			// half-finished transfer that reports a number is how a broken
			// condition gets recorded as a benchmark result.
			log.Fatal(err)
		}
	default:
		log.Fatal("one of -serve or -get is required")
	}
}

func runServer(addr string) {
	// Random rather than zeros: a NIC or a virtual link that compresses or
	// dedupes would otherwise flatter the benchmark.
	chunk := make([]byte, chunkSize)
	if _, err := rand.Read(chunk); err != nil {
		log.Fatal(err)
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/bulk", func(w http.ResponseWriter, r *http.Request) {
		n, err := strconv.ParseInt(r.URL.Query().Get("bytes"), 10, 64)
		if err != nil || n < 0 {
			http.Error(w, "bad bytes", http.StatusBadRequest)
			return
		}
		w.Header().Set("Content-Type", "application/octet-stream")
		w.Header().Set("Content-Length", strconv.FormatInt(n, 10))
		for n > 0 {
			c := int64(len(chunk))
			if n < c {
				c = n
			}
			if _, err := w.Write(chunk[:c]); err != nil {
				return
			}
			n -= c
		}
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	})

	log.Printf("bulk server listening on %s", addr)
	srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	log.Fatal(srv.ListenAndServe())
}

// runClient reports MB/s on stdout as a bare number, so the runner can read it
// without parsing prose. Any stream that fails, returns a non-200, or comes up
// short is an error: the number would be meaningless and the runner cannot tell
// a slow condition from a broken one.
func runClient(base string, n int64, streams int) error {
	client := &http.Client{Timeout: 30 * time.Minute}
	url := fmt.Sprintf("%s/bulk?bytes=%d", base, n)

	var wg sync.WaitGroup
	got := make([]int64, streams)
	errs := make([]error, streams)
	start := time.Now()
	for i := range streams {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			resp, err := client.Get(url)
			if err != nil {
				errs[i] = fmt.Errorf("stream %d: %w", i, err)
				return
			}
			defer func() { _ = resp.Body.Close() }()
			if resp.StatusCode != http.StatusOK {
				errs[i] = fmt.Errorf("stream %d: HTTP %d", i, resp.StatusCode)
				return
			}
			c, err := io.Copy(io.Discard, resp.Body)
			got[i] = c
			if err != nil {
				errs[i] = fmt.Errorf("stream %d: after %d bytes: %w", i, c, err)
			}
		}(i)
	}
	wg.Wait()
	elapsed := time.Since(start)

	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	var total int64
	for _, c := range got {
		total += c
	}
	if want := n * int64(streams); total != want {
		return fmt.Errorf("short transfer: got %d of %d bytes", total, want)
	}
	mbps := float64(total) / (1 << 20) / elapsed.Seconds()
	_, _ = fmt.Fprintf(os.Stdout, "%.2f\n", mbps)
	return nil
}
