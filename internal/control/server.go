// Package control exposes the sidecar's HTTP control and health surface: the
// reads and writes that must happen synchronously, right now, against one named
// box. The GA brain uses it to assign a candidate strategy, confirm the swap
// landed, check liveness, read the overhead measurements the pre-screen gates
// on, and (in eval mode) read the per-market canary pool.
//
// Everything that does not need to be synchronous is exported as OTLP metrics
// instead (see internal/telemetry) and read from SigNoz, which aggregates
// across the pool and outlives any single box. The engine snapshot stays on
// /healthz because the pre-screen decides whether to keep a candidate within
// seconds of self-dialling it, and the metrics pipeline's export interval plus
// query lag is longer than that decision can wait.
//
// The surface is intentionally small and unauthenticated: it binds to a
// control address the deployment keeps private (localhost or a management
// network), exactly like the other lantern sidecars' local admin endpoints.
package control

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/getlantern/geneva-server/internal/canary"
	"github.com/getlantern/geneva-server/internal/engine"
)

// Providers supplies the live objects the control surface reports on.
type Providers struct {
	Mode    string
	Version string
	Commit  string
	Engine  *engine.Engine
	// Canary is the eval-mode capture pool; nil in prod mode.
	Canary *canary.Pool
	// Verdicts returns the runtime's verdict counters (JSON-marshalable). It may
	// be nil before the runtime starts.
	Verdicts func() any
	// InboundTCP returns the inbound TCP event counts (JSON-marshalable), the
	// box-side censor-reachability signal. It may be nil.
	InboundTCP func() any
	// Apply installs a strategy end to end: it reprograms the kernel's steering
	// for what the new strategy can match and then swaps the engine. PUT goes
	// through it rather than straight to the engine, because a strategy change
	// can put the box on or take it off the data path. It is required for PUT:
	// a caller that forgets to wire it gets a loud 503, never a silent
	// engine-only swap that leaves the kernel steering for the old strategy.
	Apply func(ctx context.Context, dna string) error
	// Steering returns what the box is currently steering (JSON-marshalable).
	// It may be nil.
	Steering func() any
}

// Server is the HTTP control surface.
type Server struct {
	p       Providers
	started time.Time
}

// New builds a control server.
func New(p Providers) *Server {
	return &Server{p: p, started: time.Now()}
}

// Handler returns the HTTP handler, so it can be mounted or tested directly.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/strategy", s.handleStrategy)
	mux.HandleFunc("/canary", s.handleCanary)
	return mux
}

func (s *Server) uptime() float64 { return time.Since(s.started).Seconds() }

type healthResp struct {
	Status   string          `json:"status"`
	Mode     string          `json:"mode"`
	Version  string          `json:"version"`
	Commit   string          `json:"commit"`
	Uptime   float64         `json:"uptime_seconds"`
	Strategy string          `json:"strategy"`
	Engine   engine.Snapshot `json:"engine"`
	Verdicts any             `json:"verdicts,omitempty"`
	// InboundTCP is reported here as well as over OTLP so the counters can be
	// read on a box with no collector configured — during an e2e run, or when
	// an operator is on the box asking whether its IP has been burned.
	InboundTCP any `json:"inbound_tcp,omitempty"`
	// Steering says whether the box is on the data path at all, and for which
	// packets. A sidecar with no strategy steers nothing, and an operator
	// looking at a slow box needs to be able to tell that from here.
	Steering any `json:"steering,omitempty"`
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	resp := healthResp{
		Status:   "ok",
		Mode:     s.p.Mode,
		Version:  s.p.Version,
		Commit:   s.p.Commit,
		Uptime:   s.uptime(),
		Strategy: s.p.Engine.DNA(),
		Engine:   s.p.Engine.Snapshot(),
	}
	if s.p.Verdicts != nil {
		resp.Verdicts = s.p.Verdicts()
	}
	if s.p.InboundTCP != nil {
		resp.InboundTCP = s.p.InboundTCP()
	}
	if s.p.Steering != nil {
		resp.Steering = s.p.Steering()
	}
	writeJSON(w, http.StatusOK, resp)
}

// handleStrategy serves GET (current DNA) and PUT (assign/replace the strategy).
// PUT validates the DNA before installing it, and the swap is atomic, so the new
// strategy applies to the next packet with no restart. This works in both modes.
//
// The swap is not strategy-content-only: steering is scoped to what the strategy
// can match, so installing one can widen, narrow, or remove the kernel's rules
// (see internal/steering). PUT of an empty strategy takes the box off the data
// path completely. The write endpoint is unauthenticated, so the control address
// must stay on a private interface (see deploy/README.md).
func (s *Server) handleStrategy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]string{"strategy": s.p.Engine.DNA()})
	case http.MethodPut:
		if s.p.Apply == nil {
			writeError(w, http.StatusServiceUnavailable, "strategy updates are not wired up")
			return
		}
		// MaxBytesReader returns an error once the limit is exceeded, so an oversized
		// body is rejected rather than silently truncated (as io.LimitReader would).
		r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
		body, err := io.ReadAll(r.Body)
		if err != nil {
			var maxErr *http.MaxBytesError
			if errors.As(err, &maxErr) {
				writeError(w, http.StatusRequestEntityTooLarge, "strategy exceeds 1 MiB limit")
				return
			}
			writeError(w, http.StatusBadRequest, "read body: "+err.Error())
			return
		}
		// Tolerate a trailing newline or surrounding whitespace (common when the
		// body is piped from a file), which would otherwise fail validation.
		dna := strings.TrimSpace(string(body))
		if err := s.p.Apply(r.Context(), dna); err != nil {
			writeError(w, http.StatusBadRequest, "invalid strategy: "+err.Error())
			return
		}
		writeJSON(w, http.StatusOK, map[string]string{"strategy": s.p.Engine.DNA()})
	default:
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
	}
}

func (s *Server) handleCanary(w http.ResponseWriter, r *http.Request) {
	if s.p.Canary == nil {
		writeError(w, http.StatusNotFound, "canary capture is only available in eval mode")
		return
	}
	writeJSON(w, http.StatusOK, s.p.Canary.Snapshot())
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func writeError(w http.ResponseWriter, code int, msg string) {
	writeJSON(w, code, map[string]string{"error": msg})
}
