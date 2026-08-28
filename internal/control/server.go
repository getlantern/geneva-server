// Package control exposes the sidecar's HTTP control and health surface. The GA
// brain uses it to read health and overhead measurements (for provisioning and
// pre-screening) and, in eval mode, to assign a candidate strategy and read the
// per-market canary pool.
//
// The surface is intentionally small and unauthenticated: it binds to a
// control address the deployment keeps private (localhost or a management
// network), exactly like the other lantern sidecars' local admin endpoints.
package control

import (
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
	mux.HandleFunc("/metrics", s.handleMetrics)
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
	writeJSON(w, http.StatusOK, resp)
}

// handleMetrics returns the overhead-focused view the GA pre-screen reads: how
// much duplication/expansion the strategy adds, plus verdict counters.
func (s *Server) handleMetrics(w http.ResponseWriter, r *http.Request) {
	out := map[string]any{
		"mode":   s.p.Mode,
		"engine": s.p.Engine.Snapshot(),
	}
	if s.p.Verdicts != nil {
		out["verdicts"] = s.p.Verdicts()
	}
	writeJSON(w, http.StatusOK, out)
}

// handleStrategy serves GET (current DNA) and PUT (assign/replace the strategy).
// PUT validates the DNA before installing it, and the swap is atomic, so the new
// strategy applies to the next packet with no restart. This works in both modes:
// the swap is strategy-content-only (the queues, nftables rules, reinjector, and
// offload setup are untouched). The write endpoint is unauthenticated, so the
// control address must stay on a private interface (see deploy/README.md).
func (s *Server) handleStrategy(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodGet:
		writeJSON(w, http.StatusOK, map[string]string{"strategy": s.p.Engine.DNA()})
	case http.MethodPut:
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
		if err := s.p.Engine.SetStrategy(dna); err != nil {
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
