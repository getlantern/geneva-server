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
	"time"

	"github.com/getlantern/geneva-server/internal/adapter"
	"github.com/getlantern/geneva-server/internal/canary"
	"github.com/getlantern/geneva-server/internal/engine"
)

// Providers supplies the live objects the control surface reports on.
type Providers struct {
	Mode    string
	Version string
	Commit  string
	Engine  interface {
		DNA() string
		Snapshot() engine.Snapshot
	}
	// Canary is the eval-mode capture pool; nil in prod mode.
	Canary *canary.Pool
	// Verdicts returns the runtime's verdict counters (JSON-marshalable). It may
	// be nil before the runtime starts.
	Verdicts func() any
	// InboundTCP returns the inbound TCP event counts (JSON-marshalable), the
	// box-side censor-reachability signal. It may be nil.
	InboundTCP func() any
	// Health reports lifecycle integrity. A process remains reachable for local
	// rollback remediation while readiness is unhealthy and steering is inactive.
	Health func() error
	// Steering returns what the box is currently steering (JSON-marshalable).
	// It may be nil.
	Steering func() any
	Adapter  Adapter
}

// Adapter is deliberately generic and contains no cloud or transport types.
type Adapter = adapter.Adapter

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
	mux.HandleFunc("/canary", s.handleCanary)
	mux.HandleFunc("/v1/adapter/prepare", s.handlePrepare)
	mux.HandleFunc("/v1/adapter/descriptor", s.handleDescriptor)
	mux.HandleFunc("/v1/adapter/verify", s.handleVerify)
	mux.HandleFunc("/v1/adapter/activate-for-new-connections", s.handleActivateNew)
	mux.HandleFunc("/v1/adapter/deactivate-for-new-connections", s.handleDeactivateNew)
	mux.HandleFunc("/v1/adapter/status", s.handleAdapterStatus)
	mux.HandleFunc("/v1/adapter/drain", s.handleDrain)
	mux.HandleFunc("/v1/adapter/garbage-collect", s.handleGC)
	mux.HandleFunc("/v1/adapter/rollback", s.handleRollback)
	return mux
}

func (s *Server) uptime() float64 { return time.Since(s.started).Seconds() }

type healthResp struct {
	Status   string          `json:"status"`
	Error    string          `json:"error,omitempty"`
	Mode     string          `json:"mode"`
	Version  string          `json:"version"`
	Commit   string          `json:"commit"`
	Uptime   float64         `json:"uptime_seconds"`
	Strategy string          `json:"strategy,omitempty"`
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
	statusCode := http.StatusOK
	resp := healthResp{
		Status:  "ok",
		Mode:    s.p.Mode,
		Version: s.p.Version,
		Commit:  s.p.Commit,
		Uptime:  s.uptime(),
		Engine:  s.p.Engine.Snapshot(),
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
	if s.p.Health != nil {
		if err := s.p.Health(); err != nil {
			resp.Status = "unhealthy"
			resp.Error = err.Error()
			statusCode = http.StatusServiceUnavailable
		}
	}
	writeJSON(w, statusCode, resp)
}

const (
	// Base64 expands the generic []byte payload by 4/3. Keep a bounded allowance
	// for immutable metadata while enforcing the decoded payload separately.
	maxArtifactRequest = 2*adapter.MaxArtifactSize + 4096
)

type garbageCollectRequest struct {
	Keep []adapter.ArtifactIdentity `json:"keep"`
}

func operationContext(r *http.Request) (context.Context, context.CancelFunc) {
	return context.WithTimeout(r.Context(), 30*time.Second)
}

func (s *Server) adapter(w http.ResponseWriter) Adapter {
	if s.p.Adapter == nil {
		writeError(w, http.StatusServiceUnavailable, "adapter lifecycle is not wired up")
	}
	return s.p.Adapter
}

func decodeAdapterRequest(w http.ResponseWriter, r *http.Request, dst any) bool {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, maxArtifactRequest)
	body, err := io.ReadAll(r.Body)
	if err == nil {
		err = json.Unmarshal(body, dst)
	}
	if err != nil {
		var maxErr *http.MaxBytesError
		if errors.As(err, &maxErr) {
			writeError(w, http.StatusRequestEntityTooLarge, "serialized adapter request exceeds its bounded envelope")
		} else if errors.Is(err, adapter.ErrPayloadTooLarge) {
			writeError(w, http.StatusRequestEntityTooLarge, err.Error())
		} else {
			writeError(w, http.StatusBadRequest, "decode request: "+err.Error())
		}
		return false
	}
	if artifact, ok := dst.(*adapter.Artifact); ok && len(artifact.Payload()) > adapter.MaxArtifactSize {
		writeError(w, http.StatusRequestEntityTooLarge, "artifact exceeds 256 KiB")
		return false
	}
	return true
}

func lifecycleResult(w http.ResponseWriter, err error) {
	if err == nil {
		writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
		return
	}
	code := http.StatusInternalServerError
	switch {
	case errors.Is(err, engine.ErrInvalidStrategy):
		code = http.StatusBadRequest
	case errors.Is(err, context.DeadlineExceeded), errors.Is(err, context.Canceled):
		code = http.StatusGatewayTimeout
	case errors.Is(err, adapter.ErrLifecycleConflict):
		code = http.StatusConflict
	}
	writeError(w, code, err.Error())
}

func (s *Server) handlePrepare(w http.ResponseWriter, r *http.Request) {
	a := s.adapter(w)
	if a == nil {
		return
	}
	var artifact adapter.Artifact
	if !decodeAdapterRequest(w, r, &artifact) {
		return
	}
	ctx, cancel := operationContext(r)
	defer cancel()
	lifecycleResult(w, a.Prepare(ctx, artifact))
}

func (s *Server) handleDescriptor(w http.ResponseWriter, r *http.Request) {
	a := s.adapter(w)
	if a == nil {
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	writeJSON(w, http.StatusOK, a.Descriptor())
}

func (s *Server) handleVerify(w http.ResponseWriter, r *http.Request) {
	a := s.adapter(w)
	if a == nil {
		return
	}
	var artifact adapter.Artifact
	if !decodeAdapterRequest(w, r, &artifact) {
		return
	}
	ctx, cancel := operationContext(r)
	defer cancel()
	lifecycleResult(w, a.Verify(ctx, artifact))
}

func (s *Server) handleActivateNew(w http.ResponseWriter, r *http.Request) {
	a := s.adapter(w)
	if a == nil {
		return
	}
	var artifact adapter.Artifact
	if !decodeAdapterRequest(w, r, &artifact) {
		return
	}
	ctx, cancel := operationContext(r)
	defer cancel()
	lifecycleResult(w, a.ActivateForNewConnections(ctx, artifact))
}

func (s *Server) handleDeactivateNew(w http.ResponseWriter, r *http.Request) {
	a := s.adapter(w)
	if a == nil {
		return
	}
	var identity adapter.ArtifactIdentity
	if !decodeAdapterRequest(w, r, &identity) {
		return
	}
	ctx, cancel := operationContext(r)
	defer cancel()
	lifecycleResult(w, a.DeactivateForNewConnections(ctx, identity))
}

func (s *Server) handleAdapterStatus(w http.ResponseWriter, r *http.Request) {
	a := s.adapter(w)
	if a == nil {
		return
	}
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "method not allowed")
		return
	}
	ctx, cancel := operationContext(r)
	defer cancel()
	status, err := a.Status(ctx)
	if err != nil {
		lifecycleResult(w, err)
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) handleDrain(w http.ResponseWriter, r *http.Request) {
	a := s.adapter(w)
	if a == nil {
		return
	}
	var identity adapter.ArtifactIdentity
	if !decodeAdapterRequest(w, r, &identity) {
		return
	}
	ctx, cancel := operationContext(r)
	defer cancel()
	result, err := a.Drain(ctx, identity)
	if err != nil {
		lifecycleResult(w, err)
		return
	}
	writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleGC(w http.ResponseWriter, r *http.Request) {
	a := s.adapter(w)
	if a == nil {
		return
	}
	var req garbageCollectRequest
	if !decodeAdapterRequest(w, r, &req) {
		return
	}
	ctx, cancel := operationContext(r)
	defer cancel()
	lifecycleResult(w, a.GarbageCollect(ctx, req.Keep))
}

func (s *Server) handleRollback(w http.ResponseWriter, r *http.Request) {
	a := s.adapter(w)
	if a == nil {
		return
	}
	var artifact adapter.Artifact
	if !decodeAdapterRequest(w, r, &artifact) {
		return
	}
	ctx, cancel := operationContext(r)
	defer cancel()
	lifecycleResult(w, a.Rollback(ctx, artifact))
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
