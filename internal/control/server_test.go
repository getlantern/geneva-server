package control

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getlantern/geneva/strategy"

	"github.com/getlantern/geneva-server/internal/adapter"
	"github.com/getlantern/geneva-server/internal/canary"
	"github.com/getlantern/geneva-server/internal/censor"
	"github.com/getlantern/geneva-server/internal/engine"
)

type fakeAdapter struct {
	prepared lifecycleRequest
	active   uint32
}

type canceledAdapter struct {
	fakeAdapter
	saw error
}

func (a *canceledAdapter) PrepareDeployment(ctx context.Context, _ adapter.Deployment, _ string) error {
	<-ctx.Done()
	a.saw = ctx.Err()
	return ctx.Err()
}

func (*fakeAdapter) Descriptor() adapter.Descriptor {
	return adapter.Descriptor{ProtocolVersion: 1, Technique: "geneva", SupportedSchemaVersions: []uint32{1}, RuntimeVersion: "test-runtime", MaxArtifactBytes: 256 << 10, MaxLiveGenerations: 3}
}
func (*fakeAdapter) VerifyArtifact(_ context.Context, identity adapter.Identity, _ string) (adapter.VerifyResult, error) {
	return adapter.VerifyResult{Identity: identity}, nil
}
func (f *fakeAdapter) PrepareDeployment(_ context.Context, deployment adapter.Deployment, dna string) error {
	f.prepared = lifecycleRequest{Deployment: deployment, Artifact: dna}
	return nil
}
func (f *fakeAdapter) ActivateDeployment(_ context.Context, deployment, _ adapter.Deployment) error {
	f.active = deployment.Generation
	return nil
}
func (*fakeAdapter) DeactivateDeployment(context.Context, adapter.Deployment) error { return nil }
func (f *fakeAdapter) Status(context.Context) (any, error) {
	return map[string]any{"version": 1, "active_new_generation": f.active}, nil
}
func (*fakeAdapter) DrainDeployment(_ context.Context, deployment adapter.Deployment) (adapter.DrainResult, error) {
	return adapter.DrainResult{Deployment: deployment, Drained: true}, nil
}
func (*fakeAdapter) GarbageCollectKeep(context.Context, []adapter.Deployment) (adapter.GCResult, error) {
	return adapter.GCResult{}, nil
}
func (*fakeAdapter) RollbackDeployment(context.Context, adapter.Deployment, adapter.Deployment) error {
	return nil
}

func newTestServer(t *testing.T, mode, dna string, withCanary bool) *httptest.Server {
	t.Helper()
	eng, err := engine.New(dna)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	p := Providers{
		Mode:     mode,
		Version:  "test",
		Engine:   eng,
		Verdicts: func() any { return map[string]int{"accepted": 0} },
		// Engine-only apply: these tests exercise the HTTP surface, not the
		// kernel-reprogramming half a real box wires in.
		Apply: func(_ context.Context, dna string) error { return eng.SetStrategy(dna) },
	}
	if withCanary {
		p.Canary = canary.NewPool("RU", 16)
	}
	srv := httptest.NewServer(New(p).Handler())
	t.Cleanup(srv.Close)
	return srv
}

func TestHealthz(t *testing.T) {
	srv := newTestServer(t, "prod", `[TCP:flags:R]-drop-| \/`, false)
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	var body healthResp
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "ok" || body.Mode != "prod" {
		t.Fatalf("unexpected health: %+v", body)
	}
	if body.Strategy != `[TCP:flags:R]-drop-| \/` {
		t.Fatalf("strategy not reported: %q", body.Strategy)
	}
}

func TestStrategyReloadEval(t *testing.T) {
	srv := newTestServer(t, "eval", "", false)
	newDNA := `[TCP:flags:PA]-duplicate-| \/`
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/strategy", strings.NewReader(newDNA))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != 200 {
		t.Fatalf("reload status = %d", resp.StatusCode)
	}
	// Confirm it took effect via GET.
	gr, err := http.Get(srv.URL + "/strategy")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gr.Body.Close() }()
	var got map[string]string
	_ = json.NewDecoder(gr.Body).Decode(&got)
	if got["strategy"] != newDNA {
		t.Fatalf("strategy = %q, want %q", got["strategy"], newDNA)
	}
}

func TestStrategyReloadRejectsInvalid(t *testing.T) {
	srv := newTestServer(t, "eval", "", false)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/strategy", strings.NewReader("this is not a strategy"))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("invalid strategy status = %d, want 400", resp.StatusCode)
	}
}

func TestStrategyReloadRejectsOversizedBody(t *testing.T) {
	srv := newTestServer(t, "eval", "", false)

	// A valid strategy followed by more than 1 MiB of trailing bytes: the handler must
	// reject it with 413 rather than truncating to the first MiB and reporting success.
	body := `[TCP:flags:R]-drop-| \/` + "\n" + strings.Repeat("x", 1<<20)
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/strategy", strings.NewReader(body))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized body status = %d, want 413", resp.StatusCode)
	}
}

func TestStrategyReloadWorksInProd(t *testing.T) {
	// Reload-in-place is supported in both modes; prod is not special-cased.
	srv := newTestServer(t, "prod", `[TCP:flags:R]-drop-| \/`, false)
	newDNA := `[TCP:flags:S]-tamper{TCP:flags:replace:SA}-| \/`
	req, _ := http.NewRequest(http.MethodPut, srv.URL+"/strategy", strings.NewReader(newDNA))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("prod reload status = %d, want 200", resp.StatusCode)
	}
	gr, err := http.Get(srv.URL + "/strategy")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = gr.Body.Close() }()
	var got map[string]string
	_ = json.NewDecoder(gr.Body).Decode(&got)
	if got["strategy"] != newDNA {
		t.Fatalf("strategy = %q, want %q", got["strategy"], newDNA)
	}
}

func TestCanaryOnlyInEval(t *testing.T) {
	prod := newTestServer(t, "prod", `\/`, false)
	resp, err := http.Get(prod.URL + "/canary")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("prod canary status = %d, want 404", resp.StatusCode)
	}

	eval := newTestServer(t, "eval", "", true)
	resp2, err := http.Get(eval.URL + "/canary")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp2.Body.Close() }()
	if resp2.StatusCode != 200 {
		t.Fatalf("eval canary status = %d, want 200", resp2.StatusCode)
	}
	var snap canary.Snapshot
	if err := json.NewDecoder(resp2.Body).Decode(&snap); err != nil {
		t.Fatal(err)
	}
	if snap.Market != "RU" {
		t.Fatalf("canary market = %q, want RU", snap.Market)
	}
}

// TestMetricsEndpointGone pins the removal: the overhead numbers now ship over
// OTLP and are read from SigNoz, and /healthz carries the synchronous copy the
// pre-screen needs. A reintroduced /metrics would quietly re-create the
// scrape-every-box path this replaced.
func TestMetricsEndpointGone(t *testing.T) {
	srv := newTestServer(t, "prod", `[TCP:flags:R]-drop-| \/`, false)
	resp, err := http.Get(srv.URL + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("GET /metrics status = %d, want 404", resp.StatusCode)
	}
}

func TestHealthzReportsInboundTCP(t *testing.T) {
	eng, err := engine.New("")
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	obs := censor.New()
	// One inbound SYN, so the reported counts are non-trivially populated.
	obs.Observe(synPacket(t), strategy.DirectionInbound)

	srv := httptest.NewServer(New(Providers{
		Mode:       "eval",
		Engine:     eng,
		InboundTCP: func() any { return obs.Snapshot() },
	}).Handler())
	t.Cleanup(srv.Close)

	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = resp.Body.Close() }()

	var body struct {
		InboundTCP censor.Snapshot `json:"inbound_tcp"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if got := body.InboundTCP.Events["syn"]; got != 1 {
		t.Fatalf("inbound_tcp syn = %d, want 1", got)
	}
	if got := body.InboundTCP.Events["undecodable"]; got != 0 {
		t.Fatalf("undecodable = %d, want 0", got)
	}
}

func TestVersionedAdapterPrepareAndActivate(t *testing.T) {
	eng, err := engine.New("")
	if err != nil {
		t.Fatal(err)
	}
	a := &fakeAdapter{}
	srv := httptest.NewServer(New(Providers{Mode: "eval", Engine: eng, Adapter: a}).Handler())
	t.Cleanup(srv.Close)
	post := func(path, body string) *http.Response {
		t.Helper()
		resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(body))
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := post("/v1/adapter/prepare", `{"schema_version":1,"deployment":{"generation":42,"identity":{"technique":"geneva","revision":"r1","digest":"d"}},"artifact":"[TCP:flags:R]-drop-| \\/"}`)
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("prepare status = %d", resp.StatusCode)
	}
	if a.prepared.Deployment.Generation != 42 || a.prepared.Artifact != `[TCP:flags:R]-drop-| \/` {
		t.Fatalf("prepared = %+v", a.prepared)
	}
	resp2 := post("/v1/adapter/activate-new", `{"deployment":{"generation":42,"identity":{"technique":"geneva","revision":"r1","digest":"d"}},"expected_active":{}}`)
	defer resp2.Body.Close()
	if resp2.StatusCode != http.StatusOK || a.active != 42 {
		t.Fatalf("activate status=%d active=%d", resp2.StatusCode, a.active)
	}
}

func TestAdapterDescriptorUsesExactNumericV1WireContract(t *testing.T) {
	eng, err := engine.New("")
	if err != nil {
		t.Fatal(err)
	}
	h := New(Providers{Mode: "eval", Engine: eng, Adapter: &fakeAdapter{}}).Handler()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v1/adapter/descriptor", nil))
	if w.Code != http.StatusOK {
		t.Fatalf("descriptor status = %d: %s", w.Code, w.Body.String())
	}
	var raw map[string]any
	if err := json.Unmarshal(w.Body.Bytes(), &raw); err != nil {
		t.Fatal(err)
	}
	if raw["protocol_version"] != float64(1) {
		t.Fatalf("protocol_version wire value = %#v", raw["protocol_version"])
	}
	versions, ok := raw["supported_schema_versions"].([]any)
	if !ok || len(versions) != 1 || versions[0] != float64(1) {
		t.Fatalf("supported_schema_versions wire value = %#v", raw["supported_schema_versions"])
	}
	for _, field := range []string{"max_artifact_bytes", "max_live_generations"} {
		if _, ok := raw[field].(float64); !ok {
			t.Fatalf("%s is not a JSON number: %#v", field, raw[field])
		}
	}
}

func TestVersionedAdapterRejectsSerializedRequestOver256KiB(t *testing.T) {
	eng, err := engine.New("")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(New(Providers{Mode: "eval", Engine: eng, Adapter: &fakeAdapter{}}).Handler())
	t.Cleanup(srv.Close)
	body := `{"schema_version":1,"deployment":{"generation":1},"artifact":"` + strings.Repeat("x", maxArtifact+1) + `"}`
	resp, err := http.Post(srv.URL+"/v1/adapter/prepare", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusRequestEntityTooLarge {
		t.Fatalf("status = %d, want 413", resp.StatusCode)
	}
}

func TestVersionedAdapterAcceptsFull256KiBArtifact(t *testing.T) {
	eng, err := engine.New("")
	if err != nil {
		t.Fatal(err)
	}
	a := &fakeAdapter{}
	srv := httptest.NewServer(New(Providers{Mode: "eval", Engine: eng, Adapter: a}).Handler())
	t.Cleanup(srv.Close)
	body := `{"schema_version":1,"deployment":{"generation":1},"artifact":"` + strings.Repeat("x", maxArtifact) + `"}`
	resp, err := http.Post(srv.URL+"/v1/adapter/prepare", "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if len(a.prepared.Artifact) != maxArtifact {
		t.Fatalf("artifact bytes = %d", len(a.prepared.Artifact))
	}
}

func TestAdapterOperationUsesRequestCancellation(t *testing.T) {
	eng, err := engine.New("")
	if err != nil {
		t.Fatal(err)
	}
	a := &canceledAdapter{}
	h := New(Providers{Mode: "eval", Engine: eng, Adapter: a}).Handler()
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req := httptest.NewRequest(http.MethodPost, "/v1/adapter/prepare", strings.NewReader(`{"schema_version":1,"deployment":{"generation":1},"artifact":"x"}`)).WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if !errors.Is(a.saw, context.Canceled) {
		t.Fatalf("adapter context error = %v", a.saw)
	}
}

// synPacket builds a minimal inbound IPv4/TCP SYN.
func synPacket(t *testing.T) []byte {
	t.Helper()
	pkt := make([]byte, 40)
	pkt[0] = 0x45 // IPv4, 5-word header
	pkt[2], pkt[3] = 0, 40
	pkt[9] = 6          // TCP
	pkt[20+12] = 5 << 4 // 5-word TCP header
	pkt[20+13] = 1 << 1 // SYN
	return pkt
}
