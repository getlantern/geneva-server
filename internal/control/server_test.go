package control

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
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
	prepared adapter.Artifact
	active   *adapter.ArtifactIdentity
}

type canceledAdapter struct {
	fakeAdapter
	saw error
}

func testArtifact(t *testing.T, revision string, payload []byte) adapter.Artifact {
	t.Helper()
	artifact, err := adapter.NewArtifact(adapter.ArtifactMetadata{
		Technique: adapter.TechniqueGeneva, Revision: revision, Digest: adapter.Digest(payload), Size: len(payload),
		AdapterProtocol: adapter.Version1, RequiredRuntimeName: adapter.RuntimeNameGeneva,
		RequiredRuntimeVersion: "test-runtime", SchemaVersion: adapter.SchemaVersionV1,
	}, payload)
	if err != nil {
		t.Fatal(err)
	}
	return artifact
}

func closeResponseBody(t *testing.T, resp *http.Response) {
	t.Helper()
	if err := resp.Body.Close(); err != nil {
		t.Errorf("close response body: %v", err)
	}
}

func (a *canceledAdapter) Prepare(ctx context.Context, _ adapter.Artifact) error {
	<-ctx.Done()
	a.saw = ctx.Err()
	return ctx.Err()
}

func (*fakeAdapter) Descriptor() adapter.Descriptor {
	return adapter.Descriptor{AdapterProtocol: 1, Technique: "geneva", RuntimeName: "geneva-engine", RuntimeVersion: "test-runtime", SchemaVersions: []uint32{1}, MaxLiveGenerations: 3}
}
func (*fakeAdapter) Verify(context.Context, adapter.Artifact) error { return nil }
func (f *fakeAdapter) Prepare(_ context.Context, artifact adapter.Artifact) error {
	f.prepared = artifact
	return nil
}
func (f *fakeAdapter) ActivateForNewConnections(_ context.Context, artifact adapter.Artifact) error {
	identity := artifact.Identity()
	f.active = &identity
	return nil
}
func (*fakeAdapter) DeactivateForNewConnections(context.Context, adapter.ArtifactIdentity) error {
	return nil
}
func (f *fakeAdapter) Status(context.Context) (adapter.Status, error) {
	return adapter.Status{Active: f.active}, nil
}
func (*fakeAdapter) Drain(context.Context, adapter.ArtifactIdentity) (adapter.DrainResult, error) {
	return adapter.DrainResult{Complete: true}, nil
}
func (*fakeAdapter) GarbageCollect(context.Context, []adapter.ArtifactIdentity) error {
	return nil
}
func (*fakeAdapter) Rollback(context.Context, adapter.Artifact) error { return nil }

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
		Apply:          func(_ context.Context, dna string) error { return eng.SetStrategy(dna) },
		LegacyStrategy: true,
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
	defer closeResponseBody(t, resp)
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

func TestHealthzReportsLifecycleIntegrityFailureWhileControlRemainsReachable(t *testing.T) {
	eng := engine.NewRegistry()
	srv := httptest.NewServer(New(Providers{
		Mode: "prod", Version: "test", Engine: eng,
		Health: func() error { return errors.New("adapter state quarantined") },
	}).Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/healthz")
	if err != nil {
		t.Fatal(err)
	}
	defer closeResponseBody(t, resp)
	if resp.StatusCode != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want %d", resp.StatusCode, http.StatusServiceUnavailable)
	}
	var body healthResp
	if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
		t.Fatal(err)
	}
	if body.Status != "unhealthy" || !strings.Contains(body.Error, "quarantined") {
		t.Fatalf("health body = %+v", body)
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
	defer closeResponseBody(t, resp)
	if resp.StatusCode != 200 {
		t.Fatalf("reload status = %d", resp.StatusCode)
	}
	// Confirm it took effect via GET.
	gr, err := http.Get(srv.URL + "/strategy")
	if err != nil {
		t.Fatal(err)
	}
	defer closeResponseBody(t, gr)
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
	defer closeResponseBody(t, resp)
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
	defer closeResponseBody(t, resp)
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
	defer closeResponseBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("prod reload status = %d, want 200", resp.StatusCode)
	}
	gr, err := http.Get(srv.URL + "/strategy")
	if err != nil {
		t.Fatal(err)
	}
	defer closeResponseBody(t, gr)
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
	defer closeResponseBody(t, resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("prod canary status = %d, want 404", resp.StatusCode)
	}

	eval := newTestServer(t, "eval", "", true)
	resp2, err := http.Get(eval.URL + "/canary")
	if err != nil {
		t.Fatal(err)
	}
	defer closeResponseBody(t, resp2)
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
	defer closeResponseBody(t, resp)
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
	defer closeResponseBody(t, resp)

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
	payload := []byte(`[TCP:flags:R]-drop-| \/`)
	artifact := testArtifact(t, "r1", payload)
	body, _ := json.Marshal(artifact)
	post := func(path string, body []byte) *http.Response {
		t.Helper()
		resp, err := http.Post(srv.URL+path, "application/json", strings.NewReader(string(body)))
		if err != nil {
			t.Fatal(err)
		}
		return resp
	}
	resp := post("/v1/adapter/prepare", body)
	defer closeResponseBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("prepare status = %d", resp.StatusCode)
	}
	if a.prepared.Identity() != artifact.Identity() || string(a.prepared.Payload()) != string(payload) {
		t.Fatalf("prepared = %+v", a.prepared)
	}
	resp2 := post("/v1/adapter/activate-for-new-connections", body)
	defer closeResponseBody(t, resp2)
	if resp2.StatusCode != http.StatusOK || a.active == nil || *a.active != artifact.Identity() {
		t.Fatalf("activate status=%d active=%+v", resp2.StatusCode, a.active)
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
	if raw["adapter_protocol"] != float64(1) {
		t.Fatalf("adapter_protocol wire value = %#v", raw["adapter_protocol"])
	}
	versions, ok := raw["schema_versions"].([]any)
	if !ok || len(versions) != 1 || versions[0] != float64(1) {
		t.Fatalf("schema_versions wire value = %#v", raw["schema_versions"])
	}
	for _, field := range []string{"runtime_name", "runtime_version"} {
		if raw[field] == "" || raw[field] == nil {
			t.Fatalf("%s is absent: %#v", field, raw[field])
		}
	}
	for _, forbidden := range []string{"protocol_version", "supported_schema_versions", "max_artifact_bytes"} {
		if _, ok := raw[forbidden]; ok {
			t.Fatalf("non-generic descriptor field %s is present", forbidden)
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
	payload := []byte(strings.Repeat("x", adapter.MaxArtifactSize+1))
	body, _ := json.Marshal(map[string]any{"metadata": adapter.ArtifactMetadata{
		Technique: adapter.TechniqueGeneva, Revision: "too-large", Digest: adapter.Digest(payload), Size: len(payload),
		AdapterProtocol: adapter.Version1, RequiredRuntimeName: adapter.RuntimeNameGeneva,
		RequiredRuntimeVersion: "test-runtime", SchemaVersion: adapter.SchemaVersionV1,
	}, "payload": payload})
	resp, err := http.Post(srv.URL+"/v1/adapter/prepare", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer closeResponseBody(t, resp)
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
	artifact := testArtifact(t, "full-size", []byte(strings.Repeat("x", adapter.MaxArtifactSize)))
	body, _ := json.Marshal(artifact)
	resp, err := http.Post(srv.URL+"/v1/adapter/prepare", "application/json", strings.NewReader(string(body)))
	if err != nil {
		t.Fatal(err)
	}
	defer closeResponseBody(t, resp)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("status = %d", resp.StatusCode)
	}
	if len(a.prepared.Payload()) != adapter.MaxArtifactSize {
		t.Fatalf("artifact bytes = %d", len(a.prepared.Payload()))
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
	body, _ := json.Marshal(testArtifact(t, "cancel", []byte("x")))
	req := httptest.NewRequest(http.MethodPost, "/v1/adapter/prepare", strings.NewReader(string(body))).WithContext(ctx)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, req)
	if !errors.Is(a.saw, context.Canceled) {
		t.Fatalf("adapter context error = %v", a.saw)
	}
}

func TestLifecycleResultClassifiesClientAndServerFailures(t *testing.T) {
	tests := []struct {
		name string
		err  error
		want int
	}{
		{name: "invalid artifact", err: engine.ErrInvalidStrategy, want: http.StatusBadRequest},
		{name: "state conflict", err: fmt.Errorf("%w: not prepared", adapter.ErrLifecycleConflict), want: http.StatusConflict},
		{name: "deadline", err: context.DeadlineExceeded, want: http.StatusGatewayTimeout},
		{name: "kernel failure", err: errors.New("nft transaction failed"), want: http.StatusInternalServerError},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			w := httptest.NewRecorder()
			lifecycleResult(w, tt.err)
			if w.Code != tt.want {
				t.Fatalf("status = %d, want %d: %s", w.Code, tt.want, w.Body.String())
			}
		})
	}
}

func TestLegacyStrategyAndAuthoritativeV1AreMutuallyExclusive(t *testing.T) {
	legacy := newTestServer(t, "eval", "", false)
	resp, err := http.Get(legacy.URL + "/v1/adapter/descriptor")
	if err != nil {
		t.Fatal(err)
	}
	defer closeResponseBody(t, resp)
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("legacy server exposed v1 adapter: %d", resp.StatusCode)
	}

	eng, _ := engine.New("")
	authoritative := httptest.NewServer(New(Providers{Mode: "eval", Engine: eng, Adapter: &fakeAdapter{}}).Handler())
	defer authoritative.Close()
	resp2, err := http.Get(authoritative.URL + "/strategy")
	if err != nil {
		t.Fatal(err)
	}
	defer closeResponseBody(t, resp2)
	if resp2.StatusCode != http.StatusNotFound {
		t.Fatalf("authoritative v1 server exposed raw-DNA strategy API: %d", resp2.StatusCode)
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
