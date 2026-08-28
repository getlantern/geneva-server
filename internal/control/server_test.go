package control

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/getlantern/geneva-server/internal/canary"
	"github.com/getlantern/geneva-server/internal/engine"
)

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
