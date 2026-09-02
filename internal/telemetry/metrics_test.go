package telemetry

import (
	"context"
	"testing"
	"time"

	semconv "github.com/getlantern/semconv"
	sdkotel "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"

	"github.com/getlantern/geneva-server/internal/censor"
	"github.com/getlantern/geneva-server/internal/engine"
)

// collect registers the instruments against a manual reader and returns one
// collection, so the assertions below read what an export would carry.
func collect(t *testing.T, p Providers) metricdata.ResourceMetrics {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	mp := sdkmetric.NewMeterProvider(sdkmetric.WithReader(reader))
	prev := sdkotel.GetMeterProvider()
	sdkotel.SetMeterProvider(mp)
	t.Cleanup(func() {
		sdkotel.SetMeterProvider(prev)
		_ = mp.Shutdown(context.Background())
	})

	if err := Register(p); err != nil {
		t.Fatalf("Register: %v", err)
	}
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return rm
}

// sums indexes the collected int64 sums by metric name, then by the value of
// attribute key (empty string when the metric carries no such attribute).
func sums(t *testing.T, rm metricdata.ResourceMetrics, key attribute.Key) map[string]map[string]int64 {
	t.Helper()
	out := map[string]map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			agg, ok := m.Data.(metricdata.Sum[int64])
			if !ok {
				continue
			}
			byAttr := map[string]int64{}
			for _, dp := range agg.DataPoints {
				v, _ := dp.Attributes.Value(key)
				byAttr[v.String()] = dp.Value
			}
			out[m.Name] = byAttr
		}
	}
	return out
}

func gauges(rm metricdata.ResourceMetrics) map[string]float64 {
	out := map[string]float64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			agg, ok := m.Data.(metricdata.Gauge[float64])
			if !ok || len(agg.DataPoints) == 0 {
				continue
			}
			out[m.Name] = agg.DataPoints[0].Value
		}
	}
	return out
}

func TestRegisterRequiresEngine(t *testing.T) {
	if err := Register(Providers{Mode: "prod"}); err == nil {
		t.Fatal("Register accepted a nil engine")
	}
	var typedNil *engine.Engine
	if err := Register(Providers{Mode: "prod", Engine: typedNil}); err == nil {
		t.Fatal("Register accepted a typed-nil engine")
	}
}

func TestRegisterExportsEngineAndVerdicts(t *testing.T) {
	eng, err := engine.New(`[TCP:flags:PA]-duplicate-| \/`)
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	// One in-place swap, so the swap counter is exercised rather than merely
	// present.
	if err := eng.SetStrategy(`[TCP:flags:R]-drop-| \/`); err != nil {
		t.Fatalf("SetStrategy: %v", err)
	}
	eng.Stats.PacketsIn.Add(10)
	eng.Stats.PacketsOut.Add(12)
	eng.Stats.BytesIn.Add(1000)
	eng.Stats.BytesOut.Add(1200)
	eng.Stats.Expanded.Add(2)
	eng.Stats.Unchanged.Add(8)
	eng.Stats.Errors.Add(1)

	rm := collect(t, Providers{
		Mode:    "eval",
		Market:  "RU",
		Engine:  eng,
		Started: time.Now().Add(-90 * time.Second),
		Verdicts: func() Verdicts {
			return Verdicts{Accepted: 8, Dropped: 2, Modified: 1, Reinjected: 4, InjectFails: 1}
		},
	})

	byOutcome := sums(t, rm, semconv.GenevaOutcomeKey)
	if got := byOutcome[semconv.GenevaMetricPacketsIn][""]; got != 10 {
		t.Fatalf("%s = %d, want 10", semconv.GenevaMetricPacketsIn, got)
	}
	if got := byOutcome[semconv.GenevaMetricBytesOut][""]; got != 1200 {
		t.Fatalf("%s = %d, want 1200", semconv.GenevaMetricBytesOut, got)
	}
	if got := byOutcome[semconv.GenevaMetricErrors][""]; got != 1 {
		t.Fatalf("%s = %d, want 1", semconv.GenevaMetricErrors, got)
	}
	if got := byOutcome[semconv.GenevaMetricStrategySwaps][""]; got != 1 {
		t.Fatalf("%s = %d, want 1", semconv.GenevaMetricStrategySwaps, got)
	}
	if got := byOutcome[semconv.GenevaMetricOutcomes]["expanded"]; got != 2 {
		t.Fatalf("outcomes[expanded] = %d, want 2", got)
	}
	if got := byOutcome[semconv.GenevaMetricOutcomes]["unchanged"]; got != 8 {
		t.Fatalf("outcomes[unchanged] = %d, want 8", got)
	}

	byVerdict := sums(t, rm, semconv.GenevaVerdictKey)
	if got := byVerdict[semconv.GenevaMetricVerdicts]["accepted"]; got != 8 {
		t.Fatalf("verdicts[accepted] = %d, want 8", got)
	}
	byReinjection := sums(t, rm, semconv.GenevaReinjectionKey)
	if got := byReinjection[semconv.GenevaMetricReinjections]["failed"]; got != 1 {
		t.Fatalf("reinjections[failed] = %d, want 1", got)
	}

	g := gauges(rm)
	if got := g[semconv.GenevaMetricPacketOverhead]; got < 0.19 || got > 0.21 {
		t.Fatalf("packet overhead = %v, want ~0.2", got)
	}
	if got := g[semconv.GenevaMetricUptime]; got < 89 {
		t.Fatalf("uptime = %v, want >= 89", got)
	}
}

// TestMarketAndModeLabels pins the labelling contract the brain queries by:
// mode is always present, market is present only when known, and no label
// carries the strategy DNA.
func TestMarketAndModeLabels(t *testing.T) {
	eng, err := engine.New("")
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	dna := `[TCP:flags:R]-drop-| \/`
	if err := eng.SetStrategy(dna); err != nil {
		t.Fatalf("SetStrategy: %v", err)
	}

	for _, tc := range []struct {
		market     string
		wantMarket string
	}{
		{"RU", "RU"},
		{"unknown", ""},
		{"", ""},
	} {
		t.Run("market="+tc.market, func(t *testing.T) {
			rm := collect(t, Providers{Mode: "prod", Market: tc.market, Engine: eng})
			var checked bool
			for _, sm := range rm.ScopeMetrics {
				for _, m := range sm.Metrics {
					agg, ok := m.Data.(metricdata.Sum[int64])
					if !ok {
						continue
					}
					for _, dp := range agg.DataPoints {
						mode, ok := dp.Attributes.Value(semconv.GenevaModeKey)
						if !ok || mode.String() != "prod" {
							t.Fatalf("%s: mode label = %q, want prod", m.Name, mode.String())
						}
						market, _ := dp.Attributes.Value(semconv.GeoCountryISOCodeKey)
						if market.String() != tc.wantMarket {
							t.Fatalf("%s: market label = %q, want %q", m.Name, market.String(), tc.wantMarket)
						}
						for _, kv := range dp.Attributes.ToSlice() {
							if kv.Value.String() == dna {
								t.Fatalf("%s: strategy DNA leaked into label %s", m.Name, kv.Key)
							}
						}
						checked = true
					}
				}
			}
			if !checked {
				t.Fatal("no data points collected")
			}
		})
	}
}

func TestCensorMetricIsExported(t *testing.T) {
	eng, err := engine.New("")
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	obs := censor.New()
	rm := collect(t, Providers{Mode: "eval", Market: "IR", Engine: eng, Censor: obs})

	byEvent := sums(t, rm, semconv.GenevaTCPEventKey)[semconv.GenevaMetricInboundTCP]
	if byEvent == nil {
		t.Fatalf("%s not exported", semconv.GenevaMetricInboundTCP)
	}
	// Every event must be present at zero: a market showing syns and no data is
	// the burned-box signal, and it can only be read if the zero series exists.
	for _, want := range []string{"rst", "syn", "fin", "data", "ack_only"} {
		if _, ok := byEvent[want]; !ok {
			t.Fatalf("%s missing event %q", semconv.GenevaMetricInboundTCP, want)
		}
	}
}

func TestCensorMetricAbsentWithoutObserver(t *testing.T) {
	eng, err := engine.New("")
	if err != nil {
		t.Fatalf("engine: %v", err)
	}
	rm := collect(t, Providers{Mode: "prod", Engine: eng})
	if got := sums(t, rm, semconv.GenevaTCPEventKey)[semconv.GenevaMetricInboundTCP]; len(got) != 0 {
		t.Fatalf("%s exported without an observer: %v", semconv.GenevaMetricInboundTCP, got)
	}
}

func TestEnabled(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "")
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "")
	if Enabled() {
		t.Fatal("Enabled with no endpoint configured")
	}
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_ENDPOINT", "http://127.0.0.1:4318/v1/metrics")
	if !Enabled() {
		t.Fatal("not Enabled with a metrics endpoint configured")
	}
}
