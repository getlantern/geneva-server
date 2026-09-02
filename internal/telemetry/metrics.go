package telemetry

import (
	"context"
	"fmt"
	"time"

	semconv "github.com/getlantern/semconv"
	sdkotel "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/metric"

	"github.com/getlantern/geneva-server/internal/censor"
	"github.com/getlantern/geneva-server/internal/engine"
)

// meterName scopes the instruments to this package.
const meterName = "github.com/getlantern/geneva-server"

// Verdicts mirrors the NFQUEUE runtime's counters. The runtime itself is
// Linux-only, so it is copied into a portable struct here rather than imported:
// that keeps this package (and its tests) building on any platform.
type Verdicts struct {
	Accepted    uint64
	Dropped     uint64
	Modified    uint64
	Reinjected  uint64
	InjectFails uint64
	Overruns    uint64
}

// Providers supplies the live objects the instruments read on each collection.
type Providers struct {
	// Mode is "prod" or "eval".
	Mode string
	// Market is the ISO 3166-1 alpha-2 code the box serves; empty or "unknown"
	// is omitted from the labels rather than exported as a literal "unknown"
	// series.
	Market string
	// Engine is required.
	Engine interface{ Snapshot() engine.Snapshot }
	// Censor is where the inbound TCP counts come from — the kernel's
	// classification counters on a box that has them, the userspace classifier
	// otherwise. Nil disables the censor metric.
	Censor censor.Source
	// Verdicts reads the runtime's counters. Nil disables the verdict metrics
	// (the runtime is not up yet, or this is a non-Linux build).
	Verdicts func() Verdicts
	// Started is the process start time, reported as geneva.uptime.
	Started time.Time
}

// Register creates the sidecar's observable instruments against the global
// meter provider and wires them to a single batch callback, so every metric in
// one export interval is read from the same instant.
//
// The instruments are observable rather than synchronous on purpose: the
// counters already exist as atomics updated on the packet path, and calling
// into the OTel SDK per packet would put an allocation and a lock on the
// proxy's latency budget at line rate. Observation happens once per export.
func Register(p Providers) error {
	if p.Engine == nil {
		return fmt.Errorf("telemetry: Engine is required")
	}
	meter := sdkotel.Meter(meterName)

	base := []attribute.KeyValue{semconv.GenevaModeKey.String(p.Mode)}
	if p.Market != "" && p.Market != "unknown" {
		base = append(base, semconv.GeoCountryISOCodeKey.String(p.Market))
	}
	baseSet := metric.WithAttributes(base...)

	// Per-value attribute sets are built once here, not per collection: an
	// attribute.Set allocates, and these are the same handful of label
	// combinations on every export for the life of the process.
	outcomeAttrs := make([]metric.MeasurementOption, 0, 4)
	outcomes := []engine.Outcome{
		engine.OutcomeUnchanged, engine.OutcomeDropped,
		engine.OutcomeTampered, engine.OutcomeExpanded,
	}
	for _, o := range outcomes {
		outcomeAttrs = append(outcomeAttrs,
			metric.WithAttributes(append(base[:len(base):len(base)], semconv.GenevaOutcomeKey.String(o.String()))...))
	}

	verdictNames := []string{"accepted", "dropped", "modified"}
	verdictAttrs := make([]metric.MeasurementOption, 0, len(verdictNames))
	for _, v := range verdictNames {
		verdictAttrs = append(verdictAttrs,
			metric.WithAttributes(append(base[:len(base):len(base)], semconv.GenevaVerdictKey.String(v))...))
	}

	reinjectOK := metric.WithAttributes(append(base[:len(base):len(base)], semconv.GenevaReinjectionKey.String("ok"))...)
	reinjectFailed := metric.WithAttributes(append(base[:len(base):len(base)], semconv.GenevaReinjectionKey.String("failed"))...)

	tcpEvents := []censor.Event{
		censor.EventRST, censor.EventSYN, censor.EventFIN,
		censor.EventData, censor.EventACKOnly,
		censor.EventFragment, censor.EventUndecodable,
	}
	tcpAttrs := make([]metric.MeasurementOption, 0, len(tcpEvents))
	for _, e := range tcpEvents {
		tcpAttrs = append(tcpAttrs,
			metric.WithAttributes(append(base[:len(base):len(base)], semconv.GenevaTCPEventKey.String(e.String()))...))
	}

	packetsIn, err := meter.Int64ObservableCounter(semconv.GenevaMetricPacketsIn,
		metric.WithUnit("{packet}"),
		metric.WithDescription("packets delivered to the engine by NFQUEUE"))
	if err != nil {
		return err
	}
	packetsOut, err := meter.Int64ObservableCounter(semconv.GenevaMetricPacketsOut,
		metric.WithUnit("{packet}"),
		metric.WithDescription("packets the strategy produced (fan-out included)"))
	if err != nil {
		return err
	}
	bytesIn, err := meter.Int64ObservableCounter(semconv.GenevaMetricBytesIn,
		metric.WithUnit("By"),
		metric.WithDescription("bytes delivered to the engine"))
	if err != nil {
		return err
	}
	bytesOut, err := meter.Int64ObservableCounter(semconv.GenevaMetricBytesOut,
		metric.WithUnit("By"),
		metric.WithDescription("bytes the strategy produced"))
	if err != nil {
		return err
	}
	outcomeCounter, err := meter.Int64ObservableCounter(semconv.GenevaMetricOutcomes,
		metric.WithUnit("{packet}"),
		metric.WithDescription("packets by what the strategy did to them"))
	if err != nil {
		return err
	}
	errorCounter, err := meter.Int64ObservableCounter(semconv.GenevaMetricErrors,
		metric.WithDescription("packets the engine failed to decode or apply a strategy to"))
	if err != nil {
		return err
	}
	packetOverhead, err := meter.Float64ObservableGauge(semconv.GenevaMetricPacketOverhead,
		metric.WithUnit("1"),
		metric.WithDescription("packets out over packets in, minus one"))
	if err != nil {
		return err
	}
	byteOverhead, err := meter.Float64ObservableGauge(semconv.GenevaMetricByteOverhead,
		metric.WithUnit("1"),
		metric.WithDescription("bytes out over bytes in, minus one"))
	if err != nil {
		return err
	}
	swaps, err := meter.Int64ObservableCounter(semconv.GenevaMetricStrategySwaps,
		metric.WithDescription("strategies installed in place after the initial load"))
	if err != nil {
		return err
	}
	uptime, err := meter.Float64ObservableGauge(semconv.GenevaMetricUptime,
		metric.WithUnit("s"),
		metric.WithDescription("seconds since the sidecar started"))
	if err != nil {
		return err
	}
	verdictCounter, err := meter.Int64ObservableCounter(semconv.GenevaMetricVerdicts,
		metric.WithUnit("{packet}"),
		metric.WithDescription("NFQUEUE verdicts issued"))
	if err != nil {
		return err
	}
	reinjections, err := meter.Int64ObservableCounter(semconv.GenevaMetricReinjections,
		metric.WithUnit("{packet}"),
		metric.WithDescription("raw-socket reinjection results"))
	if err != nil {
		return err
	}
	deliveryOverruns, err := meter.Int64ObservableCounter("geneva.runtime.delivery_overruns",
		metric.WithUnit("{event}"),
		metric.WithDescription("NFQUEUE userspace-delivery ENOBUFS events; packet outcomes are unknown"))
	if err != nil {
		return err
	}
	inboundTCP, err := meter.Int64ObservableCounter(semconv.GenevaMetricInboundTCP,
		metric.WithUnit("{packet}"),
		metric.WithDescription("inbound TCP packets on the steered port, by flags and payload"))
	if err != nil {
		return err
	}

	instruments := []metric.Observable{
		packetsIn, packetsOut, bytesIn, bytesOut, outcomeCounter, errorCounter,
		packetOverhead, byteOverhead, swaps, uptime, verdictCounter, reinjections, deliveryOverruns,
		inboundTCP,
	}

	_, err = meter.RegisterCallback(func(_ context.Context, o metric.Observer) error {
		snap := p.Engine.Snapshot()
		o.ObserveInt64(packetsIn, int64(snap.PacketsIn), baseSet)
		o.ObserveInt64(packetsOut, int64(snap.PacketsOut), baseSet)
		o.ObserveInt64(bytesIn, int64(snap.BytesIn), baseSet)
		o.ObserveInt64(bytesOut, int64(snap.BytesOut), baseSet)
		o.ObserveInt64(errorCounter, int64(snap.Errors), baseSet)
		o.ObserveInt64(swaps, int64(snap.Swaps), baseSet)
		o.ObserveFloat64(packetOverhead, snap.PacketOverhead, baseSet)
		o.ObserveFloat64(byteOverhead, snap.ByteOverhead, baseSet)

		counts := []uint64{snap.Unchanged, snap.Dropped, snap.Tampered, snap.Expanded}
		for i, c := range counts {
			o.ObserveInt64(outcomeCounter, int64(c), outcomeAttrs[i])
		}

		if !p.Started.IsZero() {
			o.ObserveFloat64(uptime, time.Since(p.Started).Seconds(), baseSet)
		}

		if p.Verdicts != nil {
			v := p.Verdicts()
			for i, c := range []uint64{v.Accepted, v.Dropped, v.Modified} {
				o.ObserveInt64(verdictCounter, int64(c), verdictAttrs[i])
			}
			o.ObserveInt64(reinjections, int64(v.Reinjected), reinjectOK)
			o.ObserveInt64(reinjections, int64(v.InjectFails), reinjectFailed)
			o.ObserveInt64(deliveryOverruns, int64(v.Overruns), baseSet)
		}

		if p.Censor != nil {
			for i, e := range tcpEvents {
				o.ObserveInt64(inboundTCP, int64(p.Censor.Count(e)), tcpAttrs[i])
			}
		}
		return nil
	}, instruments...)
	if err != nil {
		return fmt.Errorf("register metric callback: %w", err)
	}
	return nil
}
