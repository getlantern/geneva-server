// Package telemetry sets up the sidecar's OTLP metric export and registers the
// runtime's counters as observable instruments.
//
// The sidecar exports metrics rather than serving them: the box already runs an
// otel collector that forwards to SigNoz, and lantern-cloud reads box metrics
// from SigNoz. Having the GA brain SSH to each box to scrape a counter would
// duplicate a pipeline that already exists and does not aggregate across the
// pool. The control surface keeps only the synchronous reads that cannot
// tolerate export-and-query latency (see internal/control).
//
// Export is opt-in via the standard OTEL_EXPORTER_OTLP_* environment variables,
// so a box with no collector configured runs with metrics disabled and no
// export goroutine, exactly like lantern-box.
package telemetry

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"time"

	semconv "github.com/getlantern/semconv"
	sdkotel "go.opentelemetry.io/otel"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/exporters/otlp/otlpmetric/otlpmetrichttp"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
)

// ServiceName is the service.name every geneva-server resource carries.
const ServiceName = "geneva-server"

// Enabled reports whether an OTLP endpoint is configured. With none set there
// is nothing to export to, so Init is skipped entirely.
func Enabled() bool {
	for _, key := range []string{
		"OTEL_EXPORTER_OTLP_ENDPOINT",
		"OTEL_EXPORTER_OTLP_METRICS_ENDPOINT",
	} {
		if os.Getenv(key) != "" {
			return true
		}
	}
	return false
}

// Init installs a global meter provider exporting over OTLP/HTTP and returns a
// shutdown function that flushes pending metrics. extras are added to the
// resource; the endpoint, headers, and any further resource attributes come
// from the standard OTEL_* environment variables.
func Init(ctx context.Context, extras ...attribute.KeyValue) (func(), error) {
	exp, err := otlpmetrichttp.New(ctx,
		otlpmetrichttp.WithTemporalitySelector(deltaForCounters),
	)
	if err != nil {
		return nil, fmt.Errorf("new otlp metric exporter: %w", err)
	}
	mp := sdkmetric.NewMeterProvider(
		sdkmetric.WithReader(sdkmetric.NewPeriodicReader(exp)),
		sdkmetric.WithResource(buildResource(ctx, extras...)),
	)
	sdkotel.SetMeterProvider(mp)

	return func() {
		shCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		_ = mp.Shutdown(shCtx)
	}, nil
}

// deltaForCounters matches the fleet's temporality choice: counters export as
// deltas so a sidecar restart (or a test box being torn down and replaced,
// which happens constantly as IPs burn) does not read as a negative jump or
// require the backend to track resets across short-lived series.
func deltaForCounters(kind sdkmetric.InstrumentKind) metricdata.Temporality {
	switch kind {
	case sdkmetric.InstrumentKindCounter,
		sdkmetric.InstrumentKindUpDownCounter,
		sdkmetric.InstrumentKindObservableCounter,
		sdkmetric.InstrumentKindObservableUpDownCounter:
		return metricdata.DeltaTemporality
	default:
		return metricdata.CumulativeTemporality
	}
}

func buildResource(ctx context.Context, extras ...attribute.KeyValue) *resource.Resource {
	attrs := append([]attribute.KeyValue{
		semconv.ServiceNameKey.String(ServiceName),
		semconv.ServiceVersionKey.String(vcsRevision()),
	}, extras...)
	// resource.WithFromEnv reads OTEL_SERVICE_NAME and OTEL_RESOURCE_ATTRIBUTES,
	// which is how the box's cloud-init supplies deployment.environment and the
	// host/route identity. It is applied last so it overrides the defaults above.
	r, err := resource.New(ctx,
		resource.WithAttributes(attrs...),
		resource.WithFromEnv(),
	)
	if err != nil {
		// resource.New returns a usable resource alongside a partial-detection
		// error (e.g. a malformed OTEL_RESOURCE_ATTRIBUTES entry). Degraded
		// resource attributes are not worth failing startup for.
		if r == nil {
			return resource.Default()
		}
	}
	return r
}

func vcsRevision() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "unknown"
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" {
			return s.Value
		}
	}
	return "unknown"
}
