// Package app wires sources, the aggregator, the Prometheus exporter and the
// top view into the commands exposed by cmd/sysprobe. Everything here runs
// unchanged against the live probe and against recorded fixtures.
package app

import (
	"bytes"
	"fmt"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/prometheus/common/expfmt"

	"github.com/SlateGitOrg/sysprobe/internal/exporter"
)

// Registry builds a registry holding the sysprobe collector and, when self
// is true, the Go runtime and process collectors for sysprobe itself.
func Registry(src exporter.Source, opts exporter.Options, self bool) (*prometheus.Registry, error) {
	reg := prometheus.NewRegistry()
	if err := reg.Register(exporter.New(src, opts)); err != nil {
		return nil, fmt.Errorf("register sysprobe collector: %w", err)
	}
	if self {
		if err := reg.Register(collectors.NewGoCollector()); err != nil {
			return nil, fmt.Errorf("register go collector: %w", err)
		}
		if err := reg.Register(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{})); err != nil {
			return nil, fmt.Errorf("register process collector: %w", err)
		}
	}
	return reg, nil
}

// MetricsText renders the registry in the Prometheus text format.
func MetricsText(reg prometheus.Gatherer) (string, error) {
	mfs, err := reg.Gather()
	if err != nil {
		return "", fmt.Errorf("gather metrics: %w", err)
	}
	var buf bytes.Buffer
	enc := expfmt.NewEncoder(&buf, expfmt.NewFormat(expfmt.TypeTextPlain))
	for _, mf := range mfs {
		if err := enc.Encode(mf); err != nil {
			return "", fmt.Errorf("encode metrics: %w", err)
		}
	}
	return buf.String(), nil
}

// NewServer returns an HTTP server exposing /metrics and /healthz.
func NewServer(addr string, reg *prometheus.Registry) *http.Server {
	mux := http.NewServeMux()
	mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{Registry: reg}))
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = w.Write([]byte("ok\n"))
	})
	return &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 5 * time.Second}
}
