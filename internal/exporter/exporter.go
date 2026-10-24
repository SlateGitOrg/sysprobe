// Package exporter exposes aggregated totals as Prometheus metrics.
//
// The collector is "const metric" style: every scrape copies the
// aggregator's cumulative totals and emits them as histograms whose bucket
// boundaries are powers of two nanoseconds, the exact edges of the kernel's
// log2 buckets, so no re-bucketing error is introduced.
package exporter

import (
	"fmt"
	"strconv"

	"github.com/prometheus/client_golang/prometheus"

	"github.com/archit2501/sysprobe/internal/aggregate"
	"github.com/archit2501/sysprobe/internal/hist"
)

// LabelMode selects how process series are labelled.
type LabelMode string

const (
	// ByComm labels by command name only. Totals survive process exit and
	// cardinality is bounded by aggregate.Config.MaxCommLabels; series are
	// monotonic. This is the default.
	ByComm LabelMode = "comm"
	// ByPID adds a pid label. Series vanish when a process is evicted, which
	// is the usual Prometheus behaviour for per-process metrics but
	// multiplies cardinality on busy hosts.
	ByPID LabelMode = "pid"
)

// ParseLabelMode validates a --prom-labels flag value.
func ParseLabelMode(s string) (LabelMode, error) {
	switch LabelMode(s) {
	case ByComm, ByPID:
		return LabelMode(s), nil
	default:
		return "", fmt.Errorf("unknown label mode %q (want %q or %q)", s, ByComm, ByPID)
	}
}

// Options configures the exporter.
type Options struct {
	Labels LabelMode
	// MinPow and MaxPow bound the exported bucket edges: le = 2^k ns for
	// k = MinPow, MinPow+Step, ... <= MaxPow (+Inf is always present).
	// Defaults: 10 (1.024us), 34 (17.2s), step 2.
	MinPow, MaxPow, Step int
}

func (o Options) withDefaults() Options {
	if o.Labels == "" {
		o.Labels = ByComm
	}
	if o.Step <= 0 {
		o.Step = 2
	}
	if o.MinPow <= 0 {
		o.MinPow = 10
	}
	if o.MaxPow <= 0 || o.MaxPow > hist.Slots-1 {
		o.MaxPow = 34
	}
	if o.MinPow > o.MaxPow {
		o.MinPow = o.MaxPow
	}
	return o
}

// Source is the part of the aggregator the exporter needs.
type Source interface {
	Totals(perPID bool) aggregate.Totals
}

// Collector implements prometheus.Collector over an aggregate.Source.
type Collector struct {
	src  Source
	opts Options
	pows []int

	sysLat, runqLat, connLat *prometheus.Desc
	retrans, drops           *prometheus.Desc
	procs, snaps, resets     *prometheus.Desc
	evicted                  *prometheus.Desc
}

// New returns a collector reading from src.
func New(src Source, opts Options) *Collector {
	opts = opts.withDefaults()
	c := &Collector{src: src, opts: opts}
	for k := opts.MinPow; k <= opts.MaxPow; k += opts.Step {
		c.pows = append(c.pows, k)
	}
	proc := []string{"comm"}
	if opts.Labels == ByPID {
		proc = []string{"comm", "pid"}
	}
	c.sysLat = prometheus.NewDesc("sysprobe_syscall_latency_seconds",
		"Syscall latency (sys_enter to sys_exit) per process and syscall.",
		append(append([]string{}, proc...), "syscall"), nil)
	c.runqLat = prometheus.NewDesc("sysprobe_runq_latency_seconds",
		"Run-queue latency (runnable to running) per process.", proc, nil)
	c.connLat = prometheus.NewDesc("sysprobe_tcp_connect_latency_seconds",
		"TCP active-open latency (SYN_SENT to ESTABLISHED or failure) per destination.",
		[]string{"dest", "result"}, nil)
	c.retrans = prometheus.NewDesc("sysprobe_tcp_retransmits_total",
		"TCP segments retransmitted, per destination.", []string{"dest"}, nil)
	c.drops = prometheus.NewDesc("sysprobe_bpf_drops_total",
		"Samples the kernel side could not record, per collector and reason.",
		[]string{"collector", "reason"}, nil)
	c.procs = prometheus.NewDesc("sysprobe_tracked_processes",
		"Processes currently tracked by the aggregator.", nil, nil)
	c.snaps = prometheus.NewDesc("sysprobe_snapshots_total",
		"Kernel map snapshots ingested.", nil, nil)
	c.resets = prometheus.NewDesc("sysprobe_series_resets_total",
		"Cumulative kernel series that went backwards (re-created keys).", nil, nil)
	c.evicted = prometheus.NewDesc("sysprobe_evicted_processes_total",
		"Processes evicted from the aggregator after exit or by the cap.", nil, nil)
	return c
}

// Describe implements prometheus.Collector.
func (c *Collector) Describe(ch chan<- *prometheus.Desc) {
	for _, d := range []*prometheus.Desc{
		c.sysLat, c.runqLat, c.connLat, c.retrans, c.drops, c.procs, c.snaps, c.resets, c.evicted,
	} {
		ch <- d
	}
}

// buckets converts a log2 histogram into Prometheus cumulative buckets
// keyed by upper bound in seconds.
func (c *Collector) buckets(h *hist.Log2) map[float64]uint64 {
	out := make(map[float64]uint64, len(c.pows))
	for _, k := range c.pows {
		out[float64(uint64(1)<<uint(k))/1e9] = h.CumulativeAt(k)
	}
	return out
}

func (c *Collector) histogram(ch chan<- prometheus.Metric, d *prometheus.Desc, h *hist.Log2, lv ...string) {
	ch <- prometheus.MustNewConstHistogram(d, h.Total(), float64(h.SumNs)/1e9, c.buckets(h), lv...)
}

// Collect implements prometheus.Collector.
func (c *Collector) Collect(ch chan<- prometheus.Metric) {
	t := c.src.Totals(c.opts.Labels == ByPID)
	if c.opts.Labels == ByPID {
		for i := range t.PIDSys {
			s := &t.PIDSys[i]
			c.histogram(ch, c.sysLat, &s.Hist, s.Comm, strconv.FormatUint(uint64(s.TGID), 10), s.Syscall)
		}
		for i := range t.PIDRunq {
			s := &t.PIDRunq[i]
			c.histogram(ch, c.runqLat, &s.Hist, s.Comm, strconv.FormatUint(uint64(s.TGID), 10))
		}
	} else {
		for i := range t.CommSys {
			s := &t.CommSys[i]
			c.histogram(ch, c.sysLat, &s.Hist, s.Comm, s.Syscall)
		}
		for i := range t.CommRunq {
			s := &t.CommRunq[i]
			c.histogram(ch, c.runqLat, &s.Hist, s.Comm)
		}
	}
	for i := range t.Dests {
		d := &t.Dests[i]
		c.histogram(ch, c.connLat, &d.ConnectOK, d.Dest, "ok")
		c.histogram(ch, c.connLat, &d.ConnectFail, d.Dest, "fail")
		ch <- prometheus.MustNewConstMetric(c.retrans, prometheus.CounterValue, float64(d.Retransmits), d.Dest)
	}
	for _, d := range t.Drops {
		ch <- prometheus.MustNewConstMetric(c.drops, prometheus.CounterValue, float64(d.Count), d.Collector, d.Reason)
	}
	ch <- prometheus.MustNewConstMetric(c.procs, prometheus.GaugeValue, float64(t.Processes))
	ch <- prometheus.MustNewConstMetric(c.snaps, prometheus.CounterValue, float64(t.Snapshots))
	ch <- prometheus.MustNewConstMetric(c.resets, prometheus.CounterValue, float64(t.Resets))
	ch <- prometheus.MustNewConstMetric(c.evicted, prometheus.CounterValue, float64(t.Evicted))
}
