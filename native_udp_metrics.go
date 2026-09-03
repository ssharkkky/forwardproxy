// Copyright 2026 The NaiveProxy Authors.
// Use of this source code is governed by the Apache License, Version 2.0.

package forwardproxy

import (
	"errors"
	"sync"
	"sync/atomic"
	"time"

	"github.com/prometheus/client_golang/prometheus"
)

// connectUDPMetrics is deliberately low-cardinality. In particular, neither
// client addresses nor CONNECT-UDP targets are metric labels.
var connectUDPMetrics = struct {
	once                sync.Once
	active              prometheus.Gauge
	activePeak          prometheus.Gauge
	activePeakValue     atomic.Uint64
	associations        prometheus.Counter
	admissionRejections *prometheus.CounterVec
	closures            *prometheus.CounterVec
	duration            prometheus.Histogram
}{}

func initConnectUDPMetrics(registry *prometheus.Registry) error {
	if registry == nil {
		return errors.New("no metrics registry found")
	}
	connectUDPMetrics.once.Do(func() {
		const namespace, subsystem = "caddy", "forward_proxy"
		connectUDPMetrics.active = prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "connect_udp_active_associations",
			Help:      "Current CONNECT-UDP associations admitted by forward proxy.",
		})
		connectUDPMetrics.activePeak = prometheus.NewGauge(prometheus.GaugeOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "connect_udp_active_associations_peak",
			Help:      "Highest number of concurrent CONNECT-UDP associations since process start.",
		})
		connectUDPMetrics.associations = prometheus.NewCounter(prometheus.CounterOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "connect_udp_associations_total",
			Help:      "Total CONNECT-UDP associations admitted by forward proxy.",
		})
		connectUDPMetrics.admissionRejections = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "connect_udp_admission_rejections_total",
				Help:      "CONNECT-UDP requests rejected by an admission limit.",
			}, []string{"limit"})
		connectUDPMetrics.closures = prometheus.NewCounterVec(
			prometheus.CounterOpts{
				Namespace: namespace,
				Subsystem: subsystem,
				Name:      "connect_udp_closures_total",
				Help:      "CONNECT-UDP associations closed by reason.",
			}, []string{"reason"})
		connectUDPMetrics.duration = prometheus.NewHistogram(prometheus.HistogramOpts{
			Namespace: namespace,
			Subsystem: subsystem,
			Name:      "connect_udp_association_duration_seconds",
			Help:      "Lifetime of admitted CONNECT-UDP associations in seconds.",
			Buckets:   []float64{0.01, 0.1, 1, 5, 30, 120, 300},
		})
	})

	collectors := []prometheus.Collector{
		connectUDPMetrics.active,
		connectUDPMetrics.activePeak,
		connectUDPMetrics.associations,
		connectUDPMetrics.admissionRejections,
		connectUDPMetrics.closures,
		connectUDPMetrics.duration,
	}
	for _, collector := range collectors {
		if err := registry.Register(collector); err != nil {
			var alreadyRegistered prometheus.AlreadyRegisteredError
			if !errors.As(err, &alreadyRegistered) {
				return err
			}
		}
	}
	return nil
}

func recordConnectUDPAdmission(limit string) {
	if connectUDPMetrics.admissionRejections != nil {
		connectUDPMetrics.admissionRejections.WithLabelValues(limit).Inc()
	}
}

func recordConnectUDPAdmissionAccepted(active uint64) {
	if connectUDPMetrics.active != nil {
		connectUDPMetrics.active.Inc()
		connectUDPMetrics.associations.Inc()
		for {
			peak := connectUDPMetrics.activePeakValue.Load()
			if active <= peak || connectUDPMetrics.activePeakValue.CompareAndSwap(peak, active) {
				if active > peak {
					connectUDPMetrics.activePeak.Set(float64(active))
				}
				break
			}
		}
	}
}

func recordConnectUDPAdmissionReleased(reason string, duration time.Duration) {
	if connectUDPMetrics.active != nil {
		connectUDPMetrics.active.Dec()
		connectUDPMetrics.closures.WithLabelValues(reason).Inc()
		connectUDPMetrics.duration.Observe(duration.Seconds())
	}
}
