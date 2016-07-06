// Copyright 2015 The Prometheus Authors
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// +build !noksmd

package collector

import (
	"fmt"
	"path"

	"github.com/prometheus/client_golang/prometheus"
)

var (
	ksmdFiles = []string{"full_scans", "merge_across_nodes", "pages_shared", "pages_sharing",
		"pages_to_scan", "pages_unshared", "pages_volatile", "run", "sleep_millisecs"}
)

type ksmdCollector struct {
	metricDescs map[string]*prometheus.Desc
}

func init() {
	Factories["ksmd"] = NewKsmdCollector
}

func getCanonicalMetricName(filename string) string {
	switch filename {
	case "full_scans":
		return filename + "_total"
	case "sleep_millisecs":
		return "sleep_seconds"
	default:
		return filename
	}
}

// Takes a prometheus registry and returns a new Collector exposing
// kernel/system statistics.
func NewKsmdCollector() (Collector, error) {
	subsystem := "ksmd"
	descs := make(map[string]*prometheus.Desc)

	for _, n := range ksmdFiles {
		descs[n] = prometheus.NewDesc(
			prometheus.BuildFQName(Namespace, subsystem, getCanonicalMetricName(n)),
			fmt.Sprintf("ksmd '%s' file.", n), nil, nil)
	}
	return &ksmdCollector{descs}, nil
}

// Expose kernel and system statistics.
func (c *ksmdCollector) Update(ch chan<- prometheus.Metric) (err error) {
	for _, n := range ksmdFiles {
		val, err := readUintFromFile(sysFilePath(path.Join("kernel/mm/ksm", n)))
		if err != nil {
			return err
		}

		t := prometheus.GaugeValue
		v := float64(val)
		switch n {
		case "full_scans":
			t = prometheus.CounterValue
		case "sleep_millisecs":
			v /= 1000
		}
		ch <- prometheus.MustNewConstMetric(c.metricDescs[n], t, v)
	}

	return nil
}