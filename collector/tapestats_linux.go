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

// +build !notapestats

package collector

import (
	"fmt"
	"path/filepath"
	"regexp"

	"github.com/go-kit/kit/log"
	"github.com/go-kit/kit/log/level"
	"github.com/prometheus/client_golang/prometheus"
	"gopkg.in/alecthomas/kingpin.v2"
)

var (
	ignoredTapeDevices = kingpin.Flag("collector.tapestats.ignored-devices", "Regexp of devices to ignore for tapestats.").Default("^$").String()
)

type tapestatsCollector struct {
	ignoredDevicesPattern *regexp.Regexp
	ioNow                 *prometheus.Desc
	ioTimeSeconds         *prometheus.Desc
	othersCompletedTotal  *prometheus.Desc
	readByteTotal         *prometheus.Desc
	readsCompletedTotal   *prometheus.Desc
	readTimeSeconds       *prometheus.Desc
	writeByteTotal        *prometheus.Desc
	writesCompletedTotal  *prometheus.Desc
	writeTimeSeconds      *prometheus.Desc
	residualTotal         *prometheus.Desc
	logger                log.Logger
}

func init() {
	registerCollector("tapestats", defaultEnabled, NewTapestatsCollector)
}

// NewTapestatsCollector returns a new Collector exposing tape device stats.
// Docs from https://www.kernel.org/doc/html/latest/scsi/st.html#sysfs-and-statistics-for-tape-devices
func NewTapestatsCollector(logger log.Logger) (Collector, error) {
	var tapeLabelNames = []string{"device"}

	tapeSubsystem := "tape"

	return &tapestatsCollector{
		ignoredDevicesPattern: regexp.MustCompile(*ignoredTapeDevices),

		ioNow: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, tapeSubsystem, "io_now"),
			"The number of I/Os currently outstanding to this device.",
			tapeLabelNames, nil,
		),
		ioTimeSeconds: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, tapeSubsystem, "io_time_seconds_total"),
			"The amount of time spent waiting (in nanoseconds) for all I/O to complete (including read and write). This includes tape movement commands such as seeking between file or set marks and implicit tape movement such as when rewind on close tape devices are used.",
			tapeLabelNames, nil,
		),
		othersCompletedTotal: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, tapeSubsystem, "io_others_total"),
			"The number of I/Os issued to the tape drive other than read or write commands. The time taken to complete these commands uses the following calculation io_time_seconds_total-read_time_seconds_total-write_time_seconds_total",
			tapeLabelNames, nil,
		),
		readByteTotal: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, tapeSubsystem, "read_bytes_total"),
			"The number of bytes read from the tape drive.",
			tapeLabelNames, nil,
		),
		readsCompletedTotal: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, tapeSubsystem, "reads_completed_total"),
			"The number of read requests issued to the tape drive.",
			tapeLabelNames, nil,
		),
		readTimeSeconds: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, tapeSubsystem, "read_time_seconds_total"),
			"The amount of time spent waiting for read requests to complete.",
			tapeLabelNames, nil,
		),
		writeByteTotal: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, tapeSubsystem, "write_bytes_total"),
			"The number of bytes written to the tape drive.",
			tapeLabelNames, nil,
		),
		writesCompletedTotal: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, tapeSubsystem, "writes_completed_total"),
			"The number of write requests issued to the tape drive.",
			tapeLabelNames, nil,
		),
		writeTimeSeconds: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, tapeSubsystem, "write_time_seconds_total"),
			"The amount of time spent waiting for write requests to complete.",
			tapeLabelNames, nil,
		),
		residualTotal: prometheus.NewDesc(
			prometheus.BuildFQName(namespace, tapeSubsystem, "residual_total"),
			"The number of times during a read or write we found the residual amount to be non-zero. This should mean that a program is issuing a read larger thean the block size on tape. For write not all data made it to tape.",
			tapeLabelNames, nil,
		),
		logger: logger,
	}, nil
}

func (c *tapestatsCollector) Update(ch chan<- prometheus.Metric) error {
	tapeStats, err := filepath.Glob(sysFilePath("class/scsi_tape/st*[^a-z]/stats"))
	if err != nil {
		return fmt.Errorf("couldn't get tapestats: %w", err)
	}

	for _, stats := range tapeStats {
		dev := filepath.Base(filepath.Dir(stats))
		if c.ignoredDevicesPattern.MatchString(dev) {
			level.Debug(c.logger).Log("msg", "Ignoring device", "device", dev)
			continue
		}

		if value, err := readUintFromFile(filepath.Join(stats, "in_flight")); err == nil {
			ch <- prometheus.MustNewConstMetric(c.ioNow, prometheus.GaugeValue, float64(value), dev)
		} else {
			level.Debug(c.logger).Log("msg", "Tape is missing 'stats/in_flight'", "device", dev, "err", err)
		}
		if value, err := readUintFromFile(filepath.Join(stats, "io_ns")); err == nil {
			ch <- prometheus.MustNewConstMetric(c.ioTimeSeconds, prometheus.CounterValue, float64(value)*0.000000001, dev)
		} else {
			level.Debug(c.logger).Log("msg", "Tape is missing 'stats/io_ns'", "device", dev, "err", err)
		}
		if value, err := readUintFromFile(filepath.Join(stats, "other_cnt")); err == nil {
			ch <- prometheus.MustNewConstMetric(c.othersCompletedTotal, prometheus.CounterValue, float64(value), dev)
		} else {
			level.Debug(c.logger).Log("msg", "Tape is missing 'stats/other_cnt'", "device", dev, "err", err)
		}
		if value, err := readUintFromFile(filepath.Join(stats, "read_byte_cnt")); err == nil {
			ch <- prometheus.MustNewConstMetric(c.readByteTotal, prometheus.CounterValue, float64(value), dev)
		} else {
			level.Debug(c.logger).Log("msg", "Tape is missing 'stats/read_byte_cnt'", "device", dev, "err", err)
		}
		if value, err := readUintFromFile(filepath.Join(stats, "read_cnt")); err == nil {
			ch <- prometheus.MustNewConstMetric(c.readsCompletedTotal, prometheus.CounterValue, float64(value), dev)
		} else {
			level.Debug(c.logger).Log("msg", "Tape is missing 'stats/read_cnt'", "device", dev, "err", err)
		}
		if value, err := readUintFromFile(filepath.Join(stats, "read_ns")); err == nil {
			ch <- prometheus.MustNewConstMetric(c.readTimeSeconds, prometheus.CounterValue, float64(value)*0.000000001, dev)
		} else {
			level.Debug(c.logger).Log("msg", "Tape is missing 'stats/read_ns'", "device", dev, "err", err)
		}
		if value, err := readUintFromFile(filepath.Join(stats, "write_byte_cnt")); err == nil {
			ch <- prometheus.MustNewConstMetric(c.writeByteTotal, prometheus.CounterValue, float64(value), dev)
		} else {
			level.Debug(c.logger).Log("msg", "Tape is missing 'stats/write_byte_cnt'", "device", dev, "err", err)
		}
		if value, err := readUintFromFile(filepath.Join(stats, "write_cnt")); err == nil {
			ch <- prometheus.MustNewConstMetric(c.writesCompletedTotal, prometheus.CounterValue, float64(value), dev)
		} else {
			level.Debug(c.logger).Log("msg", "Tape is missing 'stats/write_cnt'", "device", dev, "err", err)
		}
		if value, err := readUintFromFile(filepath.Join(stats, "write_ns")); err == nil {
			ch <- prometheus.MustNewConstMetric(c.writeTimeSeconds, prometheus.CounterValue, float64(value)*0.000000001, dev)
		} else {
			level.Debug(c.logger).Log("msg", "Tape is missing 'stats/write_ns'", "device", dev, "err", err)
		}
		if value, err := readUintFromFile(filepath.Join(stats, "resid_cnt")); err == nil {
			ch <- prometheus.MustNewConstMetric(c.residualTotal, prometheus.CounterValue, float64(value)*0.000000001, dev)
		} else {
			level.Debug(c.logger).Log("msg", "Tape is missing 'stats/resid_cnt'", "device", dev, "err", err)
		}
	}
	return nil
}
