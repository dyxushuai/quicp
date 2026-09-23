#!/usr/bin/env python3
"""Convert the existing benchmark CSV files to Bencher Metric Format."""

import argparse
import csv
import json
import math
from pathlib import Path

PAYLOADS = (64, 1200, 4096)
CODEC_METRICS = {
    "ns_per_packet": "latency",
    "payload_gbps": "payload-gbps",
    "allocations": "allocations-per-run",
}
LOOPBACK_METRICS = {
    "p50_delivery_ns": "delivery-p50-ns",
    "p95_delivery_ns": "delivery-p95-ns",
    "p99_delivery_ns": "delivery-p99-ns",
    "median_gbps": "payload-gbps",
    "median_cpu_pct": "cpu-percent",
    "median_allocations_per_run": "allocations-per-run",
    "median_absolute_peak_live_rust_heap_bytes": "rust-heap-bytes",
    "delivery_samples": "delivery-samples",
    "source_sent_total": "source-sent",
    "source_received_total": "source-received",
    "repair_sent_total": "repair-sent",
    "repair_symbols_per_million_source": "repair-per-million-source",
    "recovered_total": "recovered",
    "replayed_total": "replayed",
    "fallback_total": "fallback",
    "dropped_total": "dropped",
}
SUITES = {
    "carrier_encode": (("vec", "buffer"), CODEC_METRICS),
    "carrier_decode": (("owned", "borrowed"), CODEC_METRICS),
    "loopback": (("adaptive", "reliable"), LOOPBACK_METRICS),
}


def validate_value(measure, value):
    if type(value) not in (int, float) or not math.isfinite(value) or value < 0:
        raise ValueError(f"{measure}: invalid value")
    if value == 0 and (measure == "latency" or measure.endswith("-ns")
                       or measure in ("payload-gbps", "delivery-samples")):
        raise ValueError(f"{measure}: empty measurement")


def convert(suite, lines):
    modes, columns = SUITES[suite]
    reader = csv.DictReader(line for line in lines if not line.startswith("#"))
    required = {"payload_bytes"} | {
        f"{mode}_{column}" for mode in modes for column in columns
    }
    if not reader.fieldnames or not required.issubset(reader.fieldnames):
        raise ValueError(f"{suite}: missing CSV columns")
    if len(reader.fieldnames) != len(set(reader.fieldnames)):
        raise ValueError(f"{suite}: duplicate CSV columns")
    results, seen = {}, set()
    for row in reader:
        if None in row or None in row.values():
            raise ValueError(f"{suite}: malformed CSV row")
        payload = int(row["payload_bytes"])
        if payload not in PAYLOADS or payload in seen:
            raise ValueError(f"{suite}: unexpected or duplicate payload {payload}")
        seen.add(payload)
        for mode in modes:
            metrics = {}
            for column, measure in columns.items():
                value = float(row[f"{mode}_{column}"])
                validate_value(measure, value)
                metrics[measure] = {"value": value}
            results[f"{suite}/{mode}/{payload}"] = metrics
    if seen != set(PAYLOADS):
        raise ValueError(f"{suite}: missing payload measurements")
    return results


def validate(results):
    """Reject missing or injected series before publishing an untrusted artifact."""
    expected = {
        f"{suite}/{mode}/{payload}": set(columns.values())
        for suite, (modes, columns) in SUITES.items()
        for mode in modes for payload in PAYLOADS
    }
    if not isinstance(results, dict) or results.keys() != expected.keys():
        raise ValueError("unexpected or missing benchmark series")
    for benchmark, measures in expected.items():
        metrics = results[benchmark]
        if not isinstance(metrics, dict) or metrics.keys() != measures:
            raise ValueError(f"{benchmark}: unexpected or missing measures")
        for measure, metric in metrics.items():
            if not isinstance(metric, dict) or set(metric) != {"value"}:
                raise ValueError(f"{benchmark}: invalid metric")
            validate_value(measure, metric["value"])


def summarize(report):
    """Show alerted comparisons and keep complete details in the Bencher report."""
    rows = []
    all_rows = []
    comparisons = 0
    alert_count = report["counts"]["alerts"]["total"]
    alerts = report.get("alerts")
    alerted = {
        (alert["benchmark"]["slug"], alert["threshold"]["measure"]["slug"])
        for alert in alerts or []
    }
    show_all = alerts is None or len(alerts) != alert_count
    for iteration in report["results"]:
        for result in iteration:
            benchmark = result["benchmark"]["name"].replace("|", "\\|").replace("\n", " ")
            for metric in result["measures"]:
                if metric.get("threshold") is None:
                    continue
                boundary = metric.get("boundary") or {}
                comparisons += bool(boundary)
                baseline = boundary.get("baseline")
                value = metric["metric"]["value"]
                change = (f"{value / baseline - 1:+.2%}" if baseline else
                          "0.00%" if baseline == value == 0 else "n/a")
                base = f"{baseline:.6g}" if baseline is not None else "n/a"
                measure = metric["measure"]["slug"].replace("|", "\\|").replace("\n", " ")
                row = f"| {benchmark} | {measure} | {base} | {value:.6g} | {change} |"
                all_rows.append(row)
                if show_all or (result["benchmark"]["slug"], metric["measure"]["slug"]) in alerted:
                    rows.append(row)
    if alert_count and not rows:
        rows = all_rows
    url = f'https://bencher.dev/perf/quicp/reports/{report["uuid"]}'
    summary = [
        "## Bencher summary", "", f"**{comparisons} comparisons; {alert_count} alerts.**", "",
        f"[Full report]({url}) · `latency` is in ns; custom measures include their units.", "",
    ]
    if rows:
        summary.extend([
            "| Benchmark | Measure | Baseline | Current | Change |",
            "| --- | --- | ---: | ---: | ---: |", *rows,
        ])
    else:
        summary.append("No benchmark regressions crossed the configured thresholds.")
    return "\n".join(summary + [""])


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("directory", type=Path, nargs="?", help="directory of <suite>.csv files")
    parser.add_argument("--validate", type=Path, help="validate a complete BMF report")
    parser.add_argument("--summary", type=Path, help="summarize a published Bencher report")
    args = parser.parse_args()
    if args.summary:
        print(summarize(json.loads(args.summary.read_text())))
    elif args.validate:
        if args.validate.stat().st_size > 100_000:
            parser.error("report exceeds 100 KB")
        validate(json.loads(args.validate.read_text()))
    elif args.directory:
        results = {}
        for suite in SUITES:
            with (args.directory / f"{suite}.csv").open() as source:
                results.update(convert(suite, source))
        validate(results)
        print(json.dumps(results, allow_nan=False, indent=2))
    else:
        parser.error("provide a CSV directory or --validate")


if __name__ == "__main__":
    main()
