"""Run with python3 -m unittest discover -s benches -p 'test_*.py'."""

import io
import unittest

from bencher import PAYLOADS, SUITES, convert, summarize, validate


class BencherTest(unittest.TestCase):
    def test_summary_preserves_comparisons_and_zero_baselines(self):
        metric = {"threshold": {}, "boundary": {"baseline": 0},
                  "metric": {"value": 0}, "measure": {"slug": "latency"}}
        report = {"uuid": "report-id", "counts": {"alerts": {"total": 1}},
                  "results": [[{"benchmark": {"name": "case|name"}, "measures": [metric]}]]}
        self.assertIn("1 comparisons; 1 alerts", summarize(report))
        self.assertIn("case\\|name | latency | 0 | 0 | 0.00%", summarize(report))
        metric["metric"]["value"] = 120
        self.assertIn("| 0 | 120 | n/a |", summarize(report))
        metric["boundary"]["baseline"] = 100
        self.assertIn("| 100 | 120 | +20.00% |", summarize(report))
        metric["boundary"] = None
        self.assertIn("0 comparisons", summarize(report))
        del metric["threshold"]
        self.assertNotIn("| case", summarize(report))

    def test_csv_and_report_boundaries(self):
        results = {}
        for suite, (modes, columns) in SUITES.items():
            header = "payload_bytes," + ",".join(
                f"{mode}_{column}" for mode in modes for column in columns
            ) + "\n"
            rows = [f"{payload}," + ",".join(["1"] * (len(modes) * len(columns)))
                    + "\n" for payload in PAYLOADS]
            data = "# metadata\n" + header + "".join(rows) + "# footer\n"
            converted = convert(suite, io.StringIO(data))
            self.assertEqual(len(converted), 6)
            self.assertEqual(converted[f"{suite}/{modes[0]}/64"],
                             {measure: {"value": 1.0} for measure in columns.values()})
            results.update(converted)
            for invalid in ("", header, header + "".join(rows[:-1]),
                            data + rows[0], data.replace("64,1,", "64,NaN,"),
                            data.replace("64,1,", "64,-1,"),
                            data.replace("64,1,", "64,0,"),
                            data.replace("64,1,", "64,NA,"),
                            data.replace("64,1,", "64,1,1,")):
                with self.subTest(suite=suite, invalid=invalid):
                    with self.assertRaises(ValueError):
                        convert(suite, io.StringIO(invalid))
        validate(results)
        key = "carrier_encode/buffer/64"
        results[key]["allocations-per-run"]["value"] = 0
        validate(results)
        results[key]["latency"]["value"] = float("inf")
        with self.assertRaises(ValueError):
            validate(results)
        results[key]["latency"]["value"] = 1
        del results[key]
        with self.assertRaises(ValueError):
            validate(results)


if __name__ == "__main__":
    unittest.main()
