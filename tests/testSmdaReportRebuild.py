import json
import os
import time
import unittest
from unittest.mock import MagicMock, patch

import falcon
import falcon.testing
from smda.common.SmdaReport import SmdaReport

from mcrit.client.McritClient import McritClient
from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.server.SampleResource import SampleResource
from mcrit.storage.RebuiltSmdaReport import RebuiltSmdaReport
from mcrit.storage.SampleEntry import SampleEntry

from .context import config as memory_config

EXAMPLE_REPORT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "example_report.smda")


class SampleEntryRebuildsTheReport(unittest.TestCase):
    """#94: the extras plus the sample entry plus the functions give the report back, while
    the entry itself never carries the extras"""

    def _report(self):
        with open(EXAMPLE_REPORT) as fjson:
            report = SmdaReport.fromDict(json.load(fjson))
        assert report is not None
        # data references are keyed by integer addresses: the one shape MongoDB refuses as keys
        report.data_refs_from = {4096: [4200, 4300]}
        report.data_refs_to = {4200: [4096]}
        return report

    def test_the_report_round_trips_through_entry_and_extras(self):
        report = self._report()
        entry = SampleEntry(report, sample_id=1, family_id=1)
        extras = SampleEntry.smdaExtrasOf(report)
        self.assertNotIn("xcfg", extras)
        self.assertEqual({"4096": [4200, 4300]}, extras["xdata_refs_from"])
        self.assertNotIn("family", extras.get("metadata", {}))
        self.assertNotIn("smda_extras", entry.toDict())
        self.assertFalse(hasattr(entry, "smda_extras"))
        xcfg = {int(offset): function.toDict() for offset, function in report.xcfg.items()}
        again = SampleEntry.fromDict(json.loads(json.dumps(entry.toDict())))
        rebuilt = SmdaReport.fromDict(again.toSmdaReportDict(xcfg, json.loads(json.dumps(extras))))
        assert rebuilt is not None
        self.assertEqual(report.toDict(), rebuilt.toDict())

    def test_the_analysed_buffer_is_neither_kept_nor_rebuilt(self):
        # a report made with smda's STORE_BUFFER carries the binary itself, which only
        # STORAGE_KEEP_/STORAGE_SERVE_SUBMITTED_BINARIES may keep and hand out (#95)
        report = self._report()
        report.buffer = b"\x55\x8b\xec" + b"submitted sample bytes" * 64
        packed = report.toDict()["buffer"]
        extras = SampleEntry.smdaExtrasOf(report)
        self.assertNotIn("buffer", extras)
        # nor do extras stored before the buffer was left out hand one back
        entry = SampleEntry(report, sample_id=1, family_id=1)
        for stored in (extras, dict(extras, buffer=packed)):
            rebuilt = SmdaReport.fromDict(entry.toSmdaReportDict({}, json.loads(json.dumps(stored))))
            assert rebuilt is not None
            self.assertIsNone(rebuilt.buffer)
            self.assertNotIn("buffer", rebuilt.toDict())

    def test_without_extras_the_report_still_rebuilds(self):
        report = self._report()
        entry = SampleEntry(report, sample_id=1, family_id=1)
        rebuilt = SmdaReport.fromDict(entry.toSmdaReportDict({}, None))
        assert rebuilt is not None
        self.assertEqual(report.sha256, rebuilt.sha256)
        self.assertEqual(report.family, rebuilt.family)
        self.assertEqual(0, len(rebuilt.xcfg))


class TheExtrasStayOffTheWire(unittest.TestCase):
    """#94 review: job results and exports carry SampleEntry.toDict(), never the extras"""

    def test_job_sample_info_and_exports_carry_no_extras(self):
        report = SampleEntryRebuildsTheReport()._report()
        index = MinHashIndex(config=memory_config)
        index.getStorage().clearStorage()
        added = index.addReport(report, calculate_hashes=False)
        sample_id = added["sample_info"]["sample_id"]
        self.assertIsNotNone(index.getStorage().getSmdaExtras(sample_id))
        again = index.addReport(report, calculate_hashes=False)
        export = index.getExportData([sample_id])
        for payload in (added["sample_info"], again["sample_info"], export["sample_entries"]):
            self.assertNotIn("smda_extras", json.dumps(payload))
            self.assertNotIn("xdata_refs_from", json.dumps(payload))
        resp = falcon.Response()
        SampleResource(index).on_get_collection(falcon.Request(falcon.testing.create_environ(path="/samples")), resp)
        assert resp.data is not None
        self.assertIn(str(sample_id), json.loads(resp.data)["data"])
        self.assertNotIn("xdata_refs_from", resp.data.decode() if isinstance(resp.data, bytes) else resp.data)

    def test_a_submitted_buffer_is_not_served_by_the_smda_route(self):
        report = SampleEntryRebuildsTheReport()._report()
        report.buffer = b"\x55\x8b\xec" + b"submitted sample bytes" * 64
        index = MinHashIndex(config=memory_config)
        index.getStorage().clearStorage()
        sample_id = index.addReport(report, calculate_hashes=False)["sample_info"]["sample_id"]
        self.assertNotIn("buffer", index.getStorage().getSmdaExtras(sample_id) or {})
        resp = falcon.Response()
        SampleResource(index).on_get_smda_report(falcon.Request(falcon.testing.create_environ(path=f"/samples/{sample_id}/smda")), resp, sample_id)
        assert resp.data is not None
        data = json.loads(resp.data)["data"]
        self.assertEqual(report.sha256, data["smda_report"]["sha256"])
        self.assertNotIn("buffer", data["smda_report"])


class SmdaReportRouteAndClient(unittest.TestCase):
    def _rebuilt(self, **kwargs):
        with open(EXAMPLE_REPORT) as fjson:
            report = SmdaReport.fromDict(json.load(fjson))
        assert report is not None
        return RebuiltSmdaReport(report, **kwargs)

    def test_the_route_serves_the_rebuilt_report_and_its_completeness(self):
        rebuilt = self._rebuilt(extras_missing=True, num_functions_without_disassembly=3)
        index = MagicMock()
        index.isSampleId.return_value = True
        index.getSmdaReportForSample.return_value = rebuilt
        resp = falcon.Response()
        SampleResource(index).on_get_smda_report(falcon.Request(falcon.testing.create_environ(path="/samples/1/smda")), resp, 1)
        assert resp.data is not None
        data = json.loads(resp.data)["data"]
        self.assertEqual(rebuilt.smda_report.sha256, data["smda_report"]["sha256"])
        self.assertFalse(data["complete"])
        self.assertEqual(["extras_missing", "disassembly_missing"], data["incomplete_reasons"])
        self.assertEqual(3, data["num_functions_without_disassembly"])
        index.isSampleId.return_value = False
        resp = falcon.Response()
        SampleResource(index).on_get_smda_report(falcon.Request(falcon.testing.create_environ(path="/samples/1/smda")), resp, 1)
        self.assertEqual(falcon.HTTP_404, resp.status)

    def test_a_request_during_a_rebuild_answers_503_at_once(self):
        # a rebuild holds its request thread for seconds on a large sample: a request arriving meanwhile
        # does not queue behind it, and the slot is free again after the rebuild, failed or not
        rebuilt = self._rebuilt()
        index = MagicMock()
        index.isSampleId.return_value = True
        resource = SampleResource(index)
        during = falcon.Response()

        waited = []

        def rebuild_while_another_request_arrives(sample_id):
            started = time.monotonic()
            resource.on_get_smda_report(falcon.Request(falcon.testing.create_environ(path="/samples/2/smda")), during, 2)
            waited.append(time.monotonic() - started)
            return rebuilt

        index.getSmdaReportForSample.side_effect = rebuild_while_another_request_arrives
        resp = falcon.Response()
        resource.on_get_smda_report(falcon.Request(falcon.testing.create_environ(path="/samples/1/smda")), resp, 1)
        self.assertEqual(falcon.HTTP_200, resp.status)
        self.assertEqual(falcon.HTTP_503, during.status)
        self.assertLess(waited[0], 0.5)
        self.assertEqual(str(SampleResource.SMDA_REBUILD_RETRY_AFTER), during.get_header("Retry-After"))
        self.assertEqual(1, index.getSmdaReportForSample.call_count)
        index.getSmdaReportForSample.side_effect = RuntimeError("storage unavailable")
        with self.assertRaises(RuntimeError):
            resource.on_get_smda_report(falcon.Request(falcon.testing.create_environ(path="/samples/1/smda")), falcon.Response(), 1)
        index.getSmdaReportForSample.side_effect = None
        index.getSmdaReportForSample.return_value = rebuilt
        resp = falcon.Response()
        resource.on_get_smda_report(falcon.Request(falcon.testing.create_environ(path="/samples/1/smda")), resp, 1)
        self.assertEqual(falcon.HTTP_200, resp.status)
        assert resp.data is not None
        self.assertEqual(rebuilt.smda_report.sha256, json.loads(resp.data)["data"]["smda_report"]["sha256"])

    def test_the_client_answers_a_rebuilt_report(self):
        for kwargs in ({}, {"extras_missing": True}, {"num_functions_without_disassembly": 2}):
            sent = self._rebuilt(**kwargs)
            response = MagicMock(status_code=200)
            response.json.return_value = {"status": "successful", "data": json.loads(json.dumps(sent.toDict()))}
            client = McritClient("http://mcrit.test")
            with patch("mcrit.client.McritClient.requests.get", return_value=response):
                received = client.getSmdaReportForSample(1)
            assert received is not None
            self.assertEqual(sent.smda_report.sha256, received.smda_report.sha256)
            self.assertEqual(len(sent.smda_report.xcfg), len(received.smda_report.xcfg))
            self.assertEqual(sent.complete, received.complete)
            self.assertEqual(sent.incomplete_reasons, received.incomplete_reasons)
            self.assertEqual(sent.num_functions_without_disassembly, received.num_functions_without_disassembly)

    def test_the_client_retries_while_the_server_rebuilds_another_report(self):
        sent = self._rebuilt()
        busy = MagicMock(status_code=503, headers={"Retry-After": "5"})
        busy.json.return_value = {"status": "failed", "data": {"message": "Another SMDA report is being rebuilt, retry shortly."}}
        done = MagicMock(status_code=200, headers={})
        done.json.return_value = {"status": "successful", "data": json.loads(json.dumps(sent.toDict()))}
        client = McritClient("http://mcrit.test")
        # the client module's own `requests` and `time` names are replaced, not requests.get and time.sleep
        # themselves: those are shared, and a thread left running by another test would land in the mocks
        with patch("mcrit.client.McritClient.requests") as fake_requests, patch("mcrit.client.McritClient.time") as fake_time:
            fake_requests.get.side_effect = [busy, done]
            received = client.getSmdaReportForSample(1)
        assert received is not None
        self.assertEqual(sent.smda_report.sha256, received.smda_report.sha256)
        self.assertEqual(2, fake_requests.get.call_count)
        fake_time.sleep.assert_called_once_with(5.0)
        # a server that stays busy is asked SMDA_REBUILD_ATTEMPTS times, then answered like any other failure
        with patch("mcrit.client.McritClient.requests") as fake_requests, patch("mcrit.client.McritClient.time"):
            fake_requests.get.return_value = busy
            self.assertIsNone(client.getSmdaReportForSample(1))
        self.assertEqual(McritClient.SMDA_REBUILD_ATTEMPTS, fake_requests.get.call_count)


if __name__ == "__main__":
    unittest.main()
