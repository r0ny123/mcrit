"""MINHASH_MATCHING_SHORTLIST_SIZE and STORAGE_BAND_DF_CUTOFF per matching job, not only per deployment (#217)."""

import json
import unittest
from copy import deepcopy
from unittest.mock import MagicMock, patch

import falcon
import falcon.testing
from smda.common.SmdaReport import SmdaReport

from mcrit.client.McritClient import McritClient
from mcrit.config.MinHashConfig import MinHashConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.matchers.MatcherSample import MatcherSample
from mcrit.matchers.MatcherVs import MatcherVs
from mcrit.matchers.MatcherVsGroup import MatcherVsGroup
from mcrit.server.MatchResource import MatchResource
from mcrit.server.utils import getMatchingParams
from mcrit.Worker import Worker

from .context import config


def configured(shortlist_size=0, band_df_cutoff=0):
    mcrit_config = deepcopy(config)
    # new objects, not edits: McritConfig holds its sub-configs as class attributes shared by every copy
    mcrit_config.MINHASH_CONFIG = MinHashConfig(MINHASH_MATCHING_SHORTLIST_SIZE=shortlist_size)
    mcrit_config.STORAGE_CONFIG = StorageConfig(STORAGE_METHOD=config.STORAGE_CONFIG.STORAGE_METHOD, STORAGE_BAND_DF_CUTOFF=band_df_cutoff)
    return mcrit_config


class MatchingParamsTest(unittest.TestCase):
    def test_both_knobs_are_read_from_the_request(self):
        self.assertEqual({"shortlist_size": 25, "band_df_cutoff": 200}, getMatchingParams({"shortlist_size": "25", "band_df_cutoff": "200"}))

    def test_negative_values_mean_off_and_garbage_is_ignored(self):
        self.assertEqual({"shortlist_size": 0}, getMatchingParams({"shortlist_size": "-3", "band_df_cutoff": "many"}))

    def test_the_server_fills_in_what_the_request_leaves_out(self):
        parameters = getMatchingParams({"shortlist_size": "5"}, configured(shortlist_size=100, band_df_cutoff=200))
        self.assertEqual({"shortlist_size": 5, "band_df_cutoff": 200}, parameters)
        self.assertEqual({"shortlist_size": 100, "band_df_cutoff": 200}, getMatchingParams({}, configured(shortlist_size=100, band_df_cutoff=200)))


class JobCacheTest(unittest.TestCase):
    """A job is reused for a request with the same arguments; the knobs have to be among them."""

    def setUp(self):
        self.index = MinHashIndex(config=configured())
        report = SmdaReport.fromFile("tests/example_report.smda")
        self.sample_id = self.index._storage.addSmdaReport(report).sample_id

    def test_different_knobs_are_different_jobs(self):
        first = self.index.getMatchesForSample(self.sample_id, shortlist_size=0, band_df_cutoff=0)
        self.assertEqual(first, self.index.getMatchesForSample(self.sample_id, shortlist_size=0, band_df_cutoff=0))
        self.assertNotEqual(first, self.index.getMatchesForSample(self.sample_id, shortlist_size=10, band_df_cutoff=0))
        self.assertNotEqual(first, self.index.getMatchesForSample(self.sample_id, shortlist_size=0, band_df_cutoff=10))

    def test_a_changed_configuration_is_a_different_job_through_the_api(self):
        resource_before = MatchResource(self.index)
        app = falcon.App()
        app.add_route("/matches/sample/{sample_id:int}", resource_before, suffix="sample")
        before = falcon.testing.TestClient(app).simulate_get(f"/matches/sample/{self.sample_id}").json["data"]
        # the same corpus, served by a deployment configured with a shortlist
        self.index.config = configured(shortlist_size=10)
        after = falcon.testing.TestClient(app).simulate_get(f"/matches/sample/{self.sample_id}").json["data"]
        self.assertNotEqual(before, after)
        # each job records the settings it ran with, whether or not the request named them
        recorded = [json.loads(self.index.getJobData(job_id)["payload"]["params"]) for job_id in (before, after)]
        self.assertEqual([(0, 0), (10, 0)], [(params["shortlist_size"], params["band_df_cutoff"]) for params in recorded])


class MemoryStorageBandDfCutoffTest(unittest.TestCase):
    def test_the_cutoff_skips_common_band_hashes_per_lookup_and_by_configuration(self):
        index = MinHashIndex(config=configured())
        worker = index.queue._worker
        sample_ids = [
            index._storage.addSmdaReport(SmdaReport.fromFile(f"tests/{name}")).sample_id for name in ("example_report.smda", "example_report_2.smda", "example_report_3.smda")
        ]
        for sample_id in sample_ids:
            worker.updateMinHashesForSample(sample_id)
        bits = index.config.MINHASH_CONFIG.MINHASH_SIGNATURE_BITS
        minhashes = {entry.function_id: entry.getMinHash(minhash_bits=bits) for entry in index._storage.getFunctionsBySampleId(sample_ids[0]) if entry.minhash}
        unrestricted = index._storage.getCandidatesForMinHashes(minhashes, band_matches_required=1)
        restricted = index._storage.getCandidatesForMinHashes(minhashes, band_matches_required=1, band_df_cutoff=1)
        self.assertLess(sum(map(len, restricted.values())), sum(map(len, unrestricted.values())))
        index._storage._storage_config = configured(band_df_cutoff=1).STORAGE_CONFIG
        self.assertEqual(restricted, index._storage.getCandidatesForMinHashes(minhashes, band_matches_required=1))
        self.assertEqual(unrestricted, index._storage.getCandidatesForMinHashes(minhashes, band_matches_required=1, band_df_cutoff=0))

    def test_a_posting_list_as_long_as_the_cutoff_is_kept(self):
        index = MinHashIndex(config=configured())
        worker = index.queue._worker
        sample_ids = [
            index._storage.addSmdaReport(SmdaReport.fromFile(f"tests/{name}")).sample_id for name in ("example_report.smda", "example_report_2.smda", "example_report_3.smda")
        ]
        for sample_id in sample_ids:
            worker.updateMinHashesForSample(sample_id)
        storage = index._storage
        bits = index.config.MINHASH_CONFIG.MINHASH_SIGNATURE_BITS
        minhashes = {entry.function_id: entry.getMinHash(minhash_bits=bits) for entry in storage.getFunctionsBySampleId(sample_ids[0]) if entry.minhash}

        def posting_lengths(minhash):
            return [len(storage._bands[band][band_hash]) for band, band_hash in storage.getBandHashesForMinHash(minhash).items() if band_hash in storage._bands[band]]

        assertCutoffKeepsListsOfItsLength(self, storage, minhashes, posting_lengths)


def assertCutoffKeepsListsOfItsLength(test, storage, minhashes, posting_lengths):
    """A band hash whose posting list is exactly as long as the cutoff is kept, one longer is skipped.

    Finds a query function for which skipping its longest posting lists changes the candidates, so
    that keeping or dropping the lists at the boundary shows in the result.
    """
    for function_id, minhash in minhashes.items():
        lengths = posting_lengths(minhash)
        if not lengths or max(lengths) < 2:
            continue
        longest = max(lengths)

        def candidates(cutoff):
            return storage.getCandidatesForMinHashes({function_id: minhash}, band_matches_required=1, band_df_cutoff=cutoff)[function_id]

        if candidates(longest - 1) != candidates(0):
            test.assertEqual(candidates(0), candidates(longest))
            return
    test.fail("no query function whose longest posting lists decide its candidates")


class ClientTest(unittest.TestCase):
    def test_the_client_sends_the_knobs_only_when_given(self):
        client = McritClient("http://mcrit.test")
        with patch("mcrit.client.McritClient.requests.get") as get:
            get.return_value.status_code = 200
            get.return_value.json.return_value = {"status": "successful", "data": "0123456789abcdef01234567"}
            client.requestMatchesForSample(7, shortlist_size=25, band_df_cutoff=200)
            self.assertEqual({"shortlist_size": 25, "band_df_cutoff": 200, "force_recalculation": False}, get.call_args.kwargs["params"])
            client.requestMatchesForSample(7)
            self.assertNotIn("shortlist_size", get.call_args.kwargs["params"])

    def test_the_route_hands_them_to_the_job(self):
        index = MagicMock()
        index.config = configured(shortlist_size=100)
        index.isSampleId.return_value = True
        app = falcon.App()
        app.add_route("/matches/sample/{sample_id:int}", MatchResource(index), suffix="sample")
        falcon.testing.TestClient(app).simulate_get("/matches/sample/7", query_string="band_df_cutoff=50")
        self.assertEqual((100, 50), (index.getMatchesForSample.call_args.kwargs["shortlist_size"], index.getMatchesForSample.call_args.kwargs["band_df_cutoff"]))


KNOBS = {"shortlist_size": 3, "band_df_cutoff": 4}


class ForwardingTest(unittest.TestCase):
    """Every matching path hands the knobs on to the matcher that applies them."""

    def test_worker_methods_hand_both_knobs_to_their_matcher(self):
        worker = Worker.__new__(Worker)
        cases = {
            "MatcherSample": lambda: worker.getMatchesForSample(1, **KNOBS),
            "MatcherQuery": lambda: worker.getMatchesForSmdaReport({}, **KNOBS),
            "MatcherQuery ": lambda: worker.getMatchesForMappedBinary(b"", 0x1000, **KNOBS),
            "MatcherQuery  ": lambda: worker.getMatchesForUnmappedBinary(b"", **KNOBS),
        }
        for matcher_name, call in cases.items():
            with self.subTest(matcher_name), patch(f"mcrit.Worker.{matcher_name.strip()}") as matcher, patch("mcrit.Worker.SmdaReport"), patch("mcrit.Worker.Disassembler"):
                call()
                self.assertEqual(KNOBS, {knob: matcher.call_args.kwargs[knob] for knob in KNOBS})

    def test_vs_matching_takes_the_cutoff_and_no_shortlist(self):
        worker = Worker.__new__(Worker)
        for matcher_name, call in {
            "MatcherVs": lambda: worker.getMatchesForSampleVs(1, 2, band_df_cutoff=4),
            "MatcherVsGroup": lambda: worker.getMatchesForSampleVsGroup(1, [2, 3], band_df_cutoff=4),
        }.items():
            with self.subTest(matcher_name), patch(f"mcrit.Worker.{matcher_name}") as matcher:
                call()
                self.assertEqual(4, matcher.call_args.kwargs["band_df_cutoff"])
                self.assertNotIn("shortlist_size", matcher.call_args.kwargs)

    def test_function_queries_hand_both_knobs_to_their_matcher(self):
        report = MagicMock(xcfg={0x1000: {}}, sha256="ab" * 32)
        with patch("mcrit.index.MinHashIndex.SmdaReport") as smda_report, patch("mcrit.index.MinHashIndex.MatcherQueryFunction") as matcher:
            smda_report.fromDict.return_value = report
            matcher.return_value.getMatchesForSmdaFunction.return_value = {"info": {"job": {}}}
            MinHashIndex.getMatchesForSmdaFunction(MagicMock(), report, **KNOBS)
        self.assertEqual(KNOBS, {knob: matcher.call_args.kwargs[knob] for knob in KNOBS})

    def test_group_only_cross_matching_leaves_the_shortlist_out(self):
        index = MagicMock()
        MinHashIndex.getMatchesCross(index, [1, 2], sample_group_only=True, **KNOBS)
        self.assertEqual({"band_df_cutoff": 4}, {knob: value for knob, value in index.getMatchesForSampleVsGroup.call_args.kwargs.items() if knob in KNOBS})
        MinHashIndex.getMatchesCross(index, [1, 2], **KNOBS)
        self.assertEqual(KNOBS, {knob: index.getMatchesForSample.call_args.kwargs[knob] for knob in KNOBS})

    def test_the_client_sends_them_on_every_matching_request(self):
        client = McritClient("http://mcrit.test")
        cases = {
            "requestMatchesForSmdaReport": ("post", lambda: client.requestMatchesForSmdaReport(MagicMock(), **KNOBS), KNOBS),
            "requestMatchesForMappedBinary": ("post", lambda: client.requestMatchesForMappedBinary(b"", 0x1000, disassemble_locally=False, **KNOBS), KNOBS),
            "requestMatchesForUnmappedBinary": ("post", lambda: client.requestMatchesForUnmappedBinary(b"", disassemble_locally=False, **KNOBS), KNOBS),
            "requestMatchesForSample": ("get", lambda: client.requestMatchesForSample(1, **KNOBS), KNOBS),
            "requestMatchesForSampleVs": ("get", lambda: client.requestMatchesForSampleVs(1, 2, band_df_cutoff=4), {"band_df_cutoff": 4}),
            "requestMatchesCross": ("get", lambda: client.requestMatchesCross([1, 2], **KNOBS), KNOBS),
            "getMatchesForSmdaFunction": ("post", lambda: client.getMatchesForSmdaFunction(MagicMock(), **KNOBS), KNOBS),
        }
        for name, (verb, call, expected) in cases.items():
            with self.subTest(name), patch(f"mcrit.client.McritClient.requests.{verb}") as request:
                request.return_value.status_code = 200
                request.return_value.json.return_value = {"status": "successful", "data": "0123456789abcdef01234567"}
                call()
                params = request.call_args.kwargs["params"]
                self.assertEqual(expected, {knob: params[knob] for knob in KNOBS if knob in params})


class VsShortlistTest(unittest.TestCase):
    """A match against named samples takes no shortlist: one ranked over the corpus could drop them."""

    def _app(self, index):
        app = falcon.App()
        resource = MatchResource(index)
        app.add_route("/matches/sample/{sample_id:int}/{sample_id_b:int}", resource, suffix="sample_vs")
        app.add_route("/matches/sample/cross/{sample_ids}", resource, suffix="sample_cross")
        return falcon.testing.TestClient(app)

    def test_the_vs_and_group_routes_leave_it_out(self):
        index = MagicMock()
        index.config = configured(shortlist_size=100, band_df_cutoff=200)
        index.isSampleId.return_value = True
        client = self._app(index)
        client.simulate_get("/matches/sample/1/2", query_string="shortlist_size=5")
        self.assertNotIn("shortlist_size", index.getMatchesForSampleVs.call_args.kwargs)
        self.assertEqual(200, index.getMatchesForSampleVs.call_args.kwargs["band_df_cutoff"])
        client.simulate_get("/matches/sample/cross/1,2", query_string="sample_group_only=true&shortlist_size=5")
        self.assertNotIn("shortlist_size", index.getMatchesCross.call_args.kwargs)
        client.simulate_get("/matches/sample/cross/1,2", query_string="shortlist_size=5")
        self.assertEqual(5, index.getMatchesCross.call_args.kwargs["shortlist_size"])

    def test_vs_matchers_ignore_a_configured_shortlist(self):
        index = MinHashIndex(config=configured(shortlist_size=1))
        worker = index.queue._worker
        self.assertEqual(1, MatcherSample(worker)._getShortlistSize())
        self.assertEqual(0, MatcherVs(worker)._getShortlistSize())
        self.assertEqual(0, MatcherVsGroup(worker)._getShortlistSize())
        self.assertEqual(0, MatcherVs(worker, shortlist_size=5)._getShortlistSize())


class ParameterRangeTest(unittest.TestCase):
    def test_values_mongodb_cannot_store_are_ignored(self):
        self.assertEqual({"shortlist_size": 2**63 - 1}, getMatchingParams({"shortlist_size": str(2**63 - 1), "band_df_cutoff": str(2**63)}))


if __name__ == "__main__":
    unittest.main()
