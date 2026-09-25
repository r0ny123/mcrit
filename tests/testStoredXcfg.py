"""Rebuilding SmdaFunctions from the disassembly MCRIT stores (the `xcfg` of a FunctionEntry),
for a function that was stored without it.

STORAGE_DROP_DISASSEMBLY, a blob over MongoDB's 16 MiB limit (#42), and an import of an export from
such an instance all leave a function whose xcfg reads back as `{}`. smda cannot rebuild a function
from that - current releases raise "serialized function is incomplete", releases before 4.4.5 a
KeyError - and every rebuild path used to hand it over anyway, so one such function failed the
whole batch it was in, on every retry. Each rebuild path is run here on the smda 1.5.12 example
report, once as stored and once with one function's disassembly gone.
"""

import json
import os
import unittest
from copy import deepcopy
from unittest.mock import patch

import pytest
from smda.common.SmdaReport import SmdaReport

from mcrit.config.McritConfig import McritConfig
from mcrit.config.MinHashConfig import MinHashConfig
from mcrit.config.ShinglerConfig import ShinglerConfig
from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.storage.FunctionEntry import missingXcfgFields, smdaFunctionFromXcfg
from mcrit.storage.MatchingResult import MatchingResult
from mcrit.storage.StorageFactory import StorageFactory

from .context import config
from .testStorage import buildMongoStorageConfig

TESTS_DIR = os.path.dirname(os.path.abspath(__file__))
EXAMPLE_REPORT = os.path.join(TESTS_DIR, "example_report.smda")


class SmdaFunctionFromXcfgTest(unittest.TestCase):
    def test_an_incomplete_xcfg_names_what_it_lacks(self):
        with open(EXAMPLE_REPORT) as handle:
            function_dict = deepcopy(next(iter(json.load(handle)["xcfg"].values())))
        del function_dict["inrefs"]
        del function_dict["metadata"]["tfidf"]
        self.assertEqual(["inrefs", "metadata.tfidf"], missingXcfgFields(function_dict))
        with self.assertRaisesRegex(ValueError, "lacks inrefs, metadata.tfidf"):
            smdaFunctionFromXcfg(function_dict)

    def test_no_disassembly_rebuilds_as_none(self):
        self.assertIsNone(smdaFunctionFromXcfg(None))
        self.assertIsNone(smdaFunctionFromXcfg({}))


class RebuildPathsTest(unittest.TestCase):
    """Every path that rebuilds functions from storage, on the smda 1.5.12 example report."""

    @classmethod
    def setUpClass(cls):
        with open(EXAMPLE_REPORT) as handle:
            cls.report = SmdaReport.fromDict(json.load(handle))

    def setUp(self):
        self.index = MinHashIndex(config=deepcopy(config))
        self.storage = self.index._storage
        self.storage.clearStorage()
        self.worker = self.index.queue._worker
        self.sample_entry = self.storage.addSmdaReport(self.report)
        self.function_entries = self.storage.getFunctionsBySampleId(self.sample_entry.sample_id)

    def _dropDisassemblyOfOneHashableFunction(self):
        hashable = self.storage.getUnhashedFunctions(None)
        self.assertGreater(len(hashable), 1)
        self.storage._functions[hashable[0].function_id].xcfg = {}
        return len(hashable)

    def test_the_older_xcfg_rebuilds_on_every_path(self):
        self.assertTrue(all(entry.toSmdaFunction() is not None for entry in self.function_entries))
        self.assertGreater(self.worker.updateMinHashes(None), 0)
        MatchingResult(self.sample_entry).clusterLinkHuntResult(self.function_entries, [])

    def test_minhashing_a_sample_skips_a_function_without_disassembly(self):
        num_hashable = self._dropDisassemblyOfOneHashableFunction()
        # updateMinHashesForSample asks for the sample's function ids, which MemoryStorage does not
        # filter by disassembly - MongoDbStorage filters neither selection
        with patch("mcrit.Worker.LOGGER") as logger:
            self.assertEqual(num_hashable - 1, self.worker.updateMinHashesForSample(self.sample_entry.sample_id))
        self.assertIn("no stored disassembly", logger.warning.call_args.args[0])

    def test_link_hunt_clustering_skips_a_function_without_disassembly(self):
        entries = deepcopy(self.function_entries)
        entries[0].xcfg = {}
        MatchingResult(self.sample_entry).clusterLinkHuntResult(entries, [])
        self.assertIsNone(entries[0].toSmdaFunction())


@pytest.mark.mongo
class MongoRebuildPathsTest(unittest.TestCase):
    def setUp(self):
        mongo_config = McritConfig()
        mongo_config.STORAGE_CONFIG = buildMongoStorageConfig("test_stored_xcfg_mcrit")
        mongo_config.MINHASH_CONFIG = MinHashConfig()
        mongo_config.SHINGLER_CONFIG = ShinglerConfig()
        self.storage = StorageFactory.getStorage(mongo_config)
        self.storage.clearStorage()
        self.sample_entry = self.storage.addSmdaReport(SmdaReport.fromFile(EXAMPLE_REPORT))
        self.worker = MinHashIndex(config=deepcopy(config)).queue._worker

    def tearDown(self):
        self.storage.clearStorage()

    def test_a_missing_blob_is_skipped_by_minhashing(self):
        db = self.storage._getDb()
        unhashed = self.storage.getUnhashedFunctions()
        db.xcfg.delete_one({"_id": unhashed[0].function_id})
        # the reader decodes the missing blob to {} and still selects the function
        unhashed = self.storage.getUnhashedFunctions()
        self.assertEqual(1, sum(1 for entry in unhashed if entry.xcfg == {}))
        self.assertEqual(len(unhashed) - 1, len(self.worker.calculateMinHashes(unhashed)))

    def test_pichash_recalculation_reads_older_xcfg_and_skips_an_empty_one(self):
        # the example report was written by smda 1.5.12, older than the escaper compatibility
        # threshold, so every one of its functions is recalculated from the stored xcfg
        db = self.storage._getDb()
        function_ids = [document["function_id"] for document in db.functions.find({}, {"function_id": 1, "_id": 0})]
        # an xcfg stored as {}: what importing an export of an instance with dropped disassembly writes
        db.xcfg.update_one({"_id": function_ids[0]}, {"$set": {"_xcfg": "{}"}})
        with patch("mcrit.storage.MongoDbStorage.LOGGER") as logger:
            self.storage.recalculateAllPicHashes()
        warnings = [call.args[0] for call in logger.warning.call_args_list]
        self.assertTrue(any(message.startswith("1 functions could not be updated") for message in warnings), warnings)


if __name__ == "__main__":
    unittest.main()
