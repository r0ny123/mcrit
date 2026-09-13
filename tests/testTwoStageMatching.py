"""Tests for the two-stage (shortlist) 1-vs-N matching path and the function range index."""

import json
import logging
import os
from unittest import TestCase, main

import numpy as np
import pytest
from smda.common.SmdaReport import SmdaReport

from mcrit.config.McritConfig import McritConfig
from mcrit.config.MinHashConfig import MinHashConfig
from mcrit.config.QueueConfig import QueueConfig
from mcrit.config.ShinglerConfig import ShinglerConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.matchers.MatcherSample import MatcherSample
from mcrit.queue.QueueFactory import QueueFactory
from mcrit.storage.StorageFactory import StorageFactory

from .context import getTestMongoServerAndPort

LOG = logging.getLogger(__name__)
logging.disable(logging.CRITICAL)

THIS_FILE_PATH = str(os.path.abspath(__file__))
PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
REPORTS = ["example_report.smda", "example_report_2.smda", "example_report_3.smda", "library_report.smda"]

DB_NAME = "test_two_stage_matching"


def buildConfig(shortlist_size=0, band_df_cutoff=0):
    server, port = getTestMongoServerAndPort()
    config = McritConfig()
    config.STORAGE_CONFIG = StorageConfig(
        STORAGE_METHOD=StorageFactory.STORAGE_METHOD_MONGODB,
        STORAGE_SERVER=server,
        STORAGE_PORT=port,
        STORAGE_MONGODB_DBNAME=DB_NAME,
        STORAGE_BAND_DF_CUTOFF=band_df_cutoff,
    )
    config.MINHASH_CONFIG = MinHashConfig()
    config.MINHASH_CONFIG.MINHASH_MATCHING_SHORTLIST_SIZE = shortlist_size
    config.SHINGLER_CONFIG = ShinglerConfig()
    config.QUEUE_CONFIG = QueueConfig()
    config.QUEUE_CONFIG.QUEUE_MONGODB_DBNAME = DB_NAME + "_queue"
    # these tests drive Worker methods directly, so the queue only has to hand one back
    config.QUEUE_CONFIG.QUEUE_METHOD = QueueFactory.QUEUE_METHOD_FAKE
    return config


def loadReport(name):
    with open(os.sep.join([PROJECT_ROOT, "tests", name])) as handle:
        return SmdaReport.fromDict(json.load(handle))


@pytest.mark.mongo
class TwoStageMatchingTest(TestCase):
    @classmethod
    def setUpClass(cls):
        config = buildConfig()
        index = MinHashIndex(config=config)
        index._storage.clearStorage()
        cls.sample_ids = []
        for name in REPORTS:
            entry = index._storage.addSmdaReport(loadReport(name))
            if entry is not None:
                index.queue._worker.updateMinHashesForSample(entry.sample_id)
                cls.sample_ids.append(entry.sample_id)
        cls.query_sample_id = cls.sample_ids[0]

    def _match(self, shortlist_size=0, band_df_cutoff=0):
        index = MinHashIndex(config=buildConfig(shortlist_size, band_df_cutoff))
        return MatcherSample(index.queue._worker).getMatchesForSample(self.query_sample_id)

    @staticmethod
    def _sampleIds(report):
        return {entry["sample_id"] for entry in report["matches"]["samples"]}

    @staticmethod
    def _functionMatches(report):
        """(query function id, matched sample id) -> score, flattened out of the report."""
        flattened = {}
        for entry in report["matches"]["functions"]:
            for match in entry["matches"]:
                flattened[(entry["fid"], match[1])] = match[3]
        return flattened

    def testFunctionRangeIndexIsBuiltAndComplete(self):
        storage = MinHashIndex(config=buildConfig())._storage
        num_samples = storage.rebuildFunctionRangeIndex()
        self.assertEqual(num_samples, len(self.sample_ids))
        self.assertTrue(storage.isFunctionRangeIndexComplete())

    def testFunctionIdsResolveToTheirOwnSample(self):
        """Every function must map back to the sample that actually holds it."""
        storage = MinHashIndex(config=buildConfig())._storage
        storage.rebuildFunctionRangeIndex()
        for sample_id in self.sample_ids:
            function_ids = [entry.function_id for entry in storage.getFunctionsBySampleId(sample_id)]
            if not function_ids:
                continue
            resolved = storage.getSampleIdsForFunctionIdArray(np.array(function_ids, dtype=np.int64))
            self.assertTrue(bool(np.all(resolved == sample_id)), "sample %d resolved to %s" % (sample_id, set(resolved.tolist())))

    def testUnknownFunctionIdResolvesToMinusOne(self):
        storage = MinHashIndex(config=buildConfig())._storage
        storage.rebuildFunctionRangeIndex()
        resolved = storage.getSampleIdsForFunctionIdArray(np.array([10**9], dtype=np.int64))
        self.assertEqual(int(resolved[0]), -1)

    def testShortlistDisabledByDefaultLeavesResultsUnchanged(self):
        """The knob defaulting to 0 must mean 'no shortlist', bit for bit."""
        self.assertEqual(MinHashConfig().MINHASH_MATCHING_SHORTLIST_SIZE, 0)
        self.assertEqual(StorageConfig().STORAGE_BAND_DF_CUTOFF, 0)
        first = self._match()
        second = self._match()
        self.assertEqual(self._sampleIds(first), self._sampleIds(second))
        self.assertEqual(self._functionMatches(first), self._functionMatches(second))

    def testShortlistBoundsTheNumberOfMatchedSamples(self):
        storage = MinHashIndex(config=buildConfig())._storage
        storage.rebuildFunctionRangeIndex()
        reference = self._match()
        shortlisted = self._match(shortlist_size=1)
        # the query's own sample is always kept, so a shortlist of 1 admits at most 2
        self.assertLessEqual(len(self._sampleIds(shortlisted)), 2)
        self.assertLessEqual(len(self._sampleIds(shortlisted)), len(self._sampleIds(reference)))

    def testShortlistKeepsScoresExactForTheSamplesItKeeps(self):
        """Restricting *which* samples are matched must not change *how* they are matched."""
        storage = MinHashIndex(config=buildConfig())._storage
        storage.rebuildFunctionRangeIndex()
        reference = self._functionMatches(self._match())
        shortlisted = self._functionMatches(self._match(shortlist_size=2))
        self.assertTrue(shortlisted, "shortlisted run produced no function matches")
        for key, score in shortlisted.items():
            self.assertIn(key, reference)
            self.assertEqual(score, reference[key], "score changed for %s" % (key,))

    def testShortlistFallsBackWhenRangeIndexIsIncomplete(self):
        """Without a trustworthy range index the matcher must match the whole corpus, not guess."""
        storage = MinHashIndex(config=buildConfig())._storage
        storage.rebuildFunctionRangeIndex()
        storage._setFunctionRangeIndexComplete(False)
        try:
            fallback = self._match(shortlist_size=1)
            self.assertEqual(self._sampleIds(fallback), self._sampleIds(self._match()))
        finally:
            storage._setFunctionRangeIndexComplete(True)

    def testPicHashCutoffDropsOnlyOverCommonHashes(self):
        """A cutoff above every holder count must change nothing; a cutoff of 1 must bite."""
        storage = MinHashIndex(config=buildConfig())._storage
        function_ids = [entry.function_id for entry in storage.getFunctionsBySampleId(self.query_sample_id)]
        unrestricted = storage.getPicHashMatchesByFunctionIds(function_ids)

        generous = buildConfig()
        generous.MINHASH_CONFIG.MINHASH_PICHASH_MAX_MATCHES = 10**9
        generous_matches = MinHashIndex(config=generous)._storage.getPicHashMatchesByFunctionIds(function_ids)
        self.assertEqual(generous_matches, unrestricted)

        strict = buildConfig()
        strict.MINHASH_CONFIG.MINHASH_PICHASH_MAX_MATCHES = 1
        strict_matches = MinHashIndex(config=strict)._storage.getPicHashMatchesByFunctionIds(function_ids)
        # every hash is still reported as a key; what the cutoff removes is the holders behind it
        self.assertEqual(set(strict_matches), set(unrestricted))
        for pichash, holders in strict_matches.items():
            self.assertLessEqual(len(holders), len(unrestricted[pichash]))
        self.assertLessEqual(
            sum(len(holders) for holders in strict_matches.values()),
            sum(len(holders) for holders in unrestricted.values()),
        )

    def testPicHashCutoffDefaultsToOff(self):
        self.assertEqual(MinHashConfig().MINHASH_PICHASH_MAX_MATCHES, 0)

    def testFreshDatabaseVouchesForBothIndexes(self):
        """A database with no functions maintains both indexes from its first write.

        Without this a new instance would keep both perfectly up to date and still take the
        fallback path forever, because nothing had ever vouched for them.
        """
        config = buildConfig()
        config.STORAGE_CONFIG.STORAGE_MONGODB_DBNAME = DB_NAME + "_fresh"
        storage = MinHashIndex(config=config)._storage
        storage.clearStorage()
        self.assertTrue(storage.isFunctionRangeIndexComplete())
        self.assertTrue(storage.isBandDfIndexComplete())

    def testBandDfIsMaintainedOnInsert(self):
        """df must equal the posting list it counts, or the cutoff hides lists that should match."""
        storage = MinHashIndex(config=buildConfig())._storage
        for band_number in range(storage._storage_config.STORAGE_NUM_BANDS):
            collection = storage._getDb()["band_%d" % band_number]
            mismatching = collection.count_documents({"$expr": {"$ne": ["$df", {"$size": {"$ifNull": ["$function_ids", []]}}]}})
            self.assertEqual(mismatching, 0, "band_%d has %d documents whose df disagrees with its posting list" % (band_number, mismatching))

    def testBandDfCutoffKeepsMatchesItDoesNotFilter(self):
        """A cutoff above every posting list must leave results identical."""
        reference = self._match()
        generous = self._match(band_df_cutoff=10**9)
        self.assertEqual(self._sampleIds(reference), self._sampleIds(generous))
        self.assertEqual(self._functionMatches(reference), self._functionMatches(generous))


if __name__ == "__main__":
    main()
