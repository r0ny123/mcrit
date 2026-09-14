#!/usr/bin/python3

import json
import logging
import os
import unittest

from smda.common.SmdaReport import SmdaReport

from mcrit.config.McritConfig import McritConfig
from mcrit.config.MinHashConfig import MinHashConfig
from mcrit.config.QueueConfig import QueueConfig
from mcrit.config.ShinglerConfig import ShinglerConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.queue.QueueFactory import QueueFactory
from mcrit.storage.StorageFactory import StorageFactory

from .context import getTestMongoServerAndPort

logging.disable(logging.CRITICAL)

THIS_FILE_PATH = str(os.path.abspath(__file__))
PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
EXAMPLE_REPORT = os.sep.join([PROJECT_ROOT, "tests", "example_report.smda"])
EXAMPLE_REPORT_2 = os.sep.join([PROJECT_ROOT, "tests", "example_report_2.smda"])


class BandBucketingTest(unittest.TestCase):
    """A band posting list must be able to outgrow one MongoDB document.

    A posting list is a `function_ids` array inside a single document and MongoDB caps a document
    at 16 MB. Measured on a 7,244-sample real corpus the largest band document held 18,968
    postings in 197,606 bytes, so roughly 1.6M fit - 84.9x the corpus, putting the wall near
    615,000 samples. The $push does not degrade there, it raises, and indexing stops. Sharding
    cannot move it, because a document cannot span shards.

    What matters for correctness is that splitting a posting list changes nothing a caller sees.
    """

    @classmethod
    def setUpClass(cls):
        with open(EXAMPLE_REPORT, "r") as handle:
            cls.report = SmdaReport.fromDict(json.load(handle))
        with open(EXAMPLE_REPORT_2, "r") as handle:
            cls.report_2 = SmdaReport.fromDict(json.load(handle))

    def _index(self, bucket_size, db_suffix):
        # MongoDB-backed on purpose: bucketing exists because of a MongoDB document limit, so a
        # MemoryStorage run would exercise none of it.
        server, port = getTestMongoServerAndPort()
        db_name = "test_band_bucketing_" + db_suffix
        index_config = McritConfig()
        index_config.STORAGE_CONFIG = StorageConfig(
            STORAGE_METHOD=StorageFactory.STORAGE_METHOD_MONGODB,
            STORAGE_SERVER=server,
            STORAGE_PORT=port,
            STORAGE_MONGODB_DBNAME=db_name,
            STORAGE_BAND_BUCKET_SIZE=bucket_size,
        )
        index_config.MINHASH_CONFIG = MinHashConfig()
        index_config.SHINGLER_CONFIG = ShinglerConfig()
        index_config.QUEUE_CONFIG = QueueConfig()
        index_config.QUEUE_CONFIG.QUEUE_MONGODB_DBNAME = db_name + "_queue"
        index_config.QUEUE_CONFIG.QUEUE_METHOD = QueueFactory.QUEUE_METHOD_FAKE
        index = MinHashIndex(config=index_config)
        index._storage.clearStorage()
        return index

    @staticmethod
    def _fill(index, reports):
        for report in reports:
            index.addReport(report)

    def _bandDocuments(self, index):
        return index._storage._getDb()["band_0"].count_documents({})

    def testPostingListSplitsAcrossDocuments(self):
        """With a bucket smaller than the corpus the list spans several documents."""
        index = self._index(bucket_size=2, db_suffix="split")
        self._fill(index, [self.report, self.report_2])
        storage = index._storage
        collection = storage._getDb()["band_0"]
        spilled = collection.count_documents({"bucket": {"$gt": 0}})
        self.assertGreater(spilled, 0, "a bucket size of 2 must force a spill on this corpus")
        # every bucket obeys the cap
        for document in collection.find({}, {"function_ids": 1, "_id": 0}):
            self.assertLessEqual(len(document.get("function_ids", [])), 2)

    def testTotalDfIsKeptOnBucketZero(self):
        """df on bucket 0 is the total across buckets - the cutoff reads it and nothing else."""
        index = self._index(bucket_size=2, db_suffix="df")
        self._fill(index, [self.report, self.report_2])
        collection = index._storage._getDb()["band_0"]
        for row in collection.aggregate(
            [
                {"$project": {"band_hash": 1, "bucket": {"$ifNull": ["$bucket", 0]}, "n": {"$size": {"$ifNull": ["$function_ids", []]}}}},
                {"$group": {"_id": "$band_hash", "total": {"$sum": "$n"}}},
            ]
        ):
            head = collection.find_one({"band_hash": row["_id"], "bucket": 0}, {"df": 1, "_id": 0})
            self.assertIsNotNone(head, "every hash must have a bucket 0 carrying its counters")
            self.assertEqual(head["df"], row["total"], "df on bucket 0 must be the total across buckets")

    def testMatchingIsUnchangedByBucketing(self):
        """The point of the whole change: results must be identical, bucketed or not."""
        plain = self._index(bucket_size=0, db_suffix="plain")
        self._fill(plain, [self.report, self.report_2])
        bucketed = self._index(bucket_size=2, db_suffix="bucketed")
        self._fill(bucketed, [self.report, self.report_2])

        sample_id = sorted(sample.sample_id for sample in plain._storage.getSamples(start_index=0, limit=0))[0]
        plain_job = plain.getMatchesForSample(sample_id)
        bucketed_job = bucketed.getMatchesForSample(sample_id)

        plain_matches = plain_job["matches"]["samples"] if "matches" in plain_job else plain_job
        bucketed_matches = bucketed_job["matches"]["samples"] if "matches" in bucketed_job else bucketed_job
        self.assertEqual(
            json.dumps(plain_matches, sort_keys=True),
            json.dumps(bucketed_matches, sort_keys=True),
            "bucketing must not change a single reported match",
        )

    def testCandidatesAreUnchangedByBucketing(self):
        """Lower level than the report: the candidate sets themselves must agree."""
        plain = self._index(bucket_size=0, db_suffix="cand_plain")
        self._fill(plain, [self.report, self.report_2])
        bucketed = self._index(bucket_size=2, db_suffix="cand_bucketed")
        self._fill(bucketed, [self.report, self.report_2])

        function_entries = plain._storage.getFunctionsBySampleId(
            sorted(sample.sample_id for sample in plain._storage.getSamples(start_index=0, limit=0))[0]
        )
        minhashes = {entry.function_id: entry.getMinHash() for entry in function_entries if entry.minhash}
        self.assertTrue(minhashes, "the fixture must produce at least one hashed function")
        plain_candidates = plain._storage.getCandidatesForMinHashes(minhashes)
        bucketed_candidates = bucketed._storage.getCandidatesForMinHashes(minhashes)
        self.assertEqual(
            {key: sorted(value) for key, value in plain_candidates.items()},
            {key: sorted(value) for key, value in bucketed_candidates.items()},
            "a split posting list must yield the same candidates as an unsplit one",
        )

    def testDeletionKeepsBookkeepingConsistent(self):
        """A pull can empty a bucket anywhere in the chain; the counters must still describe reality."""
        index = self._index(bucket_size=2, db_suffix="delete")
        self._fill(index, [self.report, self.report_2])
        storage = index._storage
        sample_ids = sorted(sample.sample_id for sample in storage.getSamples(start_index=0, limit=0))
        storage.deleteSample(sample_ids[0])
        collection = storage._getDb()["band_0"]
        for row in collection.aggregate(
            [
                {"$project": {"band_hash": 1, "bucket": {"$ifNull": ["$bucket", 0]}, "n": {"$size": {"$ifNull": ["$function_ids", []]}}}},
                {"$group": {"_id": "$band_hash", "total": {"$sum": "$n"}}},
            ]
        ):
            head = collection.find_one({"band_hash": row["_id"], "bucket": 0}, {"df": 1, "_id": 0})
            if head is not None:
                self.assertEqual(head["df"], row["total"], "df must match the postings that survived the deletion")


if __name__ == "__main__":
    unittest.main()
