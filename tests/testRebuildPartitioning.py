"""Tests for the partitioned offline index rebuilds.

Two levels, deliberately. The partition arithmetic - runs cut by a boundary, a single hash
filling a whole partition, an empty collection - is exercised against an in-memory stand-in for
the functions collection, so it runs in the database-less CI job and so the awkward cases can be
constructed rather than hoped for. The equality of the two rebuilds is then checked against a
real MongoDB on a real fixture corpus, at partition sizes small enough that the boundary cases
actually occur there too.
"""

import json
import logging
import os
from unittest import TestCase, main

import pytest
from smda.common.SmdaReport import SmdaReport

from mcrit.config.McritConfig import McritConfig
from mcrit.config.MinHashConfig import MinHashConfig
from mcrit.config.QueueConfig import QueueConfig
from mcrit.config.ShinglerConfig import ShinglerConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.queue.QueueFactory import QueueFactory
from mcrit.storage.MongoDbStorage import MongoDbStorage
from mcrit.storage.StorageFactory import StorageFactory

from .context import getTestMongoServerAndPort

LOG = logging.getLogger(__name__)
logging.disable(logging.CRITICAL)

THIS_FILE_PATH = str(os.path.abspath(__file__))
PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
REPORTS = ["example_report.smda", "example_report_2.smda", "example_report_3.smda", "library_report.smda"]

DB_NAME = "test_rebuild_partitioning"


class FakeCursor:
    """The slice of pymongo's cursor API `_iteratePicHashRuns` uses, over a sorted key list."""

    def __init__(self, keys, collection):
        self._keys = keys
        self._collection = collection
        self._limit = None

    def sort(self, field, direction):
        assert (field, direction) == ("_pichash", 1)
        return self

    def limit(self, amount):
        self._limit = amount
        return self

    def __iter__(self):
        keys = self._keys if self._limit is None else self._keys[: self._limit]
        # counted here rather than in find(), because the server stops at the limit too
        self._collection.num_keys_read += len(keys)
        return iter({"_pichash": key} for key in keys)


class FakeFunctions:
    """An in-memory functions collection holding nothing but pichashes.

    It answers exactly the two calls the run iterator makes - a bounded, sorted, keyset-bounded
    `find` and an equality `count_documents` - and it counts them, so a test can assert that the
    iteration reads each key once rather than merely producing the right answer.
    """

    def __init__(self, keys):
        self.keys = sorted(key for key in keys if key is not None)
        self.num_finds = 0
        self.num_keys_read = 0

    def find(self, query, projection):
        assert projection == {"_id": 0, "_pichash": 1}
        condition = query["_pichash"]
        if "$gte" in condition:
            selected = [key for key in self.keys if key >= condition["$gte"]]
        elif "$gt" in condition:
            selected = [key for key in self.keys if key > condition["$gt"]]
        else:
            assert condition == {"$ne": None}
            selected = list(self.keys)
        self.num_finds += 1
        return FakeCursor(selected, self)

    def count_documents(self, query):
        return sum(1 for key in self.keys if key == query["_pichash"])


class FakeDatabase:
    def __init__(self, functions):
        self.functions = functions


class StorageOverFakeDatabase(MongoDbStorage):
    """MongoDbStorage with its database replaced, so the run iterator can be driven alone.

    Subclassed rather than monkey-patched: the iterator is the part under test and it must be
    the real one, but everything it needs is `_getDb().functions`, and constructing the storage
    normally would demand a live MongoDB for a test about arithmetic.
    """

    def __init__(self, functions):
        self._functions = functions

    def _getDb(self):
        return FakeDatabase(self._functions)


def runsFor(keys, partition_size):
    """(runs, fake collection) for a corpus of pichashes, without touching a database."""
    functions = FakeFunctions(keys)
    storage = StorageOverFakeDatabase(functions)
    return list(storage._iteratePicHashRuns(partition_size)), functions


def expectedRuns(keys):
    counts = {}
    for key in keys:
        if key is not None:
            counts[key] = counts.get(key, 0) + 1
    return sorted(counts.items())


class PicHashRunIterationTest(TestCase):
    """The partition arithmetic, against a stand-in collection."""

    CORPORA = {
        "empty": [],
        "single": ["0x1"],
        "distinct": ["0x%x" % value for value in range(37)],
        "duplicated": ["0x%x" % (value % 5) for value in range(37)],
        # one hash far more common than any partition size the test uses
        "one_hot_hash": ["0xff"] * 25 + ["0x1", "0x2", "0x2", "0x3"],
        "all_one_hash": ["0xaa"] * 31,
    }

    def testEveryPartitionSizeYieldsTheSameCounts(self):
        """The partition size must be a performance knob and nothing else.

        It decides where a run gets cut, so if the boundary handling were wrong the counts would
        depend on it - which is precisely the failure that would be invisible at the sizes used
        in production, where a boundary lands inside a run only rarely.
        """
        for name, keys in self.CORPORA.items():
            expected = expectedRuns(keys)
            for partition_size in (1, 2, 3, 4, 7, 32, 1000):
                runs, _ = runsFor(keys, partition_size)
                self.assertEqual(sorted(runs), expected, "%s at partition size %d" % (name, partition_size))
                self.assertEqual(len(runs), len(expected), "%s emitted a hash twice at partition size %d" % (name, partition_size))

    def testRunsArriveInIndexOrder(self):
        runs, _ = runsFor(self.CORPORA["duplicated"], 4)
        self.assertEqual([key for key, _ in runs], sorted(key for key, _ in runs))

    def testAHashLargerThanAPartitionIsCountedByIndex(self):
        """A run that cannot fit in a partition must terminate the loop, not restart it.

        Without the indexed count this is an infinite loop: the partition holds one run, the
        inclusive restart lands on the same key, and the next partition is identical.
        """
        runs, functions = runsFor(self.CORPORA["one_hot_hash"], 4)
        self.assertEqual(dict(runs)["0xff"], 25)
        self.assertLess(functions.num_finds, 25)

    def testNullPicHashesAreExcluded(self):
        keys = ["0x1", None, "0x1", None, "0x2"]
        runs, _ = runsFor(keys, 2)
        self.assertEqual(sorted(runs), [("0x1", 2), ("0x2", 1)])

    def testTheScanIsLinearInTheNumberOfKeys(self):
        """Re-reading a cut run is the only overlap a partition boundary may cost.

        The bound is what makes the rebuild linear: each partition re-reads at most the one run
        it cut, so with P partitions the scan reads at most (keys + P * longest run) keys. Left
        unbounded - for instance by restarting each partition from the beginning - the rebuild
        would be quadratic in the corpus while still producing the right answer.
        """
        keys = ["0x%04x" % (value % 400) for value in range(4000)]
        runs, functions = runsFor(keys, 64)
        self.assertEqual(sorted(runs), expectedRuns(keys))
        longest_run = max(count for _, count in runs)
        self.assertLessEqual(functions.num_keys_read, len(keys) + functions.num_finds * longest_run)


def buildConfig(partition_size, db_name=DB_NAME):
    server, port = getTestMongoServerAndPort()
    config = McritConfig()
    config.STORAGE_CONFIG = StorageConfig(
        STORAGE_METHOD=StorageFactory.STORAGE_METHOD_MONGODB,
        STORAGE_SERVER=server,
        STORAGE_PORT=port,
        STORAGE_MONGODB_DBNAME=db_name,
        STORAGE_REBUILD_PARTITION_SIZE=partition_size,
    )
    config.MINHASH_CONFIG = MinHashConfig()
    config.SHINGLER_CONFIG = ShinglerConfig()
    config.QUEUE_CONFIG = QueueConfig()
    config.QUEUE_CONFIG.QUEUE_MONGODB_DBNAME = db_name + "_queue"
    config.QUEUE_CONFIG.QUEUE_METHOD = QueueFactory.QUEUE_METHOD_FAKE
    return config


def loadReport(name):
    with open(os.sep.join([PROJECT_ROOT, "tests", name])) as handle:
        return SmdaReport.fromDict(json.load(handle))


@pytest.mark.mongo
class PicHashCountRebuildEqualityTest(TestCase):
    """The partitioned rebuild must reproduce the grouped one exactly, on a real corpus."""

    @classmethod
    def setUpClass(cls):
        index = MinHashIndex(config=buildConfig(0))
        index._storage.clearStorage()
        for name in REPORTS:
            entry = index._storage.addSmdaReport(loadReport(name))
            if entry is not None:
                index.queue._worker.updateMinHashesForSample(entry.sample_id)

    @staticmethod
    def _storedCounts(storage):
        collection = storage._getDb()[storage._PICHASH_COUNT_COLLECTION]
        return {document["_pichash"]: document["df"] for document in collection.find({}, {"_pichash": 1, "df": 1, "_id": 0})}

    def testPartitionedRebuildEqualsGroupedRebuild(self):
        grouped_storage = MinHashIndex(config=buildConfig(0))._storage
        num_grouped = grouped_storage.rebuildPicHashCountIndex()
        grouped = self._storedCounts(grouped_storage)
        self.assertTrue(grouped, "the fixture corpus carries no pichashes, so this proves nothing")
        # small enough that partition boundaries land inside runs on this fixture, which is the
        # case a production-sized partition would almost never reach
        for partition_size in (1, 2, 17, 500, 500000):
            storage = MinHashIndex(config=buildConfig(partition_size))._storage
            num_partitioned = storage.rebuildPicHashCountIndex()
            self.assertEqual(self._storedCounts(storage), grouped, "partition size %d" % partition_size)
            self.assertEqual(num_partitioned, num_grouped, "partition size %d" % partition_size)
            self.assertTrue(storage.isPicHashCountIndexComplete())

    def testTheCountsAgreeWithTheFunctionsCollection(self):
        """Not just equal to the old rebuild - equal to the truth the old rebuild was deriving."""
        storage = MinHashIndex(config=buildConfig(3))._storage
        storage.rebuildPicHashCountIndex()
        database = storage._getDb()
        truth = {}
        for function_document in database.functions.find({"_pichash": {"$ne": None}}, {"_pichash": 1, "_id": 0}):
            encoded = function_document["_pichash"]
            truth[encoded] = truth.get(encoded, 0) + 1
        self.assertEqual(self._storedCounts(storage), truth)

    def testTheDefaultKeepsTheGroupedRebuild(self):
        """The knob ships off, so an upgrade does not change what a rebuild does."""
        self.assertEqual(StorageConfig().STORAGE_REBUILD_PARTITION_SIZE, 0)


@pytest.mark.mongo
class PicHashCountRebuildEmptyCorpusTest(TestCase):
    """An empty corpus is the one input where an index-order scan has no first key at all."""

    def testARebuildOverAnEmptyCorpusIsAnEmptyIndex(self):
        storage = MinHashIndex(config=buildConfig(4, DB_NAME + "_empty"))._storage
        storage.clearStorage()
        self.assertEqual(storage.rebuildPicHashCountIndex(), 0)
        collection = storage._getDb()[storage._PICHASH_COUNT_COLLECTION]
        self.assertEqual(collection.count_documents({}), 0)
        self.assertTrue(storage.isPicHashCountIndexComplete())


if __name__ == "__main__":
    main()
