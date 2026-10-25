import copy
import datetime
import json
import os
import unittest

import pymongo
import pytest
from smda.common.SmdaReport import SmdaReport

from mcrit.config.McritConfig import McritConfig
from mcrit.config.QueueConfig import QueueConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.index.SearchCursor import MinimalSearchCursor
from mcrit.queue.QueueFactory import QueueFactory
from mcrit.storage.StorageFactory import StorageFactory

from .context import config, getTestMongoServerAndPort

EXAMPLE_REPORT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "example_report.smda")

# sample id -> timestamp as submitted; "" is a report without one, which smda reads as None
TIMESTAMPS = ["2026-01-02T00-00-00", "", "2026-01-01T00-00-00", "", "2026-01-02T00-00-00"]
# a missing timestamp sorts first, as in MongoDB, and ties are broken by the id in the same direction
ASCENDING = [1, 3, 2, 0, 4]
DESCENDING = [4, 0, 2, 3, 1]


class SampleSearchSort(unittest.TestCase):
    """Sample search sorted by timestamp: the cursor of a page used to hold a datetime, which JSON
    can't encode, so any listing with a next page answered 500; a sample submitted without a
    timestamp couldn't be read back from MongoDB at all"""

    def _index(self, index_config=None):
        index = MinHashIndex(index_config or config)
        index.getStorage().clearStorage()
        with open(EXAMPLE_REPORT) as fjson:
            report_dict = json.load(fjson)
        for number, timestamp in enumerate(TIMESTAMPS):
            sample_dict = copy.deepcopy(report_dict)
            sample_dict["sha256"] = "%064x" % (number + 1)
            sample_dict["timestamp"] = timestamp
            sample_entry = index.getStorage().addSmdaReport(SmdaReport.fromDict(sample_dict))
            assert sample_entry is not None and sample_entry.sample_id == number
        return index

    def _pages(self, index, is_ascending, cursor=None, direction="forward"):
        pages = []
        while True:
            result = index.getSampleSearchResults("", sort_by="timestamp", is_ascending=is_ascending, cursor=cursor, limit=2)
            json.dumps(result["cursor"])
            pages.append([int(sample_id) for sample_id in result["search_results"]])
            cursor = result["cursor"][direction]
            if cursor is None:
                return pages, result["cursor"]

    def test_paging_by_timestamp_visits_every_sample_once(self):
        index = self._index()
        for is_ascending, expected in ((True, ASCENDING), (False, DESCENDING)):
            with self.subTest(is_ascending=is_ascending):
                pages, last_cursor = self._pages(index, is_ascending)
                self.assertEqual(expected, [sample_id for page in pages for sample_id in page])
                # and back again from the last page, page by page
                back_pages, _ = self._pages(index, is_ascending, cursor=last_cursor["backward"], direction="backward")
                self.assertEqual(pages[:-1][::-1], back_pages)

    def test_a_sample_without_timestamp_is_read_back(self):
        index = self._index()
        storage = index.getStorage()
        self.assertIsNone(storage.getSampleById(1).timestamp)
        self.assertIsNone(storage.getSampleBySha256("%064x" % 2).toDict()["timestamp"])
        self.assertEqual(list(range(len(TIMESTAMPS))), sorted(sample.sample_id for sample in storage.getSamples(0, 0)))

    def test_naive_and_aware_timestamps_sort_together(self):
        # smda run in-process stamps a report with an aware datetime, while a stored one reads back
        # naive; the memory backend compared the two and failed
        index = self._index()
        with open(EXAMPLE_REPORT) as fjson:
            report = SmdaReport.fromDict(dict(json.load(fjson), sha256="%064x" % 99))
        assert report is not None
        report.timestamp = datetime.datetime(2026, 1, 1, 12, tzinfo=datetime.UTC)
        aware_id = index.getStorage().addSmdaReport(report).sample_id
        pages, _ = self._pages(index, True)
        self.assertEqual([1, 3, 2, aware_id, 0, 4], [sample_id for page in pages for sample_id in page])

    def test_a_cursor_with_nothing_after_it_finds_nothing(self):
        # no cursor the server issues names None for the id; a crafted one made the memory backend
        # fail, and must not match every sample on MongoDB either
        cursor = MinimalSearchCursor()
        cursor.record_values, cursor.is_forward_search = [None], False
        results = self._index().getSampleSearchResults("", cursor=cursor.toStr())
        self.assertEqual({}, results["search_results"])

    def test_function_id_is_not_a_sample_sort_field(self):
        # samples have no function_id: MongoDB sorted every sample as null and the memory backend failed
        with self.assertRaises(ValueError):
            self._index().getSampleSearchResults("", sort_by="function_id")


@pytest.mark.mongo
class SampleSearchSortMongo(SampleSearchSort):
    DB_NAME = "test_sample_search_sort"

    def _index(self, index_config=None):
        server, port = getTestMongoServerAndPort()
        self.addCleanup(lambda: pymongo.MongoClient(server, int(port)).drop_database(self.DB_NAME))
        mongo_config = McritConfig()
        mongo_config.STORAGE_CONFIG = StorageConfig(
            STORAGE_METHOD=StorageFactory.STORAGE_METHOD_MONGODB, STORAGE_SERVER=server, STORAGE_PORT=port, STORAGE_MONGODB_DBNAME=self.DB_NAME
        )
        mongo_config.QUEUE_CONFIG = QueueConfig(QUEUE_METHOD=QueueFactory.QUEUE_METHOD_FAKE)
        pymongo.MongoClient(server, int(port)).drop_database(self.DB_NAME)
        return super()._index(mongo_config)


if __name__ == "__main__":
    unittest.main()
