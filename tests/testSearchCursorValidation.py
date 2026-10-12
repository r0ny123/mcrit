import base64
import json
import unittest

import falcon
import falcon.testing
import pymongo
import pytest

from mcrit.config.McritConfig import McritConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.index.SearchCursor import FullSearchCursor, MinimalSearchCursor
from mcrit.server.StatusResource import StatusResource
from mcrit.storage.StorageFactory import StorageFactory

from .context import config, getTestMongoServerAndPort

FAMILY_NAMES = ["fam0", "fam1", "fam2", "fam3", "fam4"]


def encode_cursor(data):
    return base64.urlsafe_b64encode(json.dumps(data).encode()).decode()


class SearchCursorShapeTestSuite(unittest.TestCase):
    """A cursor comes back from the client: its values went into the storage query as they were, so a
    JSON object in it became a MongoDB query operator on the sort field - {"$regex": ...} made mongod
    run an attacker's backtracking pattern over every function of the corpus"""

    def testCursorsThisServerIssuesAreAccepted(self):
        for record_values in (["fam2", 3], [7], [None, 1], [True, 2], [1.5, 0], ["0x1f", 9]):
            for direction in (0, 1):
                with self.subTest(record_values=record_values, direction=direction):
                    cursor = MinimalSearchCursor.fromStr(encode_cursor([record_values, direction]))
                    assert cursor is not None
                    self.assertEqual(record_values, cursor.record_values)
                    self.assertEqual(bool(direction), cursor.is_forward_search)

    def testMalformedCursorsAreValueErrors(self):
        malformed = [
            [[{"$regex": "^fam[13]$"}, -1], 1],
            [[{"$in": ["fam0", "fam4"]}], 1],
            [[["fam1"], 1], 1],
            [["fam1", 1], {"$gt": 0}],
            [["fam1", 1], 2],
            [[10**30, 1], 1],
            [[-(10**30)], 1],
            [["fam1", 1]],
            {"0": ["fam1"], "1": 1},
            "fam1",
            7,
        ]
        for data in malformed:
            with self.subTest(data=data):
                with self.assertRaises(ValueError):
                    MinimalSearchCursor.fromStr(encode_cursor(data))

    def testCursorMustMatchTheSortOrder(self):
        cursor = MinimalSearchCursor.fromStr(encode_cursor([["fam2"], 1]))
        with self.assertRaises(ValueError):
            FullSearchCursor(cursor, [("family_name", True), ("family_id", True)])
        self.assertEqual(["fam2"], FullSearchCursor(cursor, [("family_name", True)]).record_values)


class MemorySearchCursorTestSuite(unittest.TestCase):
    mongo_db_name = None

    def setUp(self):
        mcrit_config = McritConfig()
        if self.mongo_db_name is None:
            mcrit_config.STORAGE_CONFIG = StorageConfig(STORAGE_METHOD=StorageFactory.STORAGE_METHOD_MEMORY)
        else:
            server, port = getTestMongoServerAndPort()
            mcrit_config.STORAGE_CONFIG = StorageConfig(
                STORAGE_METHOD=StorageFactory.STORAGE_METHOD_MONGODB, STORAGE_SERVER=server, STORAGE_PORT=port, STORAGE_MONGODB_DBNAME=self.mongo_db_name
            )
        mcrit_config.QUEUE_CONFIG = config.QUEUE_CONFIG
        self.index = MinHashIndex(mcrit_config)
        self.index.getStorage().clearStorage()
        for family_name in FAMILY_NAMES:
            self.index.getStorage().addFamily(family_name)

    def _search(self, cursor_data):
        request = falcon.Request(falcon.testing.create_environ(path="/search/families", query_string="query=&sort_by=family_name&cursor=" + encode_cursor(cursor_data)))
        response = falcon.Response()
        StatusResource(self.index).on_get_search_families(request, response)
        assert response.data is not None
        return response.status, json.loads(response.data)

    def testPagingByCursorStillWorks(self):
        status, payload = self._search([["fam2", -1], 1])
        self.assertEqual(falcon.HTTP_200, status)
        self.assertEqual(["fam2", "fam3", "fam4"], [entry["family_name"] for entry in payload["data"]["search_results"].values()])

    def testOperatorCursorIsAnsweredAsBadInput(self):
        for value in ({"$regex": "^fam[13]$"}, {"$in": ["fam0", "fam4"]}, {"$where": "sleep(100) || true"}):
            with self.subTest(value=value):
                status, payload = self._search([[value, -1], 1])
                self.assertEqual(falcon.HTTP_400, status)
                self.assertEqual("failed", payload["status"])

    def testCursorOfAnotherSortFieldIsAnsweredAsBadInputInMemory(self):
        # same number of values, but a family_id that is a string: the in-memory comparison fails
        # (MongoDB takes such a cursor as it is and answers a page)
        if self.mongo_db_name is not None:
            self.skipTest("MongoDB does not compare the values itself")
        status, _ = self._search([["fam2", "fam3"], 1])
        self.assertEqual(falcon.HTTP_400, status)

    def testCursorOfAnotherSortOrderIsAnsweredAsBadInput(self):
        status, _ = self._search([["fam2"], 1])
        self.assertEqual(falcon.HTTP_400, status)


@pytest.mark.mongo
class MongoSearchCursorTestSuite(MemorySearchCursorTestSuite):
    """The operator only ever reached MongoDB: the in-memory search compares Python values"""

    mongo_db_name = "test_search_cursor_mcrit"

    @classmethod
    def tearDownClass(cls):
        server, port = getTestMongoServerAndPort()
        pymongo.MongoClient(server, int(port)).drop_database(cls.mongo_db_name)


if __name__ == "__main__":
    unittest.main()
