"""Search input the storages can't serve is a 400, on both storages, not a 500.

Only a ValueError was answered as a client error. An integer beyond 64 bits made MongoDB raise OverflowError, a pichash that wasn't a
number failed its encoding with a TypeError, a numeric field compared with text failed the memory
storage's comparison, and a deeply nested query ran out of recursion.
"""

import json
import logging
import os
import unittest

import falcon
import falcon.testing
import pymongo
import pytest
from smda.common.SmdaReport import SmdaReport

from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.index.SearchCursor import MinimalSearchCursor
from mcrit.server.StatusResource import StatusResource

from .context import config
from .testExportImportRoundTrip import mongo_config

logging.disable(logging.CRITICAL)

EXAMPLE_REPORT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "example_report.smda")

REFUSED = [
    ("samples", {"query": "sample_id:" + str(2**64)}),
    ("functions", {"query": "function_id:-" + str(2**64)}),
    ("functions", {"query": "num_instructions:>" + str(2**63)}),
    ("functions", {"query": "num_instructions:>abc"}),
    ("functions", {"query": "pichash:zz"}),
    ("functions", {"query": "pichash:-5"}),
    ("functions", {"query": "pichash:" + str(2**64)}),
    ("functions", {"query": "offset:" + str(2**64)}),
    ("functions", {"query": "offset:-5"}),
    ("functions", {"query": "(" * 2000 + "a" + ")" * 2000}),
    # nearly 20 KB: beyond what a parser that recurses per term can take, and beyond a cap on query length
    ("functions", {"query": " ".join(["word"] * 4000)}),
]

SERVED = [
    ("functions", {"query": "", "limit": "1"}),
    ("functions", {"query": "", "limit": str(2**63 - 2)}),
    ("samples", {"query": "sample_id:0"}),
    ("samples", {"query": "sample_id:00"}),
    ("functions", {"query": "function_id:0x1"}),
    ("functions", {"query": "num_instructions:>=5"}),
    ("functions", {"query": "pichash:" + str(2**64 - 1)}),
    ("functions", {"query": "offset:" + str(2**63 - 1)}),
    ("functions", {"query": "offset:" + str(2**64 - 1)}),
]

KERNEL_OFFSET = 0xFFFFFFFF80001000


class SearchInputErrorsMixin(unittest.TestCase):
    __test__ = False
    RANGE_ABOVE_2_63_STATUS = falcon.HTTP_200

    def _config(self):
        raise NotImplementedError

    def _move_function(self, storage, function_id, offset):
        raise NotImplementedError

    def setUp(self):
        index = MinHashIndex(self._config())
        with open(EXAMPLE_REPORT) as fjson:
            report = SmdaReport.fromDict(json.load(fjson))
        assert report is not None
        index.getStorage().addSmdaReport(report)
        self.storage = index.getStorage()
        resource = StatusResource(index)
        app = falcon.App()
        for kind in ("families", "samples", "functions"):
            app.add_route(f"/search/{kind}", resource, suffix=f"search_{kind}")
        self.client = falcon.testing.TestClient(app)

    def test_input_the_storage_cant_serve_is_a_400(self):
        for kind, params in REFUSED:
            with self.subTest(kind=kind, query=params["query"][:40], limit=params.get("limit")):
                response = self.client.simulate_get(f"/search/{kind}", params=params)
                self.assertEqual(falcon.HTTP_400, response.status)
                self.assertEqual("failed", response.json["status"])

    def test_valid_numbers_are_still_served(self):
        for kind, params in SERVED:
            with self.subTest(kind=kind, query=params["query"], limit=params.get("limit")):
                self.assertEqual(falcon.HTTP_200, self.client.simulate_get(f"/search/{kind}", params=params).status)

    def test_a_search_cursor_still_pages(self):
        """A cursor's conditions hold the stored values themselves, numbers already."""
        first = self.client.simulate_get("/search/functions", params={"query": "num_instructions:>0", "limit": "2", "sort_by": "num_instructions"})
        self.assertEqual(falcon.HTTP_200, first.status)
        cursor = first.json["data"]["cursor"]["forward"]
        self.assertIsNotNone(cursor)
        second = self.client.simulate_get("/search/functions", params={"query": "num_instructions:>0", "limit": "2", "sort_by": "num_instructions", "cursor": cursor})
        self.assertEqual(falcon.HTTP_200, second.status)
        self.assertTrue(set(first.json["data"]["search_results"]).isdisjoint(second.json["data"]["search_results"]))

    def test_an_offset_beyond_2_63_is_found_and_paged_past(self):
        """64 bit kernel code sits above 2**63; MongoDB stores such an offset as a signed value."""
        function_ids = sorted(entry.function_id for entry in self.storage.getFunctionsBySampleId(0))
        self._move_function(self.storage, function_ids[-1], KERNEL_OFFSET)
        self._move_function(self.storage, function_ids[-2], KERNEL_OFFSET + 0x10)
        found = self.client.simulate_get("/search/functions", params={"query": f"offset:{KERNEL_OFFSET:#x}"})
        self.assertEqual(falcon.HTTP_200, found.status)
        self.assertEqual([str(function_ids[-1])], list(found.json["data"]["search_results"]))
        first = self.client.simulate_get("/search/functions", params={"query": "", "limit": "1", "sort_by": "offset", "is_ascending": "false"})
        self.assertEqual(falcon.HTTP_200, first.status)
        cursor = first.json["data"]["cursor"]["forward"]
        second = self.client.simulate_get("/search/functions", params={"query": "", "limit": "1", "sort_by": "offset", "is_ascending": "false", "cursor": cursor})
        self.assertEqual(falcon.HTTP_200, second.status)
        self.assertNotEqual(list(first.json["data"]["search_results"]), list(second.json["data"]["search_results"]))

    def test_a_cursor_number_beyond_63_bits_on_a_text_field_is_a_400(self):
        """A cursor may hold up to 2**64 for a kernel-space offset; on a text sort field MongoDB can't
        encode that and answered 500."""
        for kind, sort_by in (("families", "family_name"), ("samples", "filename"), ("functions", "function_name")):
            for value in (2**63, 2**64 - 1):
                cursor = MinimalSearchCursor()
                cursor.record_values = [value, 1]
                with self.subTest(kind=kind, value=value):
                    response = self.client.simulate_get(f"/search/{kind}", params={"query": "", "sort_by": sort_by, "cursor": cursor.toStr()})
                    self.assertEqual(falcon.HTTP_400, response.status)

    def test_offset_ranges_above_2_63_are_refused_on_mongodb_only(self):
        """MongoDB keeps such an offset as a negative number, which a range over it can't reach."""
        response = self.client.simulate_get("/search/functions", params={"query": f"offset:>={KERNEL_OFFSET:#x}"})
        self.assertEqual(self.RANGE_ABOVE_2_63_STATUS, response.status)
        self.assertEqual(falcon.HTTP_200, self.client.simulate_get("/search/functions", params={"query": "offset:>=0x1000"}).status)


class SearchInputErrorsMemoryTest(SearchInputErrorsMixin):
    __test__ = True
    RANGE_ABOVE_2_63_STATUS = falcon.HTTP_200

    def _config(self):
        return config

    def _move_function(self, storage, function_id, offset):
        storage._functions[function_id].offset = offset


@pytest.mark.mongo
class SearchInputErrorsMongoTest(SearchInputErrorsMixin):
    __test__ = True
    RANGE_ABOVE_2_63_STATUS = falcon.HTTP_400
    DB_NAME = "test_search_input_errors"

    def _config(self):
        return mongo_config(self.DB_NAME)

    def _move_function(self, storage, function_id, offset):
        storage._getDb().functions.update_one({"function_id": function_id}, {"$set": {"offset": offset - 2**64 if offset >= 2**63 else offset}})

    def setUp(self):
        storage_config = mongo_config(self.DB_NAME).STORAGE_CONFIG
        self._client = pymongo.MongoClient(storage_config.STORAGE_SERVER, int(storage_config.STORAGE_PORT))
        self._client.drop_database(self.DB_NAME)
        self.addCleanup(self._client.close)
        self.addCleanup(self._client.drop_database, self.DB_NAME)
        super().setUp()


if __name__ == "__main__":
    unittest.main()
