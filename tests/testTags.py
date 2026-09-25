"""#53: tags on families, samples and functions."""

import json
import logging
import os
import unittest
from unittest.mock import MagicMock, patch

import falcon.testing
import pymongo
import pytest
from smda.common.SmdaReport import SmdaReport

from mcrit.client.McritClient import McritBadRequest, McritClient, McritNotFound
from mcrit.config.McritConfig import McritConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.index.SearchCursor import FullSearchCursor
from mcrit.index.SearchQueryParser import SearchQueryParser
from mcrit.libs.tags import isValidTag, normalizeTags
from mcrit.server import application_routes
from mcrit.storage.FamilyEntry import FamilyEntry
from mcrit.storage.FunctionEntry import FunctionEntry
from mcrit.storage.SampleEntry import SampleEntry
from mcrit.storage.StorageFactory import StorageFactory

from .context import config, getTestMongoServerAndPort

logging.disable(logging.CRITICAL)

THIS_FILE_PATH = str(os.path.abspath(__file__))
PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
EXAMPLE_REPORT = os.sep.join([PROJECT_ROOT, "tests", "example_report.smda"])
EXAMPLE_REPORT_2 = os.sep.join([PROJECT_ROOT, "tests", "example_report_2.smda"])


def storage_config(mongo_db_name=None):
    mcrit_config = McritConfig()
    if mongo_db_name is None:
        mcrit_config.STORAGE_CONFIG = StorageConfig(STORAGE_METHOD=StorageFactory.STORAGE_METHOD_MEMORY, STORAGE_DROP_DISASSEMBLY=False)
    else:
        server, port = getTestMongoServerAndPort()
        mcrit_config.STORAGE_CONFIG = StorageConfig(
            STORAGE_METHOD=StorageFactory.STORAGE_METHOD_MONGODB, STORAGE_SERVER=server, STORAGE_PORT=port, STORAGE_MONGODB_DBNAME=mongo_db_name, STORAGE_DROP_DISASSEMBLY=False
        )
    # the same hashing configuration as the in-memory test config, so exports import across both
    mcrit_config.MINHASH_CONFIG = config.MINHASH_CONFIG
    mcrit_config.SHINGLER_CONFIG = config.SHINGLER_CONFIG
    mcrit_config.QUEUE_CONFIG = config.QUEUE_CONFIG
    return mcrit_config


def load_report(path, family=None):
    with open(path) as fjson:
        report = SmdaReport.fromDict(json.load(fjson))
    assert report is not None
    if family is not None:
        report.family = family
    return report


class TagNormalisation(unittest.TestCase):
    def test_tags_are_stripped_lowercased_and_kept_once(self):
        self.assertEqual(["packed", "source:vt", "has space"], normalizeTags([" Packed ", "SOURCE:VT", "packed", "has space"]))
        self.assertEqual([], normalizeTags([]))

    def test_the_rule(self):
        for valid in ("a", "0day", "ns:value", "a.b-c_d e", "x" * 64, "UPPER"):
            self.assertTrue(isValidTag(valid), valid)
        for invalid in ("", "   ", "x" * 65, "$where", "-x", ".x", ":x", "a/b", "a\nb", "tagé", None, 5, ["a"]):
            self.assertFalse(isValidTag(invalid), invalid)

    def test_invalid_input_is_refused_or_dropped(self):
        for invalid in (["ok", ""], ["x" * 65], ["$gt"], "packed", None, [1]):
            with self.assertRaises(ValueError):
                normalizeTags(invalid)
        # an import drops what it cannot take instead of failing
        self.assertEqual(["ok"], normalizeTags(["ok", "$gt", "", 3], drop_invalid=True))
        self.assertEqual([], normalizeTags("packed", drop_invalid=True))


class EntryTags(unittest.TestCase):
    def test_entries_carry_tags_and_older_dicts_read_as_none(self):
        family = FamilyEntry(family_name="win.x", family_id=3, tags=["a"])
        self.assertEqual(["a"], family.toDict()["tags"])
        self.assertEqual(["a"], FamilyEntry.fromDict(family.toDict()).tags)
        legacy_family = family.toDict()
        del legacy_family["tags"]
        self.assertEqual([], FamilyEntry.fromDict(legacy_family).tags)
        report = load_report(EXAMPLE_REPORT)
        sample = SampleEntry(report, sample_id=1, family_id=0)
        self.assertEqual([], sample.tags)
        sample.tags = ["b"]
        self.assertEqual(["b"], SampleEntry.fromDict(sample.toDict()).tags)
        legacy_sample = sample.toDict()
        del legacy_sample["tags"]
        self.assertEqual([], SampleEntry.fromDict(legacy_sample).tags)
        function = FunctionEntry(sample, report.getFunctions().__next__(), 7)
        self.assertEqual([], function.tags)
        function.tags = ["c"]
        self.assertEqual(["c"], FunctionEntry.fromDict(function.toDict()).tags)
        legacy_function = function.toDict()
        del legacy_function["tags"]
        self.assertEqual([], FunctionEntry.fromDict(legacy_function).tags)


class MemoryStorageTags(unittest.TestCase):
    mongo_db_name = None

    def setUp(self):
        self.index = MinHashIndex(storage_config(self.mongo_db_name))
        self.storage = self.index.getStorage()
        self.storage.clearStorage()
        self.sample = self.storage.addSmdaReport(load_report(EXAMPLE_REPORT, family="family_a"))
        self.other_sample = self.storage.addSmdaReport(load_report(EXAMPLE_REPORT_2, family="family_b"))
        assert self.sample is not None and self.other_sample is not None
        self.function_ids = sorted(self.storage.getFunctionIdsBySampleId(self.sample.sample_id))

    def tearDown(self):
        self.storage.clearStorage()

    def _tags_of(self, entity, entity_id):
        if entity == "family":
            return self.storage.getFamily(entity_id).tags
        if entity == "sample":
            return self.storage.getSampleById(entity_id).tags
        return self.storage.getFunctionById(entity_id).tags

    def test_add_remove_and_duplicate_add_on_every_entity(self):
        for entity, entity_id in (("family", self.sample.family_id), ("sample", self.sample.sample_id), ("function", self.function_ids[0])):
            self.assertEqual([], self._tags_of(entity, entity_id), entity)
            self.assertEqual(["packed", "source:vt"], self.storage.addTags(entity, entity_id, [" Packed", "source:VT"]), entity)
            # adding a tag it carries already keeps it once, and adds the new ones behind it
            self.assertEqual(["packed", "source:vt", "reviewed"], self.storage.addTags(entity, entity_id, ["packed", "reviewed", "REVIEWED"]), entity)
            self.assertEqual(["packed", "source:vt", "reviewed"], self._tags_of(entity, entity_id), entity)
            # removing one it does not carry is ignored
            self.assertEqual(["source:vt"], self.storage.removeTags(entity, entity_id, ["Packed", "reviewed", "unknown"]), entity)
            self.assertEqual(["source:vt"], self._tags_of(entity, entity_id), entity)
            self.assertEqual([], self.storage.removeTags(entity, entity_id, ["source:vt"]), entity)
            self.assertEqual([], self._tags_of(entity, entity_id), entity)
        # the other entities were not touched
        self.assertEqual([], self._tags_of("family", self.other_sample.family_id))
        self.assertEqual([], self._tags_of("function", self.function_ids[1]))

    def test_unknown_ids_and_invalid_input(self):
        for entity in ("family", "sample", "function"):
            self.assertIsNone(self.storage.addTags(entity, 4242, ["x"]), entity)
            self.assertIsNone(self.storage.removeTags(entity, 4242, ["x"]), entity)
        # query samples and functions carry no tags
        query_sample = self.storage.addSmdaReport(load_report(EXAMPLE_REPORT), isQuery=True)
        assert query_sample is not None
        self.assertIsNone(self.storage.addTags("sample", query_sample.sample_id, ["x"]))
        query_function_id = self.storage.getFunctionIdsBySampleId(query_sample.sample_id)[0]
        self.assertIsNone(self.storage.addTags("function", query_function_id, ["x"]))
        with self.assertRaises(ValueError):
            self.storage.addTags("report", self.sample.sample_id, ["x"])
        with self.assertRaises(ValueError):
            self.storage.getTagCounts("report")
        # an invalid tag refuses the whole list, before anything is written
        with self.assertRaises(ValueError):
            self.storage.addTags("sample", self.sample.sample_id, ["fine", "$bad"])
        self.assertEqual([], self._tags_of("sample", self.sample.sample_id))

    def test_tag_counts(self):
        self.assertEqual({}, self.storage.getTagCounts("function"))
        self.storage.addTags("function", self.function_ids[0], ["b", "a"])
        self.storage.addTags("function", self.function_ids[1], ["b"])
        self.storage.addTags("sample", self.sample.sample_id, ["b"])
        self.assertEqual({"a": 1, "b": 2}, self.storage.getTagCounts("function"))
        self.assertEqual(["a", "b"], list(self.storage.getTagCounts("function")))
        self.assertEqual({"b": 1}, self.storage.getTagCounts("sample"))
        self.assertEqual({}, self.storage.getTagCounts("family"))
        self.storage.removeTags("function", self.function_ids[0], ["a"])
        self.assertEqual({"b": 2}, self.storage.getTagCounts("function"))

    def test_a_rename_keeps_the_tags_and_a_merge_unions_them(self):
        family_a, family_b = self.sample.family_id, self.other_sample.family_id
        self.storage.addTags("family", family_a, ["shared", "only-a"])
        self.storage.addTags("family", family_b, ["only-b", "shared"])
        # a rename onto an unused name keeps them
        self.assertTrue(self.storage.modifyFamily(family_a, {"family_name": "family_c"}))
        family_c = self.storage.getFamilyId("family_c")
        self.assertEqual(["shared", "only-a"], self.storage.getFamily(family_c).tags)
        # a rename onto an existing family merges them into that family's
        self.assertTrue(self.storage.modifyFamily(family_c, {"family_name": "family_b"}))
        self.assertIsNone(self.storage.getFamilyId("family_c"))
        self.assertEqual(["only-b", "shared", "only-a"], self.storage.getFamily(family_b).tags)
        # the samples' and functions' own tags do not move
        self.assertEqual([], self.storage.getSampleById(self.sample.sample_id).tags)

    def _search(self, kind, term):
        parsed = SearchQueryParser().parse(term)
        id_field = f"{kind}_id"
        cursor = FullSearchCursor(None, [(id_field, True)])
        finder = {"family": self.storage.findFamilyByString, "sample": self.storage.findSampleByString, "function": self.storage.findFunctionByString}[kind]
        return sorted(finder(parsed, cursor=cursor, max_num_results=1000))

    def test_search_on_tags_is_element_wise(self):
        first, second, third = self.function_ids[:3]
        self.storage.addTags("function", first, ["packed", "source:vt"])
        self.storage.addTags("function", second, ["packed"])
        self.storage.addTags("function", third, ["unpacked"])
        all_functions = sorted(self.storage.getFunctionIdsBySampleId(self.sample.sample_id) + self.storage.getFunctionIdsBySampleId(self.other_sample.sample_id))
        # some element equals the value; "tag" is the same field, and the value is normalised like a tag
        self.assertEqual([first, second], self._search("function", "tags:packed"))
        self.assertEqual([first, second], self._search("function", "tag:packed"))
        self.assertEqual([first, second], self._search("function", "tag:PACKED"))
        self.assertEqual([first], self._search("function", 'tags:"source:vt"'))
        # no element equals the value, which includes every untagged function
        self.assertEqual([function_id for function_id in all_functions if function_id not in (first, second)], self._search("function", "tags:!=packed"))
        self.assertEqual(self._search("function", "tags:!=packed"), self._search("function", "NOT tag:packed"))
        # some element contains the value
        self.assertEqual([first, second, third], self._search("function", "tags:?pack"))
        self.assertEqual([first], self._search("function", "tag:?vt"))
        self.assertEqual([function_id for function_id in all_functions if function_id not in (first, second, third)], self._search("function", "tags:!?pack"))
        # combined with another field
        self.assertEqual([second], self._search("function", f"tag:packed function_id:{second}"))
        # a plain term does not search the tags: existing searches find what they found before
        self.assertEqual([], self._search("function", "unpacked"))

    def test_search_on_family_and_sample_tags(self):
        self.storage.addTags("family", self.other_sample.family_id, ["apt"])
        self.storage.addTags("sample", self.sample.sample_id, ["reviewed"])
        self.assertEqual([self.other_sample.family_id], self._search("family", "tag:apt"))
        self.assertNotIn(self.other_sample.family_id, self._search("family", "tags:!=apt"))
        self.assertEqual([self.sample.sample_id], self._search("sample", "tags:reviewed"))
        self.assertEqual([self.other_sample.sample_id], self._search("sample", "tags:!=reviewed"))
        self.assertEqual([self.sample.sample_id], self._search("sample", "tag:?view"))
        self.assertEqual([], self._search("sample", "reviewed"))


@pytest.mark.mongo
class MongoDbStorageTags(MemoryStorageTags):
    """Every test above, against MongoDB: both backends have to give the same answers."""

    mongo_db_name = "test_tags_mcrit"

    @classmethod
    def tearDownClass(cls):
        server, port = getTestMongoServerAndPort()
        pymongo.MongoClient(server, int(port)).drop_database(cls.mongo_db_name)

    def test_untagged_functions_store_no_tags_field(self):
        """which keeps them out of the sparse tags index"""
        db = self.storage._getDb()
        self.assertEqual(0, db.functions.count_documents({"tags": {"$exists": True}}))
        self.assertTrue(db.functions.index_information()["tags_1"].get("sparse"))
        self.assertIn("tags_1", db.samples.index_information())
        self.assertIn("tags_1", db.families.index_information())
        self.storage.addTags("function", self.function_ids[0], ["a"])
        self.assertEqual(1, db.functions.count_documents({"tags": {"$exists": True}}))
        self.storage.removeTags("function", self.function_ids[0], ["a"])
        self.assertEqual(0, db.functions.count_documents({"tags": {"$exists": True}}))
        # the query uses the index
        plan = db.functions.find({"tags": "a"}).explain()["queryPlanner"]["winningPlan"]
        self.assertIn("tags_1", json.dumps(plan))


class ExportImportTags(unittest.TestCase):
    source_db = None
    target_db = None

    def test_round_trip_keeps_tags_and_merges_family_tags(self):
        source = MinHashIndex(storage_config(self.source_db))
        source.getStorage().clearStorage()
        sample = source.getStorage().addSmdaReport(load_report(EXAMPLE_REPORT, family="tagged_family"))
        assert sample is not None
        function_ids = sorted(source.getStorage().getFunctionIdsBySampleId(sample.sample_id))
        function_offset = source.getStorage().getFunctionById(function_ids[0]).offset
        source.getStorage().addTags("family", sample.family_id, ["apt", "source:vt"])
        source.getStorage().addTags("sample", sample.sample_id, ["reviewed"])
        source.getStorage().addTags("function", function_ids[0], ["crypto"])
        export_data = json.loads(json.dumps(source.getExportData()))
        self.assertEqual({str(sample.family_id): ["apt", "source:vt"]}, export_data["family_tags"])
        target = MinHashIndex(storage_config(self.target_db))
        target.getStorage().clearStorage()
        target_family_id = target.getStorage().addFamily("tagged_family")
        target.getStorage().addTags("family", target_family_id, ["local", "apt"])
        report = target.addImportData(export_data)
        self.assertEqual(1, report["num_samples_imported"])
        self.assertEqual(["local", "apt", "source:vt"], target.getStorage().getFamily(target_family_id).tags)
        imported = target.getStorage().getSampleBySha256(sample.sha256)
        self.assertEqual(["reviewed"], imported.tags)
        imported_functions = {entry.offset: entry for entry in target.getStorage().getFunctionsBySampleId(imported.sample_id)}
        self.assertEqual(["crypto"], imported_functions[function_offset].tags)
        self.assertEqual(1, sum(1 for entry in imported_functions.values() if entry.tags))
        for index in (source, target):
            index.getStorage().clearStorage()

    def test_an_export_without_tags_imports_as_before(self):
        """an export written before #53, or tampered with: no family_tags, no tags in the
        entries, or tags this instance would not accept"""
        source = MinHashIndex(storage_config(self.source_db))
        source.getStorage().clearStorage()
        sample = source.getStorage().addSmdaReport(load_report(EXAMPLE_REPORT, family="old_family"))
        assert sample is not None
        export_data = json.loads(json.dumps(source.getExportData()))
        del export_data["family_tags"]
        export_data["sample_entries"][sample.sha256]["tags"] = ["fine", "$bad"]
        for function_dict in export_data["function_entries"][sample.sha256].values():
            del function_dict["tags"]
        target = MinHashIndex(storage_config(self.target_db))
        target.getStorage().clearStorage()
        self.assertEqual(1, target.addImportData(export_data)["num_samples_imported"])
        imported = target.getStorage().getSampleBySha256(sample.sha256)
        self.assertEqual(["fine"], imported.tags)
        self.assertTrue(all(entry.tags == [] for entry in target.getStorage().getFunctionsBySampleId(imported.sample_id)))
        self.assertEqual([], target.getStorage().getFamily(imported.family_id).tags)
        for index in (source, target):
            index.getStorage().clearStorage()


@pytest.mark.mongo
class MongoExportImportTags(ExportImportTags):
    source_db = "test_tags_export_source_mcrit"
    target_db = "test_tags_export_target_mcrit"

    @classmethod
    def tearDownClass(cls):
        server, port = getTestMongoServerAndPort()
        client = pymongo.MongoClient(server, int(port))
        for name in (cls.source_db, cls.target_db):
            client.drop_database(name)


class TagRoutes(unittest.TestCase):
    """The routes as get_app registers them, over a memory storage."""

    def setUp(self):
        self.index = MinHashIndex(storage_config())
        self.sample = self.index.getStorage().addSmdaReport(load_report(EXAMPLE_REPORT, family="family_a"))
        assert self.sample is not None
        self.function_id = sorted(self.index.getStorage().getFunctionIdsBySampleId(self.sample.sample_id))[0]
        with patch.object(application_routes, "create_index", return_value=self.index), patch.object(McritConfig, "AUTH_TOKEN", ""):
            self.client = falcon.testing.TestClient(application_routes.get_app())

    def test_add_and_remove_on_every_entity(self):
        for route, entity, entity_id in (("families", "family", self.sample.family_id), ("samples", "sample", self.sample.sample_id), ("functions", "function", self.function_id)):
            result = self.client.simulate_post(f"/{route}/{entity_id}/tags", json={"tags": ["Packed", "source:vt"]})
            self.assertEqual(falcon.HTTP_200, result.status, route)
            self.assertEqual({"entity": entity, "entity_id": entity_id, "tags": ["packed", "source:vt"]}, result.json["data"], route)
            result = self.client.simulate_delete(f"/{route}/{entity_id}/tags", json={"tags": ["packed"]})
            self.assertEqual(falcon.HTTP_200, result.status, route)
            self.assertEqual(["source:vt"], result.json["data"]["tags"], route)
            result = self.client.simulate_get("/tags", params={"entity": entity})
            self.assertEqual(falcon.HTTP_200, result.status, route)
            self.assertEqual({"entity": entity, "tags": {"source:vt": 1}}, result.json["data"], route)
        # the tags are part of what the entity's own route answers
        self.assertEqual(["source:vt"], self.client.simulate_get(f"/samples/{self.sample.sample_id}").json["data"]["tags"])
        self.assertEqual(["source:vt"], self.client.simulate_get(f"/functions/{self.function_id}").json["data"]["tags"])
        self.assertEqual(["source:vt"], self.client.simulate_get(f"/families/{self.sample.family_id}").json["data"]["tags"])

    def test_malformed_requests_answer_400_and_change_nothing(self):
        path = f"/samples/{self.sample.sample_id}/tags"
        for body, fragment in (
            ({"tags": [""]}, "invalid tag"),
            ({"tags": ["x" * 65]}, "invalid tag"),
            ({"tags": ["$where"]}, "invalid tag"),
            ({"tags": ["fine", "$where"]}, "invalid tag"),
            ({"tags": "packed"}, "list of strings"),
            ({"tags": [5]}, "invalid tag"),
            ({"tags": []}, "at least one tag"),
            ({"tag": ["packed"]}, '{"tags": [...]}'),
            (["packed"], '{"tags": [...]}'),
        ):
            for method in (self.client.simulate_post, self.client.simulate_delete):
                result = method(path, json=body)
                self.assertEqual(falcon.HTTP_400, result.status, body)
                self.assertEqual("failed", result.json["status"], body)
                self.assertIn(fragment, result.json["data"]["message"], body)
        self.assertEqual(falcon.HTTP_400, self.client.simulate_post(path).status)
        self.assertEqual([], self.index.getStorage().getSampleById(self.sample.sample_id).tags)

    def test_unknown_ids_answer_404(self):
        for route, entity in (("families", "family"), ("samples", "sample"), ("functions", "function")):
            for method in (self.client.simulate_post, self.client.simulate_delete):
                result = method(f"/{route}/4242/tags", json={"tags": ["x"]})
                self.assertEqual(falcon.HTTP_404, result.status, route)
                # MCRIT's own answer, not the router's for a path it does not know
                self.assertEqual({"status": "failed", "data": {"message": f"We don't have a {entity} with that id."}}, result.json, route)
        # a query sample (negative id) carries no tags
        query_sample = self.index.getStorage().addSmdaReport(load_report(EXAMPLE_REPORT), isQuery=True)
        assert query_sample is not None
        result = self.client.simulate_post(f"/samples/{query_sample.sample_id}/tags", json={"tags": ["x"]})
        self.assertEqual(falcon.HTTP_404, result.status)
        self.assertEqual("We don't have a sample with that id.", result.json["data"]["message"])

    def test_the_listing_needs_a_valid_entity(self):
        for params in ({}, {"entity": "report"}, {"entity": "families"}):
            result = self.client.simulate_get("/tags", params=params)
            self.assertEqual(falcon.HTTP_400, result.status, params)
            self.assertIn("entity must be one of family, sample, function", result.json["data"]["message"])


class TagClient(unittest.TestCase):
    def _answer(self, data, status_code=200):
        response = MagicMock(status_code=status_code, url="http://mcrit.test/x")
        response.json.return_value = {"status": "successful", "data": data} if status_code == 200 else {"status": "failed", "data": {"message": "nope"}}
        return response

    def test_requests(self):
        client = McritClient("http://mcrit.test", username="alice")
        with patch("mcrit.client.McritClient.requests.post", return_value=self._answer({"entity": "sample", "entity_id": 4, "tags": ["a", "b"]})) as post:
            self.assertEqual(["a", "b"], client.addTags("sample", 4, ["a", "b"]))
        self.assertEqual("http://mcrit.test/samples/4/tags", post.call_args.args[0])
        self.assertEqual({"tags": ["a", "b"]}, post.call_args.kwargs["json"])
        self.assertEqual("alice", post.call_args.kwargs["headers"]["username"])
        with patch("mcrit.client.McritClient.requests.delete", return_value=self._answer({"entity": "family", "entity_id": 2, "tags": []})) as delete:
            # a single string is one tag
            self.assertEqual([], client.removeTags("family", 2, "a"))
        self.assertEqual("http://mcrit.test/families/2/tags", delete.call_args.args[0])
        self.assertEqual({"tags": ["a"]}, delete.call_args.kwargs["json"])
        with patch("mcrit.client.McritClient.requests.post", return_value=self._answer({"entity": "function", "entity_id": 9, "tags": ["c"]})) as post:
            client.addTags("function", 9, ("c",))
        self.assertEqual("http://mcrit.test/functions/9/tags", post.call_args.args[0])
        with patch("mcrit.client.McritClient.requests.get", return_value=self._answer({"entity": "function", "tags": {"c": 3}})) as get:
            self.assertEqual({"c": 3}, client.getTags("function"))
        self.assertEqual("http://mcrit.test/tags", get.call_args.args[0])
        self.assertEqual({"entity": "function"}, get.call_args.kwargs["params"])
        with self.assertRaises(ValueError):
            client.addTags("report", 1, ["x"])

    def test_error_modes(self):
        # default: a failure answers None
        with patch("mcrit.client.McritClient.requests.post", return_value=self._answer(None, 404)):
            self.assertIsNone(McritClient("http://mcrit.test").addTags("sample", 4, ["a"]))
        raising = McritClient("http://mcrit.test", raise_client_errors=True)
        with patch("mcrit.client.McritClient.requests.post", return_value=self._answer(None, 404)):
            with self.assertRaises(McritNotFound):
                raising.addTags("sample", 4, ["a"])
        with patch("mcrit.client.McritClient.requests.delete", return_value=self._answer(None, 400)):
            with self.assertRaises(McritBadRequest):
                raising.removeTags("sample", 4, ["$a"])
        with patch("mcrit.client.McritClient.requests.get", return_value=self._answer(None, 400)):
            with self.assertRaises(McritBadRequest):
                raising.getTags("report")
        raw = McritClient("http://mcrit.test", raw_responses=True)
        answer = self._answer({"tags": {}})
        with patch("mcrit.client.McritClient.requests.get", return_value=answer):
            self.assertIs(answer, raw.getTags("sample"))


if __name__ == "__main__":
    unittest.main()
