"""#53: tags on families, samples and functions."""

import json
import logging
import os
import unittest

import pymongo
import pytest
from smda.common.SmdaReport import SmdaReport

from mcrit.config.McritConfig import McritConfig
from mcrit.config.StorageConfig import StorageConfig
from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.libs.tags import isValidTag, normalizeTags
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


if __name__ == "__main__":
    unittest.main()
