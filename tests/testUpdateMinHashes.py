#!/usr/bin/python3

import logging
import os
import unittest
from copy import deepcopy

from smda.common.SmdaReport import SmdaReport

from mcrit.index.MinHashIndex import MinHashIndex

from .context import config

LOG = logging.getLogger(__name__)
logging.disable(logging.CRITICAL)

THIS_FILE_PATH = str(os.path.abspath(__file__))
PROJECT_ROOT = str(os.path.abspath(os.sep.join([THIS_FILE_PATH, "..", ".."])))
EXAMPLE_REPORT = os.sep.join([PROJECT_ROOT, "tests", "example_report.smda"])


class UpdateMinHashesTest(unittest.TestCase):
    """Worker.updateMinHashes has to survive having nothing to do, and count every batch.

    Both defects showed up on a real indexing run. The job hashes in workpacks, and `minhashes`
    was only ever bound inside the batch loop:

      * with no unhashed functions left the loop body never ran, so `return len(minhashes)` raised
        UnboundLocalError - finishing successfully failed indistinguishably from crashing. This is
        the normal state of a resumed index, where a previous pass already cleared the backlog.
      * the return value was the size of the *last* batch rather than the total, so any run longer
        than one workpack under-reported. Every caller reads it as a total: recalculateMinHashes
        assigns it to `num_updated`, and updateMinHashesForSample substitutes 0 for a sample with
        no functions.
    """

    @classmethod
    def setUpClass(cls):
        with open(EXAMPLE_REPORT, "r") as handle:
            cls.report = SmdaReport.fromDict(__import__("json").load(handle))

    def _freshIndex(self, workpack_size=None):
        index_config = deepcopy(config)
        if workpack_size is not None:
            index_config.MINHASH_CONFIG.MINHASH_GENERATION_WORKPACK_SIZE = workpack_size
        index = MinHashIndex(config=index_config)
        index._storage.clearStorage()
        return index

    def testReturnsZeroWhenThereIsNothingToHash(self):
        """The regression: an empty corpus has no unhashed functions, so the loop never runs."""
        index = self._freshIndex()
        worker = index.queue._worker
        self.assertEqual(worker.updateMinHashes(None), 0)

    def testReturnsZeroWhenEverythingIsAlreadyHashed(self):
        """The shape that actually broke the indexer: a resumed run with the backlog cleared."""
        index = self._freshIndex()
        worker = index.queue._worker
        index._storage.addSmdaReport(self.report)
        first = worker.updateMinHashes(None)
        self.assertGreater(first, 0, "the report should have produced hashable functions")
        # second pass has nothing left to do and must report that rather than raise
        self.assertEqual(worker.updateMinHashes(None), 0)

    def testCountsEveryBatchNotJustTheLast(self):
        """With a workpack smaller than the corpus, the total must exceed one batch."""
        index = self._freshIndex(workpack_size=1)
        worker = index.queue._worker
        index._storage.addSmdaReport(self.report)
        num_updated = worker.updateMinHashes(None)
        self.assertGreater(num_updated, 1, "a one-function workpack must still total every batch")
        # and it must equal what a single-batch run of the same corpus reports
        index_single = self._freshIndex(workpack_size=100000)
        worker_single = index_single.queue._worker
        index_single._storage.addSmdaReport(self.report)
        self.assertEqual(num_updated, worker_single.updateMinHashes(None))


if __name__ == "__main__":
    unittest.main()
