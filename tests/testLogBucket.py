#!/usr/bin/python3

import unittest

from mcrit.shinglers.LogBucket import LogBucket
from .context import config  # noqa: F401  (keeps the shared test bootstrap consistent)


class LogBucketTest(unittest.TestCase):
    """Values outside the precomputed table must not abort indexing.

    LogBucket precomputes value -> bucket range for 0..max_value-1. FuzzyStatPairShingler buckets
    max_block_size, num_ins_C, num_ins_S and num_calls through it, and none of those are bounded -
    only stack_size is clamped, at the call site. A real corpus produced a basic block of 108,837
    bytes, and the resulting KeyError propagated out of the hashing pool and killed the whole
    indexing job, leaving the corpus half-hashed.
    """

    MAX_VALUE = 1024

    def setUp(self):
        self.buckets = LogBucket(self.MAX_VALUE, 1)
        # Bounds are read from the table that was actually loaded rather than from MAX_VALUE.
        # LogBucket caches to a file whose name carries none of its parameters, so asking for
        # 1024 can return a table built for 100,000 - asserting against MAX_VALUE here would be
        # asserting against something the class does not promise.
        self.highest = max(self.buckets._value_to_bucket_range)
        self.lowest = min(self.buckets._value_to_bucket_range)

    def testValueAboveTableDoesNotRaise(self):
        # the exact shape that killed indexing: a basic block far larger than the table's top
        self.assertEqual(self.buckets.getLogBucketRange(self.highest * 106), self.buckets.getLogBucketRange(self.highest))

    def testFirstValueOutsideTableDoesNotRaise(self):
        # off-by-one at the boundary: the first key past the top was the one that was missing
        self.assertEqual(self.buckets.getLogBucketRange(self.highest + 1), self.buckets.getLogBucketRange(self.highest))

    def testNegativeValueDoesNotRaise(self):
        self.assertEqual(self.buckets.getLogBucketRange(-1), self.buckets.getLogBucketRange(self.lowest))

    def testValuesInsideTableAreUnchanged(self):
        """The clamp must not move any value that was already defined.

        This is what makes the fix safe to apply to an existing corpus: every MinHash computed
        before it stays computable to the same value, because only previously-raising inputs
        changed behaviour.
        """
        for value in self.buckets._value_to_bucket_range:
            self.assertEqual(self.buckets.getLogBucketRange(value), self.buckets._value_to_bucket_range[value])

    def testClampTargetsAreRealKeys(self):
        """Guards the assumption the clamp relies on: both bounds are present in the table."""
        self.assertIn(self.highest, self.buckets._value_to_bucket_range)
        self.assertIn(self.lowest, self.buckets._value_to_bucket_range)


if __name__ == "__main__":
    unittest.main()
