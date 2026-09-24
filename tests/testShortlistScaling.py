#!/usr/bin/python3

import unittest
from typing import Dict, Iterable, Optional

from mcrit.matchers.MatcherInterface import MatcherInterface


class RecordingStorage:
    """Minimal stand-in that records how getSampleFunctionCounts was asked."""

    def __init__(self, corpus_size):
        self.corpus_size = corpus_size
        self.calls = []

    def getSampleFunctionCounts(self, sample_ids: Optional[Iterable[int]] = None) -> Dict[int, int]:
        self.calls.append(None if sample_ids is None else sorted(int(s) for s in sample_ids))
        if sample_ids is None:
            # what a whole-corpus answer would cost: one entry per sample that exists
            return {sample_id: 10 for sample_id in range(self.corpus_size)}
        return {int(sample_id): 10 for sample_id in sample_ids}


class LegacyStorage:
    """A storage from before the argument existed, to prove the fallback still works."""

    def __init__(self, corpus_size):
        self.corpus_size = corpus_size

    def getSampleFunctionCounts(self) -> Dict[int, int]:
        return {sample_id: 10 for sample_id in range(self.corpus_size)}


class ShortlistScalingTest(unittest.TestCase):
    """Ranking the shortlist must not read the whole corpus.

    _rankShortlist needs a function count per *candidate* to rank by coverage. It used to ask for
    the counts of every sample in the corpus, which is invisible at the sizes benchmarked here
    (a few thousand entries) and fatal at the sizes this work is aimed at: the map is built once
    per matching job, so at 10^9 samples it is a 10^9-entry dict per query. The votes are what
    bound the work, and there are at most a few thousand of those.
    """

    @staticmethod
    def _matcher(storage):
        matcher = MatcherInterface.__new__(MatcherInterface)
        matcher._storage = storage
        return matcher

    def testAsksOnlyForVotedSamples(self):
        storage = RecordingStorage(corpus_size=1000000)
        matcher = self._matcher(storage)
        votes = {7: 5, 11: 3, 42: 1}
        matcher._rankShortlist(votes, shortlist_size=2)
        self.assertEqual(len(storage.calls), 1)
        self.assertEqual(storage.calls[0], [7, 11, 42], "must ask for exactly the voted samples")

    def testDoesNotScaleWithCorpusSize(self):
        """The same votes against a corpus 1000x larger must ask for the same thing.

        Asserting the two agree is not enough on its own - a whole-corpus request is `None` in
        both cases and would compare equal, so the check would pass against the very code it is
        meant to catch. The request must also name the voted samples.
        """
        small = RecordingStorage(corpus_size=1000)
        large = RecordingStorage(corpus_size=1000000)
        votes = {3: 2, 9: 7}
        self._matcher(small)._rankShortlist(votes, shortlist_size=2)
        self._matcher(large)._rankShortlist(votes, shortlist_size=2)
        self.assertEqual(small.calls, large.calls)
        self.assertEqual(small.calls, [[3, 9]], "must name the voted samples, not ask for everything")

    def testStillRanksByCoverageAndCount(self):
        """The cheaper lookup must not change which samples survive.

        Sample 1 has few votes but owns few functions (high coverage); sample 2 has more votes
        against many functions. Both rankings contribute, so both survive a shortlist of two.
        """

        class Counts(RecordingStorage):
            def getSampleFunctionCounts(self, sample_ids=None):
                super().getSampleFunctionCounts(sample_ids)
                return {1: 2, 2: 1000, 3: 1000}

        matcher = self._matcher(Counts(corpus_size=3))
        shortlist = matcher._rankShortlist({1: 2, 2: 5, 3: 1}, shortlist_size=2)
        self.assertIn(2, shortlist, "the highest vote count must survive")
        self.assertIn(1, shortlist, "the highest coverage must survive")
        self.assertNotIn(3, shortlist)

    def testFallsBackForStorageWithoutTheArgument(self):
        matcher = self._matcher(LegacyStorage(corpus_size=50))
        shortlist = matcher._rankShortlist({4: 2, 9: 1}, shortlist_size=2)
        self.assertEqual(shortlist, {4, 9})


if __name__ == "__main__":
    unittest.main()
