import signal
import time
import unittest
from contextlib import contextmanager

from mcrit.index.MinHashIndex import MinHashIndex
from mcrit.index.SearchQueryParser import SearchQueryParser
from mcrit.index.SearchQueryTree import AndNode, OrNode

from .context import config

# what the grammar answered before it was made backtracking-free, as repr of the parsed tree
KNOWN_TREES = {
    "a b c": "And(Search('a'), Search('b'), Search('c'))",
    "a AND b c OR d e AND f": "Or(And(Search('a'), Search('b'), Search('c')), And(Search('d'), Search('e'), Search('f')))",
    "a OR b AND c OR d": "Or(Search('a'), And(Search('b'), Search('c')), Search('d'))",
    "NOT (a OR b) AND NOT c": "And(Not(Or(Search('a'), Search('b'))), Not(Search('c')))",
    "(a OR b) c": "And(Or(Search('a'), Search('b')), Search('c'))",
    "NOT": "Search('NOT')",
    "a NOT": "And(Search('a'), Search('NOT'))",
    "NOT NOT a": "Not(Not(Search('a')))",
    "NOT AND": "Not(Search('AND'))",
    "x:NOT (a)": "And(Condition('x' : 'NOT'), Search('a'))",
    "family:foo AND NOT bar": "And(Condition('family' : 'foo'), Not(Search('bar')))",
    "offset:>=0x100 num_blocks:<5": "And(Condition('offset' >= '0x100'), Condition('num_blocks' < '5'))",
    "\"a b\" OR 'c d'": "Or(Search('a b'), Search('c d'))",
    '"say \\"hi\\""': "Search('say \"hi\"')",
    "a (b (c d) e) f": "And(Search('a'), Search('b'), Search('c'), Search('d'), Search('e'), Search('f'))",
    "(a)(b)": "And(Search('a'), Search('b'))",
}


@contextmanager
def deadline(seconds):
    """Fails the test instead of letting a parser that backtracks again run for minutes."""

    def on_alarm(signum, frame):
        raise AssertionError(f"still parsing after {seconds} s")

    previous = signal.signal(signal.SIGALRM, on_alarm)
    signal.alarm(seconds)
    try:
        yield
    finally:
        signal.alarm(0)
        signal.signal(signal.SIGALRM, previous)


class SearchQueryNestingTestSuite(unittest.TestCase):
    """The search grammar retried alternatives that began with the same operand, so every unbalanced
    parenthesis multiplied the parse time by five to eight: '((((((a' held a request thread for 50 s
    before it was answered 400, and four such GETs stalled every thread of the server"""

    def assertParsesQuickly(self, query, is_valid):
        parser = SearchQueryParser()
        started = time.monotonic()
        with deadline(10):
            if is_valid:
                parser.parse(query)
            else:
                with self.assertRaises(ValueError):
                    parser.parse(query)
        # the grammar before took minutes for any of these, and now takes milliseconds
        self.assertLess(time.monotonic() - started, 2, query)

    def testTreesAreUnchanged(self):
        parser = SearchQueryParser()
        for query, tree in KNOWN_TREES.items():
            with self.subTest(query=query):
                self.assertEqual(tree, repr(parser.parse(query)))

    def testNestingCostsLinearTime(self):
        for depth in (8, 16, 24):
            with self.subTest(depth=depth):
                self.assertParsesQuickly("(" * depth + "a", is_valid=False)
                self.assertParsesQuickly("(" * depth + "a" + ")" * depth, is_valid=True)
                self.assertParsesQuickly("(NOT " * depth + "a", is_valid=False)
                self.assertParsesQuickly("(NOT " * depth + "a" + ")" * depth, is_valid=True)
                self.assertParsesQuickly("a (b " * depth + "c", is_valid=False)
                self.assertParsesQuickly("a OR (a " * depth + "c" + ")" * depth, is_valid=True)

    def testUnterminatedEscapedQuotesCostLinearTime(self):
        # \" matched both as an escaped quote and as an escaped character: 2^n ways to fail
        for quote in ('"', "'"):
            with self.subTest(quote=quote):
                self.assertParsesQuickly(quote + ("\\" + quote) * 40 + "x", is_valid=True)

    def testLongChainsParse(self):
        # the right-recursive grammar ran out of stack at about a hundred terms (a 500)
        terms = ["t%d" % index for index in range(300)]
        for separator in (" ", " AND ", " OR "):
            with self.subTest(separator=separator):
                tree = SearchQueryParser().parse(separator.join(terms))
                assert isinstance(tree, (AndNode, OrNode))
                self.assertEqual(300, len(tree.children))

    def testOverlongAndOverdeepQueriesAreValueErrors(self):
        parser = SearchQueryParser()
        for query in ("(" * 500 + "a" + ")" * 500, "NOT " * 500 + "a", "a " * SearchQueryParser.MAX_QUERY_LENGTH):
            with self.subTest(query=query[:20]):
                started = time.monotonic()
                with deadline(10), self.assertRaises(ValueError):
                    parser.parse(query)
                self.assertLess(time.monotonic() - started, 2)

    def testDeepQueryIsAnsweredAsBadInput(self):
        # ValueError is what StatusResource._respond_search answers with a 400
        index = MinHashIndex(config)
        for search in (index.getFamilySearchResults, index.getSampleSearchResults, index.getFunctionSearchResults):
            with self.subTest(search=search.__name__):
                started = time.monotonic()
                with deadline(10), self.assertRaises(ValueError):
                    search("((((((((a")
                self.assertLess(time.monotonic() - started, 2)


if __name__ == "__main__":
    unittest.main()
