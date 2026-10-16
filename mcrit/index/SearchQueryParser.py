"""Search query parser

version 2022-08-08

This search query parser uses the excellent Pyparsing module
(http://pyparsing.sourceforge.net/) to parse search queries by users.
It handles:

* 'and', 'or' and implicit 'and' operators;
* parentheses;
* quoted strings;
* <field>:<value>
* <field>:<operator><value> for the following operators:
    <, <=, >, >=, =, !=, ? (search in a single field), !?


Requirements:
* Python
* Pyparsing


This work is based on
https://github.com/pyparsing/pyparsing/blob/master/examples/searchparser.py
and modified by Manuel Blatt, 2022
The original license can be found below.

-------------------------------------------------------------------------------
Copyright (c) 2006, Estrate, the Netherlands
All rights reserved.

Redistribution and use in source and binary forms, with or without modification,
are permitted provided that the following conditions are met:

* Redistributions of source code must retain the above copyright notice, this
  list of conditions and the following disclaimer.
* Redistributions in binary form must reproduce the above copyright notice,
  this list of conditions and the following disclaimer in the documentation
  and/or other materials provided with the distribution.
* Neither the name of Estrate nor the names of its contributors may be used
  to endorse or promote products derived from this software without specific
  prior written permission.

THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND
ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT OWNER OR CONTRIBUTORS BE LIABLE FOR
ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
(INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON
ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
(INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.

CONTRIBUTORS:
- Steven Mooij
- Rudolph Froger
- Paul McGuire
-------------------------------------------------------------------------------

"""

from functools import lru_cache
from string import whitespace

from pyparsing import (
    CharsNotIn,
    Forward,
    Group,
    Keyword,
    ParseBaseException,
    QuotedString,
    StringEnd,
    Suppress,
    Word,
    ZeroOrMore,
    identbodychars,
    identchars,
    one_of,
)

from mcrit.index.SearchQueryTree import AndNode, NodeType, NotNode, OrNode, SearchConditionNode, SearchTermNode


class SearchQueryParser:
    # bounds the parse time, which grows with the query's length; it is set above what the grammar
    # accepted before AND/OR became loops (about 120 OR'd terms, about 9,000 characters as sha256 terms)
    MAX_QUERY_LENGTH = 16384

    def __init__(self):
        self._methods = {
            "and": self._build_tree_and,
            "or": self._build_tree_or,
            "not": self._build_tree_not,
            "parenthesis": self._build_tree_parenthesis,
            "one_filter": self._build_tree_one_filter,
        }
        self._parser = self._get_parser()

    def _get_parser(self):
        # no esc_quote: the escape character already covers an escaped quote, and offering both made
        # the generated regex match every \" two ways, so an unterminated "\"\"\"... took 2^n steps
        search_term = QuotedString('"', esc_char="\\") | QuotedString("'", esc_char="\\") | ZeroOrMore(Suppress(whitespace)) + CharsNotIn(whitespace + "()")
        identifier = Word(identchars, identbodychars + ".")
        operator = one_of("< <= > >= = != ? !?")
        condition_compare = identifier + (":" + operator + search_term).leave_whitespace()
        condition_equal = identifier + (":" + search_term).leave_whitespace()
        one_filter = Group(condition_compare | condition_equal | search_term).set_results_name("one_filter")

        # The grammar must never parse the same input twice: without memoisation every retried
        # alternative multiplies the work of everything nested inside it, so a few unbalanced
        # parentheses kept a request thread busy for minutes. AND and OR chains are therefore
        # loops instead of alternatives that start with the same operand, and NOT commits to its
        # operand: a NOT followed by anything but the end of the query or ")" is never re-read as
        # a search term, as that could only ever fail again on the same operand.
        operatorOr = Forward()

        operatorParenthesis = Group(Suppress("(") + operatorOr + Suppress(")")).set_results_name("parenthesis") | one_filter

        operatorNot = Forward()
        operatorNot << (Group(Suppress(Keyword("NOT")) + ~(StringEnd() | ")") - operatorNot).set_results_name("not") | operatorParenthesis)

        operatorAnd = Group(operatorNot + ZeroOrMore(Suppress(Keyword("AND")) + operatorNot | ~one_of("AND OR") + operatorNot)).set_results_name("and")

        operatorOr << Group(operatorAnd + ZeroOrMore(Suppress(Keyword("OR")) + operatorAnd)).set_results_name("or")

        parser = operatorOr + StringEnd()
        return parser

    def _build_tree_or(self, argument) -> NodeType:
        children = [self._build_tree(child) for child in argument]
        if len(children) == 1:
            return children[0]
        return OrNode(children)

    def _build_tree_and(self, argument) -> NodeType:
        children = [self._build_tree(child) for child in argument]
        if len(children) == 1:
            return children[0]
        return AndNode(children)

    def _build_tree_parenthesis(self, argument) -> NodeType:
        assert len(argument) == 1
        return self._build_tree(argument[0])

    def _build_tree_not(self, argument) -> NodeType:
        assert len(argument) == 1
        return NotNode(self._build_tree(argument[0]))

    def _build_tree_one_filter(self, argument) -> NodeType:
        if len(argument) == 1:
            return SearchTermNode(argument[0])
        if len(argument) == 3:
            return SearchConditionNode(argument[0], "", argument[-1])
        if len(argument) == 4:
            return SearchConditionNode(argument[0], argument[-2], argument[-1])
        raise ValueError()

    def _build_tree(self, argument) -> NodeType:
        return self._methods[argument.getName()](argument)

    @lru_cache(maxsize=100)
    def parse(self, string: str) -> NodeType:
        if string.strip(whitespace) == "":
            return AndNode([])
        if len(string) > self.MAX_QUERY_LENGTH:
            raise ValueError(f"Could not parse search query: it is longer than {self.MAX_QUERY_LENGTH} characters")
        try:
            raw_result = self._parser.parse_string(string)
        except ParseBaseException as parse_error:
            # an unbalanced parenthesis or a dangling operator is bad input, not a server fault -
            # report it as a ValueError, which is what the REST layer already answers with a 400.
            # pyparsing's message names the offending character and its offset, so it is worth keeping.
            raise ValueError(f"Could not parse search query: {parse_error}") from parse_error
        except RecursionError as recursion_error:
            # every parenthesis and NOT nests the parse one level deeper, and Python's stack ends somewhere
            raise ValueError("Could not parse search query: it is nested too deeply") from recursion_error
        assert len(raw_result) == 1
        result = self._build_tree(raw_result[0])
        return result
