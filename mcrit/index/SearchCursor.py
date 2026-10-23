import base64
import json
import re
from typing import Any, List, Optional

from mcrit.index.SearchQueryTree import AndNode, NodeType, OrNode, SearchConditionNode

_SORT_SPEC_ENTRY = re.compile(r"-?[A-Za-z_][A-Za-z0-9_.]{0,63}")
_MAX_SORT_FIELDS = 8


def sortSpec(sort_by_list) -> List[str]:
    """The sort a cursor belongs to, as field names; a descending field carries a leading '-'."""
    return [field if is_ascending else "-" + field for field, is_ascending in sort_by_list]


class MinimalSearchCursor:
    """
    Contains the minimum amount of data (when combined with search order info) required to reconstruct a FullSearchCursor.
    """

    record_values: List[Any]
    is_forward_search: bool
    # the sort fields and directions (see sortSpec) the cursor was issued for; None for a cursor of an
    # older server, which only fits a sort by its number of values
    sort_spec: Optional[List[str]]

    def __init__(self):
        self.record_values = []
        self.is_forward_search = True
        self.sort_spec = None

    def toDict(self):
        if self.sort_spec is not None:
            return self.record_values, 1 if self.is_forward_search else 0, self.sort_spec
        result = self.record_values, 1 if self.is_forward_search else 0
        return result

    @classmethod
    def fromDict(cls, data):
        # the cursor comes back from the client and its values go into the storage query as they are,
        # so anything but [[scalar, ...], 0|1] is refused: an object there was a MongoDB query operator
        if not isinstance(data, list) or len(data) not in (2, 3) or not isinstance(data[0], list) or data[1] not in (0, 1):
            raise ValueError("Malformed search cursor.")
        # integers beyond 8 bytes are refused too. Up to 2**64 is kept: a function offset in kernel space
        # (0xffffffff8...) is one, and the memory storage issues it as it is when paging by offset
        if not all(value is None or isinstance(value, (str, float)) or (isinstance(value, int) and -(2**63) <= value < 2**64) for value in data[0]):
            raise ValueError("Malformed search cursor.")
        sort_spec = None
        if len(data) == 3:
            sort_spec = data[2]
            if (
                not isinstance(sort_spec, list)
                or not 0 < len(sort_spec) <= _MAX_SORT_FIELDS
                or not all(isinstance(entry, str) and _SORT_SPEC_ENTRY.fullmatch(entry) for entry in sort_spec)
            ):
                raise ValueError("Malformed search cursor.")
        result = cls()
        result.record_values, result.is_forward_search, result.sort_spec = data[0], bool(data[1]), sort_spec
        return result

    def toStr(self):
        return base64.urlsafe_b64encode(json.dumps(self.toDict()).encode()).decode()
        # return json.dumps(self.toDict())

    @classmethod
    def fromStr(cls, data):
        # return cls.fromDict(json.loads(data))
        if data is not None:
            return cls.fromDict(json.loads(base64.urlsafe_b64decode(data).decode()))


class FullSearchCursor:
    """
    Contains Data to deliver sorted search results after a certain point.
    sort_fields:
        is the list of n fields used for sorting.
        Fields with higher sorting priority come first.
        These fields together should be unique for each db entry.
    sort_directions:
        a list of n booleans corresponding to the n fields.
        True means ascending order, False descending
    record_values:
        the n concrete field values of a record.
        The SearchCursor references those records within the db
        which come either after or before this record.
        This record itself
    is_forward_search:
        if True, the SearchCursor references records after the specified record.
        if False, the SearchCursor references records befor the specified record.
    is_initial_cursor:
        True if record_values contains no meaningful data and the cursor should not exclude any records
    """

    sort_fields: List[str]
    sort_directions: List[bool]
    record_values: List[Any]
    is_forward_search: bool
    is_initial_cursor: bool

    def __init__(self, input_cursor: Optional[MinimalSearchCursor], sort_by_list):
        """
        sort_by_list:
            a list of (sort_field, sort_direction) entries
        """
        self.sort_fields = [sort_info[0] for sort_info in sort_by_list]
        self.sort_directions = [sort_info[1] for sort_info in sort_by_list]
        if input_cursor is not None:
            if len(input_cursor.record_values) != len(self.sort_fields):
                # a cursor holds one value per sort field and only fits the sort order it was issued for
                raise ValueError("The search cursor does not match the requested sort order.")
            if input_cursor.sort_spec is not None and input_cursor.sort_spec != sortSpec(sort_by_list):
                raise ValueError("The search cursor was issued for another sort order.")
            self.record_values = input_cursor.record_values
            self.is_forward_search = input_cursor.is_forward_search
            self.is_initial_cursor = False
        else:
            self.record_values = []
            self.is_forward_search = True
            self.is_initial_cursor = True

    @property
    def sort_by_list(self):
        return zip(self.sort_fields, self.sort_directions)

    def toTree(self):
        def get_operator(i):
            direction = self.sort_directions[i] ^ (not self.is_forward_search)
            return ">" if direction else "<"

        if self.is_initial_cursor:
            return AndNode([])

        # condition has form (a > a0) or (a = a0 and b>b0) or (a=a0 and b=b0 and c>c0)...
        # A missing value (None) sorts before every other one, but no comparison with it holds, so
        # "after None" is "not None", nothing is "before None", and "before a0" includes None. The
        # last sort field is the id, which is never None.
        conditions = []
        for inner_condition_length in range(1, len(self.sort_fields) + 1):
            inner_condition: List[NodeType] = []
            for i in range(inner_condition_length - 1):
                inner_condition.append(SearchConditionNode(self.sort_fields[i], "=", self.record_values[i]))
            last = inner_condition_length - 1
            field, value, operator = self.sort_fields[last], self.record_values[last], get_operator(last)
            if value is None:
                if operator == "<":
                    continue
                inner_condition.append(SearchConditionNode(field, "!=", None))
            elif operator == "<" and last < len(self.sort_fields) - 1:
                inner_condition.append(OrNode([SearchConditionNode(field, "<", value), SearchConditionNode(field, "=", None)]))
            else:
                inner_condition.append(SearchConditionNode(field, operator, value))
            conditions.append(AndNode(inner_condition))

        if not conditions:
            # only a cursor naming None for the id gets here, and no record comes after it; an
            # empty OR would match everything on MongoDB, so ask for the id no record has
            return SearchConditionNode(self.sort_fields[-1], "=", None)
        return OrNode(conditions)
