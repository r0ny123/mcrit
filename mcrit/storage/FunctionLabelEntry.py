import datetime
import re
from typing import Optional

# what PUT /functions/{id} accepts as a name, and so as a label
_VALID_LABEL = re.compile(r"[ -~]{1,256}")
# names smda makes up for functions it has no symbol for
_GENERATED_NAME = re.compile(r"sub_[a-fA-F0-9]{1,16}")


class FunctionLabelEntry:
    # MCRIT specific
    function_id: Optional[int]
    function_label: str
    username: str
    timestamp: datetime.datetime

    def __init__(self, function_label: str, username: str, function_id: Optional[int] = None, timestamp: Optional[datetime.datetime] = None) -> None:
        self.function_label = function_label
        self.username = username
        self.function_id = function_id
        self.timestamp = timestamp if timestamp is not None else datetime.datetime.now(datetime.UTC).replace(tzinfo=None)

    @staticmethod
    def labelFromReport(function_name, checked: bool = False) -> Optional[str]:
        """The label a submitted report's function name gives, or None for no label.

        A name smda generated says nothing and gives no label. With checked, the name is held to what
        PUT /functions/{id} accepts, 1 to 256 printable ASCII characters once stripped: a report for
        a sample that exists already labels functions that may well be someone else's. The first
        report of a sample keeps every name its disassembly found, long and non-ASCII ones included.
        """
        if not isinstance(function_name, str) or not function_name or _GENERATED_NAME.match(function_name):
            return None
        if not checked:
            return function_name
        label = function_name.strip()
        return label if _VALID_LABEL.fullmatch(label) else None

    def setFunctionId(self, function_id):
        self.function_id = function_id

    def toDict(self):
        function_entry = {
            "function_label": self.function_label,
            "username": self.username,
            "timestamp": self.timestamp.strftime("%Y-%m-%dT%H:%M:%S"),
        }
        return function_entry

    @classmethod
    def fromDict(cls, entry_dict):
        function_label_entry = cls("", "")
        function_label_entry.function_label = entry_dict["function_label"]
        # function_entry.function_id = entry_dict["function_id"]
        function_label_entry.username = entry_dict["username"]
        function_label_entry.function_id = entry_dict["function_id"] if "function_id" in entry_dict else None
        function_label_entry.timestamp = datetime.datetime.strptime(entry_dict["timestamp"], "%Y-%m-%dT%H:%M:%S")
        return function_label_entry

    def __str__(self):
        return f"FunctionLabel: '{self.function_label}' -- by user: {self.username}"
