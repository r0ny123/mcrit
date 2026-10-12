import datetime
import re
from typing import TYPE_CHECKING, Dict, Optional

from mcrit.libs.utility import decode_two_complement, encode_two_complement

if TYPE_CHECKING:  # pragma: no cover
    from smda.common.SmdaReport import SmdaReport


# @dataclass
class SampleEntry:
    family_id: int
    sample_id: int
    architecture: str
    base_addr: int
    binary_size: int
    binweight: float
    bitness: int
    component: str
    family: str
    version: str
    is_library: bool
    filename: str
    sha256: str
    smda_version: str
    summary: Optional[str]
    statistics: Dict[str, int]
    timestamp: Optional[datetime.datetime]

    SHA256_PATTERN = re.compile(r"[0-9a-fA-F]{64}")

    @staticmethod
    def isValidSha256(sha256) -> bool:
        """Whether a sha256 a submission states can identify a sample: 64 hex digits. smda copies the
        field of a report unchecked, and MongoDB reads an object in its place as a query operator."""
        return isinstance(sha256, str) and SampleEntry.SHA256_PATTERN.fullmatch(sha256) is not None

    # TODO -> rename to fromSmdaReport
    def __init__(self, smda_report: Optional["SmdaReport"], sample_id=-1, family_id=0):
        self.sample_id = sample_id
        self.family_id = family_id
        if smda_report:
            self.architecture = smda_report.architecture or ""
            self.base_addr = smda_report.base_addr or 0
            self.binary_size = smda_report.binary_size or 0
            self.binweight = smda_report.binweight or 0
            self.bitness = smda_report.bitness or 0
            self.component = smda_report.component or ""
            self.family = smda_report.family or ""
            self.filename = smda_report.filename or ""
            self.is_library = bool(smda_report.is_library)
            self.sha256 = smda_report.sha256 or ""
            self.smda_version = smda_report.smda_version or ""
            self.statistics = smda_report.statistics.toDict() if smda_report.statistics is not None else {}
            self.timestamp = smda_report.timestamp
            self.version = smda_report.version or ""

    def getShortSha256(self, prefix=8, border=0):
        if border > 0:
            return self.sha256[:border] + "..." + self.sha256[-border:]
        elif prefix > 0:
            return self.sha256[:prefix]
        return self.sha256

    def getShortFilename(self, size_visible=20):
        if len(self.filename) > 2 * size_visible:
            return self.filename[:size_visible] + "..." + self.filename[-size_visible:]
        return self.filename

    def toDict(self):
        sample_entry = {
            "architecture": self.architecture,
            "base_addr": encode_two_complement(self.base_addr),
            "binary_size": self.binary_size,
            "binweight": self.binweight,
            "bitness": self.bitness,
            "component": self.component,
            "family_id": self.family_id,
            "family": self.family,
            "filename": self.filename,
            "is_library": self.is_library,
            "sample_id": self.sample_id,
            "sha256": self.sha256,
            "smda_version": self.smda_version,
            "statistics": self.statistics,
            "timestamp": self.timestamp.strftime("%Y-%m-%dT%H-%M-%S") if self.timestamp is not None else None,
            "version": self.version,
        }
        return sample_entry

    @classmethod
    def fromDict(cls, entry_dict):
        sample_entry = cls(None)
        sample_entry.family_id = entry_dict["family_id"]
        sample_entry.sample_id = entry_dict["sample_id"]
        sample_entry.architecture = entry_dict["architecture"]
        sample_entry.base_addr = decode_two_complement(entry_dict["base_addr"])
        sample_entry.binary_size = entry_dict["binary_size"]
        sample_entry.binweight = entry_dict["binweight"]
        sample_entry.bitness = entry_dict["bitness"]
        sample_entry.component = entry_dict["component"]
        sample_entry.family = entry_dict["family"]
        sample_entry.version = entry_dict["version"]
        sample_entry.is_library = entry_dict["is_library"]
        sample_entry.filename = entry_dict["filename"]
        sample_entry.sha256 = entry_dict["sha256"]
        sample_entry.smda_version = entry_dict["smda_version"]
        # a dict, empty for a report without statistics; an export is data from elsewhere, and
        # statistics of another type it states are read as none
        statistics = entry_dict.get("statistics")
        sample_entry.statistics = statistics if isinstance(statistics, dict) else {}
        sample_entry.timestamp = cls._parseTimestamp(entry_dict.get("timestamp"))
        return sample_entry

    @staticmethod
    def _parseTimestamp(timestamp) -> Optional[datetime.datetime]:
        """The timestamp as toDict writes it, or None for a sample that has none.

        smda reads a report whose timestamp is missing or empty as None, which toDict stores as
        null, and strftime writes a year below 1000 with fewer digits than strptime reads back.
        Every reader of a stored sample - listings, exports, matching, deleteSample, the query
        cleanup - comes through here, so such a value is read as no timestamp instead of failing
        all of them.
        """
        if not timestamp:
            return None
        try:
            return datetime.datetime.strptime(timestamp, "%Y-%m-%dT%H-%M-%S")
        except (TypeError, ValueError):
            return None

    def __str__(self):
        return "Sample {} ({}, {} bit) - {} ({}): ".format(self.sample_id, self.architecture, self.bitness, self.filename, self.family)

    def __hash__(self):
        """Override the default hash behavior"""
        return hash(f"{self.sample_id}_{self.sha256}")
