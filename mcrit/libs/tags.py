"""Tags on families, samples and functions (#53).

A tag is a short lower-case label - ``packed``, ``reviewed``, ``source:vt`` - that an analyst
attaches to an entity. Stored tags are always normalised and valid, so every writer goes through
normalizeTags, and the search and the distinct-tag listing can compare them as plain strings.
"""

import re
from typing import Any, List

# the entities that carry tags, as the REST API and McritClient name them
TAG_ENTITIES = ("family", "sample", "function")
# a letter or digit first, so a tag can neither start an operator ("$", "-") nor be blank;
# the colon allows namespaced tags such as "source:vt"
TAG_PATTERN = re.compile(r"^[a-z0-9][a-z0-9 ._:\-]{0,63}$")
TAG_RULE = "a tag is 1-64 letters, digits, spaces, dots, colons, underscores or dashes, starting with a letter or digit, and is stored lower-cased"


def normalizeTag(tag: str) -> str:
    """A tag as stored: stripped and lower-cased. Does not validate, see isValidTag."""
    return tag.strip().lower()


def isValidTag(tag) -> bool:
    """True for a string that is a valid tag once normalised."""
    return isinstance(tag, str) and TAG_PATTERN.fullmatch(normalizeTag(tag)) is not None


def normalizeTags(tags: Any, drop_invalid: bool = False) -> List[str]:
    """Tags as stored: normalised, each once, in the order given.

    Raises ValueError when tags is not a list (or tuple/set) of strings or any of them is invalid,
    naming the offending value; with drop_invalid=True those are skipped instead, for data that
    arrives from elsewhere (an import) and should not fail as a whole over one bad tag.
    """
    if isinstance(tags, (str, bytes)) or not isinstance(tags, (list, tuple, set)):
        if drop_invalid:
            return []
        raise ValueError(f"tags must be a list of strings, not {type(tags).__name__}.")
    normalized: List[str] = []
    for tag in tags:
        if not isValidTag(tag):
            if drop_invalid:
                continue
            raise ValueError(f"invalid tag {tag!r}: {TAG_RULE}.")
        tag = normalizeTag(tag)
        if tag not in normalized:
            normalized.append(tag)
    return normalized


def checkTagEntity(entity: str) -> str:
    """The entity if it is one that carries tags, otherwise a ValueError naming the valid ones."""
    if entity not in TAG_ENTITIES:
        raise ValueError(f"entity must be one of {', '.join(TAG_ENTITIES)}, not {entity!r}.")
    return entity
