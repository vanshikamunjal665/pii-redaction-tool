"""Shared data models for detection, replacement, and evaluation."""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any, Optional


class PIIType(str, Enum):
    """PII categories supported by the tool."""

    PERSON = "PERSON"
    EMAIL = "EMAIL"
    PHONE = "PHONE"
    ORG = "ORG"
    ADDRESS = "ADDRESS"
    SSN = "SSN"
    CREDIT_CARD = "CREDIT_CARD"
    DOB = "DOB"
    IP = "IP"


SUPPORTED_TYPES: tuple[PIIType, ...] = (
    PIIType.PERSON,
    PIIType.EMAIL,
    PIIType.PHONE,
    PIIType.ORG,
    PIIType.ADDRESS,
    PIIType.SSN,
    PIIType.CREDIT_CARD,
    PIIType.DOB,
    PIIType.IP,
)


@dataclass(frozen=True)
class Entity:
    """A detected entity and its offsets within one text unit.

    Offsets are zero-based, end-exclusive character offsets in the text unit
    passed to the detector.  ``part`` and ``context`` are retained for
    evaluation and diagnostics, but are not required by the core detector.
    """

    text: str
    pii_type: PIIType
    start: int
    end: int
    part: str = "body"
    context: str = ""
    score: float = 1.0
    detector: str = "regex"
    # Optional document-level identity used when one logical value is laid out
    # across two or more text units.  A fragment such as ``Distriparks`` is not
    # a value on its own, so residual verification checks the identity: the
    # original value must be absent, not every piece of it.
    identity: Optional[str] = None

    def as_dict(self) -> dict[str, Any]:
        """Return a JSON-serialisable representation."""

        return {
            "text": self.text,
            "type": self.pii_type.value,
            "start": self.start,
            "end": self.end,
            "part": self.part,
            "context": self.context,
            "score": self.score,
            "detector": self.detector,
            "identity": self.identity,
        }


@dataclass(frozen=True)
class TextUnit:
    """A logical paragraph-like unit extracted from a document part."""

    part: str
    unit_id: str
    text: str

    def as_dict(self) -> dict[str, Any]:
        return {"part": self.part, "unit_id": self.unit_id, "text": self.text}
