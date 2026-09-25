"""Merge per-chunk ground-truth annotations into one validated corpus.

Annotators work from the source text only and emit ``unit_id``/``type``/``text``.
This tool resolves each span to an exact offset, drops annotations contained in
a longer annotation of the same type, and reports anything it cannot resolve so
a human can decide.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from collections import Counter
from pathlib import Path
from typing import Any

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.document_processor import extract_docx_units

SOURCE = Path(r"C:\Users\Vanshika Munjal\Desktop\Red Herring Prospectus.docx")
VALID_TYPES = {"PERSON", "ORG", "ADDRESS", "EMAIL", "PHONE"}


def _occurrences(text: str, needle: str) -> list[int]:
    positions: list[int] = []
    start = 0
    while True:
        found = text.find(needle, start)
        if found < 0:
            return positions
        positions.append(found)
        start = found + 1


def _resolve(text: str, needle: str, taken: list[tuple[int, int]]) -> int | None:
    """Return the offset of the occurrence that does not collide with ``taken``."""

    options = [pos for pos in _occurrences(text, needle) if (pos, pos + len(needle)) not in taken]
    if len(options) == 1:
        return options[0]
    if not options:
        return None
    # Prefer an occurrence that sits inside a name/address list, i.e. one that is
    # not immediately preceded by sentence punctuation.  If still ambiguous the
    # caller reports it for a human decision.
    for position in options:
        before = text[max(0, position - 3) : position]
        if not re.search(r"[.;:!?]$", before):
            return position
    return options[0]


def _contains_outer(inner: tuple[int, int], outer: tuple[int, int]) -> bool:
    return outer[0] <= inner[0] and inner[1] <= outer[1] and inner != outer


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--chunks", required=True, help="Directory holding gt_*.jsonl")
    parser.add_argument("--output", required=True, help="Merged ground-truth JSON path")
    parser.add_argument("--report", help="Where to write the resolution report")
    parser.add_argument("--source", default=str(SOURCE))
    args = parser.parse_args()

    units = {unit.unit_id: unit.text for unit in extract_docx_units(args.source)}

    raw: list[dict[str, Any]] = []
    for path in sorted(Path(args.chunks).glob("gt_*.jsonl")):
        for number, line in enumerate(
            path.read_text(encoding="utf-8-sig").splitlines(), start=1
        ):
            line = line.strip()
            if not line:
                continue
            try:
                record = json.loads(line)
            except json.JSONDecodeError as error:
                print(f"{path.name}:{number}: invalid JSON: {error}", file=sys.stderr)
                return 2
            record["_source"] = f"{path.name}:{number}"
            raw.append(record)

    unknown_units: list[dict[str, Any]] = []
    bad_types: list[dict[str, Any]] = []
    not_found: list[dict[str, Any]] = []
    annotations: list[dict[str, Any]] = []
    for record in raw:
        unit_id = record.get("unit_id")
        pii_type = record.get("type")
        value = record.get("text")
        if pii_type not in VALID_TYPES:
            bad_types.append(record)
            continue
        if unit_id not in units:
            unknown_units.append(record)
            continue
        if not isinstance(value, str) or not value:
            not_found.append(record)
            continue
        taken = [
            (item["start"], item["end"])
            for item in annotations
            if item["unit_id"] == unit_id and item["type"] == pii_type
        ]
        start = _resolve(units[unit_id], value, taken)
        if start is None:
            not_found.append(record)
            continue
        annotations.append(
            {
                "unit_id": unit_id,
                "type": pii_type,
                "start": start,
                "end": start + len(value),
                "text": value,
            }
        )

    # Drop a short annotation fully contained in a longer one of the same type:
    # annotators occasionally emit both a brand name and its full legal name.
    by_unit: dict[tuple[str, str], list[dict[str, Any]]] = {}
    for item in annotations:
        by_unit.setdefault((item["unit_id"], item["type"]), []).append(item)
    dropped: list[dict[str, Any]] = []
    kept: list[dict[str, Any]] = []
    for items in by_unit.values():
        items.sort(key=lambda item: (item["start"], -(item["end"] - item["start"])))
        for index, item in enumerate(items):
            span = (item["start"], item["end"])
            if any(
                _contains_outer(span, (other["start"], other["end"]))
                for other in items
                if other is not item
            ):
                dropped.append(item)
            else:
                kept.append(item)
    kept.sort(key=lambda item: (item["unit_id"], item["start"], item["end"], item["type"]))

    payload = {
        "document": "Red Herring Prospectus (real document)",
        "source": str(args.source),
        "annotation_policy": "See docs/annotation_policy.md",
        "units": len(units),
        "annotations": kept,
    }
    output_path = Path(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(
        json.dumps(payload, indent=2, ensure_ascii=False) + "\n", encoding="utf-8"
    )

    report = {
        "input_annotations": len(raw),
        "resolved": len(kept),
        "dropped_contained": len(dropped),
        "not_found": [
            {"source": item["_source"], "unit_id": item.get("unit_id"), "type": item.get("type")}
            for item in not_found
        ],
        "unknown_units": [
            {"source": item["_source"], "unit_id": item.get("unit_id")} for item in unknown_units
        ],
        "bad_types": [
            {"source": item["_source"], "type": item.get("type")} for item in bad_types
        ],
        "dropped_examples": [
            {"unit_id": item["unit_id"], "type": item["type"], "text": item["text"]}
            for item in dropped[:40]
        ],
        "counts": dict(Counter(item["type"] for item in kept)),
    }
    if args.report:
        Path(args.report).write_text(
            json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8"
        )
    print(json.dumps({key: value for key, value in report.items() if key != "dropped_examples"}, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
