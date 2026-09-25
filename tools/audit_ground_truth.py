"""Cross-check ground truth against predictions without echoing values.

Emails and phone numbers are objective, so their coverage can be checked
mechanically: every value-shaped occurrence in the source must be annotated.
The report describes each gap by category, location and shape so a reviewer can
open the unit and decide, without this tool printing a single source value.
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

EMAIL_RE = re.compile(r"(?<![\w.+-])[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
PHONE_RE = re.compile(
    r"(?<![\w+])\+?\d[\d\s()+-]{6,}\d(?![\w])",
)


def shape(value: str) -> str:
    letters = sum(1 for char in value if char.isalpha())
    digits = sum(1 for char in value if char.isdigit())
    if "@" in value:
        kind = "email-shaped"
    elif letters == 0:
        kind = "numeric"
    else:
        kind = f"{len(value.split())} token(s)"
    return f"{kind}, {letters} letters, {digits} digits, {len(value)} chars"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--output", required=True)
    args = parser.parse_args()

    units = {unit.unit_id: unit.text for unit in extract_docx_units(args.source)}
    truth = json.loads(Path(args.ground_truth).read_text(encoding="utf-8"))["annotations"]
    predictions = json.loads(Path(args.predictions).read_text(encoding="utf-8"))["predictions"]

    truth_by_unit: dict[str, list[dict[str, Any]]] = {}
    for item in truth:
        truth_by_unit.setdefault(item["unit_id"], []).append(item)

    def covered(unit_id: str, start: int, end: int, pii_type: str) -> bool:
        return any(
            item["type"] == pii_type and item["start"] < end and start < item["end"]
            for item in truth_by_unit.get(unit_id, [])
        )

    # 1. Mechanical sweep: every email-shaped / phone-shaped run in the source.
    gaps: dict[str, list[dict[str, Any]]] = {"EMAIL": [], "PHONE": []}
    for unit_id, text in units.items():
        for match in EMAIL_RE.finditer(text):
            if not covered(unit_id, match.start(), match.end(), "EMAIL"):
                gaps["EMAIL"].append(
                    {"unit_id": unit_id, "shape": shape(match.group(0))}
                )
        for match in PHONE_RE.finditer(text):
            value = match.group(0).strip()
            if not re.search(r"\d{3}", re.sub(r"\D", "", value)):
                continue
            if not covered(unit_id, match.start(), match.end(), "PHONE"):
                gaps["PHONE"].append(
                    {"unit_id": unit_id, "shape": shape(value)}
                )

    # 2. Predictions with no matching annotation.
    unmatched: list[dict[str, Any]] = []
    for item in predictions:
        unit_text = units.get(item["part"], "")
        start = unit_text.find(item["text"])
        if start < 0:
            unmatched.append(
                {
                    "type": item["type"],
                    "part": item["part"],
                    "detector": item["detector"],
                    "reason": "span not found in source unit (cross-unit fragment?)",
                    "shape": shape(item.get("identity") or item["text"]),
                }
            )
            continue
        if not covered(item["part"], start, start + len(item["text"]), item["type"]):
            unmatched.append(
                {
                    "type": item["type"],
                    "part": item["part"],
                    "detector": item["detector"],
                    "reason": "no annotation overlaps this span",
                    "shape": shape(item["text"]),
                }
            )

    # 3. Annotations with no overlapping prediction: these are detector misses.
    predictions_by_unit: dict[str, list[dict[str, Any]]] = {}
    for item in predictions:
        predictions_by_unit.setdefault(item["part"], []).append(item)
    missed: list[dict[str, Any]] = []
    for item in truth:
        unit_text = units[item["unit_id"]]
        start = unit_text.find(item["text"])
        if start < 0:
            continue
        span = (start, start + len(item["text"]))
        hit = any(
            prediction["type"] == item["type"]
            and prediction["start"] < span[1]
            and span[0] < prediction["end"]
            for prediction in predictions_by_unit.get(item["unit_id"], [])
        )
        if not hit:
            missed.append(
                {
                    "type": item["type"],
                    "unit_id": item["unit_id"],
                    "shape": shape(item["text"]),
                }
            )

    result = {
        "ground_truth_counts": dict(Counter(item["type"] for item in truth)),
        "prediction_counts": dict(Counter(item["type"] for item in predictions)),
        "email_shape_not_annotated": len(gaps["EMAIL"]),
        "email_shape_not_annotated_units": sorted(
            {item["unit_id"] for item in gaps["EMAIL"]}
        ),
        "phone_shape_not_annotated": len(gaps["PHONE"]),
        "phone_shape_not_annotated_units": sorted(
            {item["unit_id"] for item in gaps["PHONE"]}
        ),
        "unmatched_predictions": len(unmatched),
        "unmatched_predictions_by_type": dict(
            Counter(item["type"] for item in unmatched)
        ),
        "unmatched_prediction_units": sorted({item["part"] for item in unmatched}),
        "missed_annotations": len(missed),
        "missed_annotations_by_type": dict(Counter(item["type"] for item in missed)),
        "missed_annotation_units": sorted({item["unit_id"] for item in missed}),
    }
    Path(args.output).write_text(
        json.dumps(
            {
                **result,
                "unmatched_prediction_detail": unmatched,
                "missed_annotation_detail": missed,
            },
            indent=2,
            ensure_ascii=False,
        ),
        encoding="utf-8",
    )
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
