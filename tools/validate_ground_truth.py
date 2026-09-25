"""Check that fixture ground-truth spans really occur in the source DOCX."""

from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.document_processor import extract_docx_units


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--source", required=True)
    parser.add_argument("--ground-truth", required=True)
    args = parser.parse_args()
    payload = json.loads(Path(args.ground_truth).read_text(encoding="utf-8"))
    units = {unit.unit_id: unit.text for unit in extract_docx_units(args.source)}
    errors: list[dict[str, object]] = []
    for annotation in payload["annotations"]:
        text = units.get(annotation["unit_id"])
        if text is None:
            errors.append({"annotation": annotation, "error": "unit not found"})
        elif text[annotation["start"] : annotation["end"]] != annotation["text"]:
            errors.append(
                {
                    "annotation": annotation,
                    "error": "span text mismatch",
                    "actual": text[annotation["start"] : annotation["end"]],
                }
            )
    counts = dict(Counter(item["type"] for item in payload["annotations"]))
    result = {
        "source": str(args.source),
        "annotation_count": len(payload["annotations"]),
        "unit_count": len(units),
        "counts": counts,
        "errors": errors,
        "passed": not errors,
    }
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
