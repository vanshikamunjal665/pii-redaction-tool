"""Verify the generated DOCX opens, is intact, and no source value survives.

The report deliberately never prints a source value. Residuals are reported by
span shape plus the location where the value still occurs, so the verification
artifact can be shared without disclosing the data it verifies.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from pathlib import Path
from zipfile import ZipFile

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from docx import Document
from docx.opc.constants import RELATIONSHIP_TYPE as RT

from src.document_processor import (
    contains_original_value,
    extract_docx_text,
    extract_docx_units,
)

MAX_LISTED_LOCATIONS = 8


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1 << 20), b""):
            digest.update(block)
    return digest.hexdigest()


def _shape(value: str) -> str:
    """Describe a value's shape without reproducing it."""

    letters = sum(1 for char in value if char.isalpha())
    digits = sum(1 for char in value if char.isdigit())
    if "@" in value:
        kind = "email-shaped value"
    elif letters == 0:
        kind = "numeric value"
    else:
        tokens = [token for token in value.split() if token.strip(".,;:()[]")]
        kind = f"{len(tokens)} token(s)"
    return f"{kind}, {letters} letters, {digits} digits, {len(value)} chars"


def _endpoint(target: str) -> str:
    """Return the scheme/host of a hyperlink target, dropping path and query."""

    match = re.match(r"(?i)^([A-Za-z][A-Za-z0-9+.-]*):(?:/{0,3}([^/?#]*))?", target)
    if match is None:
        return "(unparseable)"
    scheme = match.group(1).lower()
    host = match.group(2) or ""
    host = host.split("@")[-1]
    return f"{scheme}://{host}" if host else f"{scheme}://"


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--input", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--report", required=True)
    args = parser.parse_args()

    input_path = Path(args.input)
    output_path = Path(args.output)
    predictions_path = Path(args.predictions)
    payload = json.loads(predictions_path.read_text(encoding="utf-8"))
    predictions = payload.get("predictions", [])

    output_text = extract_docx_text(output_path)
    with ZipFile(output_path) as package:
        names = package.namelist()
        package_parts = {
            name: package.read(name).decode("utf-8", errors="ignore")
            for name in names
            if name.endswith((".xml", ".rels"))
        }
    joined_package = "\n".join(package_parts.values())

    output_units = extract_docx_units(output_path)
    # Where does a surviving value actually still occur?  Report the output
    # location, not the unit that produced the prediction.  A value laid out
    # across several units is recorded once per fragment, and each fragment
    # carries the same identity, so the check is done on the value: the
    # original entity must be absent, not every piece of it.  Matching is
    # whole-value, so a fragment that also appears inside an ordinary word
    # (``Broad`` inside ``abroad``) is not reported as a leak.
    residual_items: list[dict[str, object]] = []
    seen: set[tuple[str, str]] = set()
    for item in predictions:
        value = item.get("identity") or item["text"]
        key = (item.get("type", "?"), value.casefold())
        if key in seen:
            continue
        in_text = contains_original_value(output_text, value)
        in_package = contains_original_value(joined_package, value)
        if not in_text and not in_package:
            continue
        seen.add(key)
        locations = [
            unit.unit_id
            for unit in output_units
            if contains_original_value(unit.text, value)
        ]
        residual_items.append(
            {
                "type": item.get("type", "?"),
                "shape": _shape(value),
                "is_split_value": bool(item.get("identity")),
                "survives_in_output_text": in_text,
                "survives_in_package_xml": in_package,
                "output_units": locations[:MAX_LISTED_LOCATIONS],
                "output_unit_count": len(locations),
                "package_parts": sorted(
                    name
                    for name, content in package_parts.items()
                    if contains_original_value(content, value)
                )[:MAX_LISTED_LOCATIONS],
            }
        )

    document = Document(str(output_path))
    hyperlink_targets: list[str] = []
    for part in document.part.package.parts:
        for relationship in getattr(part, "rels", {}).values():
            if getattr(relationship, "reltype", "") == RT.HYPERLINK:
                hyperlink_targets.append(getattr(relationship, "target_ref", ""))
    original_emails = {
        item["text"] for item in predictions if item.get("type") == "EMAIL"
    }

    def carries_original_email(blob: str) -> bool:
        return any(contains_original_value(blob, email) for email in original_emails)

    stale_hyperlinks = [
        target for target in hyperlink_targets if carries_original_email(target)
    ]
    # A Word field code (`HYPERLINK "mailto:..."` in w:instrText or a
    # w:fldSimple@w:instr attribute) is invisible to the relationship list but
    # still ships inside the package XML.
    field_code_links = re.findall(r"(?i)HYPERLINK\s+\"([^\"]*)\"", joined_package)
    stale_field_codes = [
        target for target in field_code_links if carries_original_email(target)
    ]

    endpoints = sorted({_endpoint(target) for target in hyperlink_targets})
    result = {
        "input": str(input_path),
        "output": str(output_path),
        "output_reopened": True,
        "input_sha256": _sha256(input_path),
        "output_sha256": _sha256(output_path),
        "paragraph_like_units_checked": len(output_units),
        "prediction_count": len(predictions),
        "distinct_predicted_values": len({(i.get("type"), i["text"]) for i in predictions}),
        "residual_original_value_count": len(residual_items),
        "residual_original_values": residual_items,
        "residual_note": (
            "values are described by shape and location only; no source value is printed"
        ),
        "hyperlink_relationships_checked": len(hyperlink_targets),
        "hyperlink_endpoints": endpoints,
        "stale_original_email_hyperlink_count": len(stale_hyperlinks),
        "stale_original_email_hyperlink_endpoints": sorted(
            {_endpoint(target) for target in stale_hyperlinks}
        ),
        "hyperlink_field_codes_checked": len(field_code_links),
        "stale_original_email_field_code_count": len(stale_field_codes),
        "passed": not residual_items and not stale_hyperlinks and not stale_field_codes,
    }
    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
