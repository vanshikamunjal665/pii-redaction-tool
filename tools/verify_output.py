"""Verify the generated DOCX can be opened and known source values are gone."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from zipfile import ZipFile

if __package__ in {None, ""}:
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from docx import Document
from docx.opc.constants import RELATIONSHIP_TYPE as RT

from src.document_processor import extract_docx_text, extract_docx_units


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
    lowered = output_text.casefold()
    text_residual = sorted(
        {item["text"] for item in predictions if item["text"].casefold() in lowered}
    )
    with ZipFile(output_path) as package:
        package_text = "\n".join(
            package.read(name).decode("utf-8", errors="ignore")
            for name in package.namelist()
            if name.endswith((".xml", ".rels"))
        )
    package_residual = sorted(
        {
            item["text"]
            for item in predictions
            if item["text"].casefold() in package_text.casefold()
        }
    )
    residual = sorted(set(text_residual) | set(package_residual))

    document = Document(str(output_path))
    hyperlink_targets: list[str] = []
    for part in document.part.package.parts:
        for relationship in getattr(part, "rels", {}).values():
            if getattr(relationship, "reltype", "") == RT.HYPERLINK:
                hyperlink_targets.append(getattr(relationship, "target_ref", ""))
    original_emails = {
        item["text"] for item in predictions if item.get("type") == "EMAIL"
    }
    stale_hyperlinks = [
        target
        for target in hyperlink_targets
        if any(email.casefold() in target.casefold() for email in original_emails)
    ]

    result = {
        "input": str(input_path),
        "output": str(output_path),
        "output_reopened": True,
        "paragraph_like_units_checked": len(extract_docx_units(output_path)),
        "prediction_count": len(predictions),
        "residual_original_values": residual,
        "text_residual_original_values": text_residual,
        "package_xml_residual_original_values": package_residual,
        "hyperlink_targets_checked": hyperlink_targets,
        "stale_original_email_hyperlinks": stale_hyperlinks,
        "passed": not residual and not stale_hyperlinks,
    }
    report_path = Path(args.report)
    report_path.parent.mkdir(parents=True, exist_ok=True)
    report_path.write_text(json.dumps(result, indent=2, ensure_ascii=False), encoding="utf-8")
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0 if result["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
