"""Command-line entry point for the PII redaction pipeline."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Sequence

from .detectors import PIIDetector
from .document_processor import contains_original_value, redact_document
from .evaluation import evaluate_files, write_report
from .replacers import ReplacementRegistry


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Detect and replace PII in a DOCX or PDF")
    parser.add_argument("--input", required=True, help="Input .docx or .pdf path")
    parser.add_argument("--output", required=True, help="Output .docx path")
    parser.add_argument(
        "--predictions",
        default="evaluation/predictions.json",
        help="Where to write detector predictions (default: evaluation/predictions.json)",
    )
    parser.add_argument("--ground-truth", help="Optional ground-truth JSON for evaluation")
    parser.add_argument("--report", help="Optional evaluation report Markdown path")
    parser.add_argument("--seed", type=int, default=1337, help="Synthetic replacement seed")
    parser.add_argument(
        "--no-spacy",
        action="store_true",
        help="Disable the optional spaCy backend and use deterministic fallback rules",
    )
    return parser


def run(args: argparse.Namespace) -> int:
    input_path = Path(args.input)
    output_path = Path(args.output)
    predictions_path = Path(args.predictions)
    if not input_path.is_file():
        raise FileNotFoundError(f"Input document does not exist: {input_path}")
    if predictions_path.resolve() in {input_path.resolve(), output_path.resolve()}:
        raise ValueError("Predictions path must differ from both input and output paths")

    detector = PIIDetector(use_spacy=not args.no_spacy)
    registry = ReplacementRegistry(seed=args.seed)
    result = redact_document(input_path, output_path, detector=detector, registry=registry)

    predictions = result.prediction_dicts()
    predictions_payload = {
        "source": str(input_path),
        "output": str(output_path),
        "seed": args.seed,
        "prediction_count": len(predictions),
        "predictions": predictions,
    }
    predictions_path.parent.mkdir(parents=True, exist_ok=True)
    predictions_path.write_text(
        json.dumps(predictions_payload, indent=2, ensure_ascii=False), encoding="utf-8"
    )

    # Reopen/read output and perform a conservative residual-value check.  A
    # value can legitimately occur in non-PII prose, so this is reported as a
    # warning rather than silently changing the prediction set.  Matching is
    # whole-value, so an entity fragment that also occurs inside an ordinary
    # word is not counted.  This quick check covers extracted text only;
    # ``tools/verify_output.py`` additionally inspects the package XML and
    # hyperlink targets.
    output_text = "\n".join(unit.text for unit in result.redacted_units)
    residual = sorted(
        {
            entity.identity or entity.text
            for entity in result.predictions
            if contains_original_value(output_text, entity.identity or entity.text)
        }
    )
    print(f"Input: {input_path}")
    print(f"Output: {output_path}")
    print(f"Predictions written: {predictions_path} ({len(predictions)} entities)")
    print(f"Output reopened successfully; residual original-value matches: {len(residual)}")
    if residual:
        print(
            "Warning: some original values still occur in the extracted text. "
            "Run tools/verify_output.py to locate them (it reports locations, "
            "not values)."
        )

    if args.ground_truth:
        evaluation = evaluate_files(args.ground_truth, predictions_path)
        if args.report:
            write_report(evaluation, args.report)
            print(f"Evaluation report written: {args.report}")
        totals = evaluation.totals
        print(
            "Evaluation: "
            f"TP={totals['TP']} FP={totals['FP']} FN={totals['FN']} "
            f"precision={evaluation.precision if evaluation.precision is not None else 'N/A'} "
            f"recall={evaluation.recall if evaluation.recall is not None else 'N/A'} "
            f"f1={evaluation.f1 if evaluation.f1 is not None else 'N/A'} "
            f"accuracy={evaluation.accuracy if evaluation.accuracy is not None else 'N/A'}"
        )
    elif args.report:
        raise ValueError("--report requires --ground-truth")
    return 0


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return run(args)
    except Exception as exc:
        parser.error(str(exc))
        return 2


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
