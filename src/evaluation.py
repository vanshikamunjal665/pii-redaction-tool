"""Entity-level evaluation for the PII detector.

There is no finite, meaningful true-negative set for arbitrary text spans, so
this module uses an explicit open-world entity-decision accuracy:

    accuracy = TP / (TP + FP + FN)

It is not presented as ordinary binary classification accuracy.  Precision,
recall, and F1 remain the primary metrics.
"""

from __future__ import annotations

import argparse
import json
import re
import unicodedata
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

from .models import PIIType, SUPPORTED_TYPES


@dataclass
class CategoryMetrics:
    pii_type: PIIType
    ground_truth: int
    detected: int
    true_positive: int
    false_positive: int
    false_negative: int
    unmatched_ground_truth: list[dict[str, Any]] = field(default_factory=list)
    unmatched_predictions: list[dict[str, Any]] = field(default_factory=list)

    @property
    def precision(self) -> Optional[float]:
        denominator = self.true_positive + self.false_positive
        return self.true_positive / denominator if denominator else None

    @property
    def recall(self) -> Optional[float]:
        denominator = self.true_positive + self.false_negative
        return self.true_positive / denominator if denominator else None

    @property
    def f1(self) -> Optional[float]:
        if self.precision is None or self.recall is None:
            return None
        return 2 * self.precision * self.recall / (self.precision + self.recall) if self.precision + self.recall else 0.0

    @property
    def accuracy(self) -> Optional[float]:
        denominator = self.ground_truth + self.false_positive
        return self.true_positive / denominator if denominator else None

    def as_dict(self, include_examples: bool = False) -> dict[str, Any]:
        payload: dict[str, Any] = {
            "type": self.pii_type.value,
            "ground_truth": self.ground_truth,
            "detected": self.detected,
            "TP": self.true_positive,
            "FP": self.false_positive,
            "FN": self.false_negative,
            "precision": self.precision,
            "recall": self.recall,
            "f1": self.f1,
            "accuracy": self.accuracy,
        }
        if include_examples:
            payload["unmatched_ground_truth"] = self.unmatched_ground_truth
            payload["unmatched_predictions"] = self.unmatched_predictions
        return payload


@dataclass
class EvaluationResult:
    per_type: dict[PIIType, CategoryMetrics]
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def totals(self) -> dict[str, int]:
        return {
            "ground_truth": sum(item.ground_truth for item in self.per_type.values()),
            "detected": sum(item.detected for item in self.per_type.values()),
            "TP": sum(item.true_positive for item in self.per_type.values()),
            "FP": sum(item.false_positive for item in self.per_type.values()),
            "FN": sum(item.false_negative for item in self.per_type.values()),
        }

    @property
    def precision(self) -> Optional[float]:
        totals = self.totals
        denominator = totals["TP"] + totals["FP"]
        return totals["TP"] / denominator if denominator else None

    @property
    def recall(self) -> Optional[float]:
        totals = self.totals
        denominator = totals["TP"] + totals["FN"]
        return totals["TP"] / denominator if denominator else None

    @property
    def f1(self) -> Optional[float]:
        if self.precision is None or self.recall is None:
            return None
        return 2 * self.precision * self.recall / (self.precision + self.recall) if self.precision + self.recall else 0.0

    @property
    def accuracy(self) -> Optional[float]:
        totals = self.totals
        denominator = totals["ground_truth"] + totals["FP"]
        return totals["TP"] / denominator if denominator else None

    def as_dict(self, include_examples: bool = False) -> dict[str, Any]:
        """Return the machine-readable summary.

        Unmatched entity values are omitted by default: the JSON is printed
        to stdout and frequently pasted into tickets, so it must not carry
        the source data.  ``include_examples=True`` is available for local
        debugging only.
        """

        return {
            "metadata": self.metadata,
            "matching_policy": {
                "unit": "entity",
                "text": "case-insensitive exact normalized text",
                "type": "exact category",
                "location": "part/unit and context used to disambiguate repeats",
                "overlap": "detector resolves complete structured spans before scoring",
                "accuracy": "TP/(GT+FP), an open-world entity-decision accuracy; no artificial TN",
                "examples": "unmatched values are omitted unless include_examples is set",
            },
            "overall": {
                **self.totals,
                "precision": self.precision,
                "recall": self.recall,
                "f1": self.f1,
                "accuracy": self.accuracy,
            },
            "per_type": {
                key.value: value.as_dict(include_examples=include_examples)
                for key, value in self.per_type.items()
            },
        }


def _normalise(value: str) -> str:
    value = unicodedata.normalize("NFKC", value or "")
    return re.sub(r"\s+", " ", value).strip().casefold()


def _type_value(value: Any) -> PIIType:
    if isinstance(value, PIIType):
        return value
    try:
        return PIIType(str(value).upper())
    except ValueError as exc:
        raise ValueError(f"Unknown PII type: {value}") from exc


def _load_json(path: str | Path) -> Any:
    with Path(path).open("r", encoding="utf-8") as handle:
        return json.load(handle)


def _annotations(payload: Any) -> list[dict[str, Any]]:
    if isinstance(payload, list):
        return payload
    if isinstance(payload, dict):
        value = payload.get("annotations", [])
        if not isinstance(value, list):
            raise ValueError("Ground-truth 'annotations' must be a list")
        return value
    raise ValueError("Ground truth must be a JSON object or list")


def _location(item: dict[str, Any]) -> str:
    for key in ("unit_id", "location", "part"):
        if item.get(key):
            return str(item[key])
    return ""


def _same_location(ground_truth: dict[str, Any], prediction: dict[str, Any]) -> bool:
    gt_location = _location(ground_truth).lstrip("/")
    pred_location = _location(prediction).lstrip("/")
    if not gt_location and not pred_location:
        return True
    if not gt_location or not pred_location:
        return False

    def split_location(value: str) -> tuple[str, str]:
        if ":" in value:
            part, unit = value.split(":", 1)
            return part, unit
        return value, ""

    gt_part, gt_unit = split_location(gt_location)
    pred_part, pred_unit = split_location(pred_location)
    gt_name = gt_part.replace("\\", "/").rsplit("/", 1)[-1]
    pred_name = pred_part.replace("\\", "/").rsplit("/", 1)[-1]
    if gt_unit and pred_unit:
        return gt_name == pred_name and gt_unit == pred_unit
    # A report may identify only the XML part while a prediction includes the
    # paragraph ID.  Do not collapse two different paragraph IDs to the same
    # location merely because both values share a part name.
    if gt_unit or pred_unit:
        return gt_name == pred_name
    return gt_name == pred_name


def _context_compatible(ground_truth: dict[str, Any], prediction: dict[str, Any]) -> bool:
    gt_context = _normalise(str(ground_truth.get("context", "")))
    pred_context = _normalise(str(prediction.get("context", "")))
    if not gt_context or not pred_context:
        return True
    return (
        gt_context == pred_context
        or gt_context in pred_context
        or pred_context in gt_context
    )


def _match_score(ground_truth: dict[str, Any], prediction: dict[str, Any]) -> Optional[int]:
    if _type_value(ground_truth["type"]) != _type_value(prediction["type"]):
        return None
    if _normalise(str(ground_truth.get("text", ""))) != _normalise(str(prediction.get("text", ""))):
        return None
    if not _same_location(ground_truth, prediction):
        return None
    if not _context_compatible(ground_truth, prediction):
        return None
    score = 100
    if _location(ground_truth):
        score += 10
    if ground_truth.get("context"):
        score += 5
    return score


def evaluate_annotations(
    ground_truth: Iterable[dict[str, Any]],
    predictions: Iterable[dict[str, Any]],
    metadata: Optional[dict[str, Any]] = None,
) -> EvaluationResult:
    gt_items = list(ground_truth)
    pred_items = list(predictions)
    per_type: dict[PIIType, CategoryMetrics] = {}
    for pii_type in SUPPORTED_TYPES:
        gt_for_type = [item for item in gt_items if _type_value(item["type"]) == pii_type]
        pred_for_type = [item for item in pred_items if _type_value(item["type"]) == pii_type]
        unmatched_gt = set(range(len(gt_for_type)))
        unmatched_pred = set(range(len(pred_for_type)))
        matches: dict[int, int] = {}
        candidates: list[tuple[int, int, int]] = []
        for gi, ground_truth_item in enumerate(gt_for_type):
            for pi, prediction in enumerate(pred_for_type):
                score = _match_score(ground_truth_item, prediction)
                if score is not None:
                    candidates.append((score, gi, pi))
        # Highest-confidence and exact-location matches win; stable tie breaks
        # make repeated identical values deterministic.
        for _score, gi, pi in sorted(candidates, key=lambda item: (-item[0], item[1], item[2])):
            if gi not in unmatched_gt or pi not in unmatched_pred:
                continue
            matches[gi] = pi
            unmatched_gt.remove(gi)
            unmatched_pred.remove(pi)
        tp = len(matches)
        fp = len(unmatched_pred)
        fn = len(unmatched_gt)
        per_type[pii_type] = CategoryMetrics(
            pii_type=pii_type,
            ground_truth=len(gt_for_type),
            detected=len(pred_for_type),
            true_positive=tp,
            false_positive=fp,
            false_negative=fn,
            unmatched_ground_truth=[gt_for_type[index] for index in sorted(unmatched_gt)],
            unmatched_predictions=[pred_for_type[index] for index in sorted(unmatched_pred)],
        )
    return EvaluationResult(per_type=per_type, metadata=metadata or {})


def evaluate_files(
    ground_truth_path: str | Path, predictions_path: str | Path
) -> EvaluationResult:
    truth_payload = _load_json(ground_truth_path)
    pred_payload = _load_json(predictions_path)
    metadata: dict[str, Any] = {}
    if isinstance(truth_payload, dict):
        metadata = {key: value for key, value in truth_payload.items() if key != "annotations"}
    predictions = pred_payload.get("predictions", []) if isinstance(pred_payload, dict) else pred_payload
    return evaluate_annotations(_annotations(truth_payload), predictions, metadata)


def _metric_text(value: Optional[float]) -> str:
    return "N/A" if value is None else f"{value:.3f}"


def _percent(value: Optional[float]) -> str:
    return "N/A" if value is None else f"{value:.1%}"


def _value_shape(value: str) -> str:
    """Describe a span's shape without reproducing its value.

    Reports are review artifacts that get shared around, so an unmatched
    entity is described by token classes and counts only.  Nothing derived
    from the characters themselves (names, e-mail local parts, digits) is
    printed.
    """

    letters = sum(1 for char in value if char.isalpha())
    digits = sum(1 for char in value if char.isdigit())
    if "@" in value:
        shape = "email-shaped value"
    elif letters == 0:
        shape = "numeric value"
    else:
        classes: list[str] = []
        for token in value.split():
            stripped = token.strip(".,;:()[]'\u2019\"")
            if not stripped:
                continue
            if len(stripped) > 1 and stripped.isupper():
                classes.append("CAPS")
            elif re.fullmatch(r"[A-Za-z]\.", stripped):
                classes.append("initial")
            elif stripped[:1].isalpha() and stripped[:1].isupper():
                classes.append("Capitalized")
            else:
                classes.append("lower")
        shape = f"{len(classes)} token(s) [{'/'.join(classes) or 'none'}]"
    return f"{shape}, {letters} letters, {digits} digits, {len(value)} chars"


def _describe_item(item: dict[str, Any]) -> str:
    """Return a reviewable, value-free description of an unmatched entity."""

    parts = [str(item.get("type", "?"))]
    parts.append(_value_shape(str(item.get("text", ""))))
    location = _location(item) or str(item.get("part", "unknown"))
    parts.append(f"at {location}")
    detector = item.get("detector")
    if detector:
        parts.append(f"via {detector}")
    return " | ".join(parts)


def write_report(result: EvaluationResult, output_path: str | Path) -> None:
    metadata = result.metadata
    totals = result.totals
    lines: list[str] = [
        "# PII Redaction Evaluation Report",
        "",
        "## 1. Executive Summary",
        "",
        f"The entity-level evaluation contains **{totals['ground_truth']}** manually/semantically verified annotations and **{totals['detected']}** detector predictions.",
        f"It produced **{totals['TP']} TP**, **{totals['FP']} FP**, and **{totals['FN']} FN** overall.",
        "",
        "## 2. Dataset",
        "",
    ]
    for key in (
        "source",
        "source_kind",
        "description",
        "document_stats",
        "category_counts",
        "annotation_policy",
        "limitations",
    ):
        if key in metadata:
            value = metadata[key]
            if isinstance(value, (dict, list)):
                import json as _json

                rendered = _json.dumps(value, ensure_ascii=False, indent=2)
                lines.append(f"- **{key}:**")
                lines.append("  ```json")
                lines.extend(f"  {line}" for line in rendered.splitlines())
                lines.append("  ```")
            else:
                lines.append(f"- **{key}:** {value}")
    if not any(
        key in metadata
        for key in (
            "source",
            "source_kind",
            "description",
            "document_stats",
            "category_counts",
            "annotation_policy",
            "limitations",
        )
    ):
        lines.append("- No dataset metadata was supplied.")

    lines.extend(
        [
            "",
            "## 3. Evaluation Method",
            "",
            "Predictions are matched to annotations at the entity level. A match requires the same category and the same text after Unicode normalization, whitespace collapsing, and case folding. When supplied, unit/location and context must also be compatible, which distinguishes repeated identical values. A prediction of the wrong type is a false positive for its predicted type and leaves the true annotation as a false negative.",
            "",
            "Nested structured matches are resolved before scoring: a complete address suppresses a phone/email/card-like substring inside that address. There is no artificial true-negative set for arbitrary text spans. Accordingly, the reported **entity-decision accuracy** is `TP / (ground_truth + FP)`, while precision, recall, and F1 use the standard formulas.",
            "",
            "## 4. Results",
            "",
            "| Category | Ground Truth | Detected | TP | FP | FN | Precision | Recall | F1 | Accuracy |",
            "| -------- | -----------: | -------: | -: | -: | -: | --------: | -----: | --: | --------: |",
        ]
    )
    for pii_type in SUPPORTED_TYPES:
        item = result.per_type[pii_type]
        metric_label = _metric_text(item.precision)
        recall_label = _metric_text(item.recall)
        f1_label = _metric_text(item.f1)
        accuracy_label = _metric_text(item.accuracy)
        if item.ground_truth == 0:
            metric_label = recall_label = f1_label = "N/A — no instances present in source"
            accuracy_label = "N/A"
        lines.append(
            f"| {pii_type.value} | {item.ground_truth} | {item.detected} | {item.true_positive} | "
            f"{item.false_positive} | {item.false_negative} | {metric_label} | {recall_label} | "
            f"{f1_label} | {accuracy_label} |"
        )

    lines.extend(
        [
            "",
            "## 5. Overall Metrics",
            "",
            f"- **Entity-decision accuracy:** {_percent(result.accuracy)} (`TP / (GT + FP)`; no artificial TN)",
            f"- **Precision:** {_percent(result.precision)}",
            f"- **Recall:** {_percent(result.recall)}",
            f"- **F1-score:** {_percent(result.f1)}",
            "",
            "## 6. Error Analysis",
            "",
        ]
    )
    representative_fps: list[dict[str, Any]] = []
    representative_fns: list[dict[str, Any]] = []
    for item in result.per_type.values():
        representative_fps.extend(item.unmatched_predictions)
        representative_fns.extend(item.unmatched_ground_truth)
    lines.append(
        "Entity values are never printed in this report. Each item below is "
        "described by category, span shape, size, and location only, so the "
        "report can be shared without disclosing the underlying data."
    )
    lines.append("")
    if representative_fps:
        lines.append(f"False positives ({len(representative_fps)} total, up to 20 shown):")
        for item in representative_fps[:20]:
            lines.append(f"- {_describe_item(item)}")
        lines.append("")
    else:
        lines.append("No false positives were observed in the supplied ground-truth set.")
        lines.append("")
    if representative_fns:
        lines.append(f"False negatives ({len(representative_fns)} total, up to 20 shown):")
        for item in representative_fns[:20]:
            lines.append(f"- {_describe_item(item)}")
        lines.append("")
    else:
        lines.append("No false negatives were observed in the supplied ground-truth set.")
        lines.append("")

    lines.extend(
        [
            "## 7. Limitations",
            "",
            "- Regex detectors can miss unusual separators, OCR errors, and entities split across formatting runs.",
            "- The fallback name detector uses context and a small first-name heuristic; a full deployment should provide a domain-appropriate NER model.",
            "- Organization names are treated as sensitive under the assignment policy because the required category is explicit; this can redact non-personal organizations.",
            "- Address detection is deliberately conservative and can miss prose-only or multi-line addresses.",
            "- DOB detection requires explicit birth context; ordinary filing, transaction, and financial dates remain unchanged.",
            "- PDF-to-DOCX conversion preserves extracted text and page boundaries, not the original PDF's exact visual layout.",
            "- The report describes the dataset named in the metadata. If that dataset is a synthetic demonstration fixture rather than the assignment's RHP, its metrics must not be presented as source-document performance.",
            "",
        ]
    )
    path = Path(output_path)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(description="Evaluate PII entity predictions")
    parser.add_argument("--ground-truth", required=True)
    parser.add_argument("--predictions", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument(
        "--include-examples",
        action="store_true",
        help="print unmatched entity values on stdout (local debugging only)",
    )
    args = parser.parse_args()
    result = evaluate_files(args.ground_truth, args.predictions)
    write_report(result, args.output)
    print(
        json.dumps(
            result.as_dict(include_examples=args.include_examples),
            indent=2,
            ensure_ascii=False,
        )
    )
    return 0


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(main())
