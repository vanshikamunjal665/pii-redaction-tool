from __future__ import annotations

from src.evaluation import evaluate_annotations
from src.models import PIIType


def test_entity_metrics_and_wrong_type_handling() -> None:
    truth = [
        {"text": "Rashi Patil", "type": "PERSON", "unit_id": "doc:p1"},
        {"text": "rashi@example.com", "type": "EMAIL", "unit_id": "doc:p2"},
        {"text": "+91 9876543210", "type": "PHONE", "unit_id": "doc:p3"},
    ]
    predictions = [
        {"text": "Rashi Patil", "type": "PERSON", "unit_id": "doc:p1"},
        {"text": "rashi@example.com", "type": "PERSON", "unit_id": "doc:p2"},
        {"text": "+91 9876543210", "type": "PHONE", "unit_id": "doc:p3"},
        {"text": "not pii", "type": "ORG", "unit_id": "doc:p4"},
    ]
    result = evaluate_annotations(truth, predictions)
    assert result.totals == {"ground_truth": 3, "detected": 4, "TP": 2, "FP": 2, "FN": 1}
    assert result.precision == 0.5
    assert result.recall == 2 / 3
    assert result.accuracy == 2 / 5


def test_repeated_values_require_matching_unit_ids() -> None:
    truth = [
        {"text": "Rashi Patil", "type": "PERSON", "unit_id": "doc:p1"},
        {"text": "Rashi Patil", "type": "PERSON", "unit_id": "doc:p2"},
    ]
    predictions = [
        {"text": "Rashi Patil", "type": "PERSON", "unit_id": "doc:p1"},
        {"text": "Rashi Patil", "type": "PERSON", "unit_id": "doc:p3"},
    ]
    result = evaluate_annotations(truth, predictions)
    assert result.per_type[PIIType.PERSON].true_positive == 1
    assert result.per_type[PIIType.PERSON].false_positive == 1
    assert result.per_type[PIIType.PERSON].false_negative == 1


def test_empty_category_is_not_given_artificial_perfect_score() -> None:
    result = evaluate_annotations([], [])
    assert result.per_type[PIIType.SSN].ground_truth == 0
    assert result.precision is None
    assert result.recall is None
    assert result.f1 is None
