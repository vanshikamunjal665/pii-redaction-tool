from __future__ import annotations

import pytest

from src.detectors import PIIDetector
from src.models import PIIType


@pytest.fixture()
def detector() -> PIIDetector:
    return PIIDetector(use_spacy=False)


def found(detector: PIIDetector, text: str) -> dict[PIIType, list[str]]:
    result: dict[PIIType, list[str]] = {}
    for entity in detector.detect(text):
        result.setdefault(entity.pii_type, []).append(entity.text)
    return {pii_type: result.get(pii_type, []) for pii_type in PIIType}


def test_name_after_a_generic_label_is_detected(detector: PIIDetector) -> None:
    assert found(detector, "Contact Rashi Patil rashi.patil@gmail.com")[PIIType.PERSON] == [
        "Rashi Patil"
    ]


def test_required_positive_examples(detector: PIIDetector) -> None:
    text = (
        "Rashi Patil; John Doe; rashi.patil@gmail.com; "
        "+91 9876543210; ABC Technologies Pvt. Ltd.; "
        "123 Example Street, Example City, NY 10001; "
        "SSN: 123-45-6789; 4111 1111 1111 1111; "
        "Date of Birth: 14/08/1998; 192.168.1.1"
    )
    values = found(detector, text)
    assert "Rashi Patil" in values[PIIType.PERSON]
    assert "John Doe" in values[PIIType.PERSON]
    assert "rashi.patil@gmail.com" in values[PIIType.EMAIL]
    assert "+91 9876543210" in values[PIIType.PHONE]
    assert "ABC Technologies Pvt. Ltd." in values[PIIType.ORG]
    assert "123 Example Street, Example City, NY 10001" in values[PIIType.ADDRESS]
    assert "123-45-6789" in values[PIIType.SSN]
    assert "4111 1111 1111 1111" in values[PIIType.CREDIT_CARD]
    assert "14/08/1998" in values[PIIType.DOB]
    assert "192.168.1.1" in values[PIIType.IP]


def test_phone_formats_and_date_context(detector: PIIDetector) -> None:
    values = found(
        detector,
        "+91-9876543210; +1-202-555-0147; "
        "Filing date: 12/01/2025; Date of Birth: 14/08/1998",
    )
    assert values[PIIType.PHONE] == ["+91-9876543210", "+1-202-555-0147"]
    assert values[PIIType.DOB] == ["14/08/1998"]
    assert found(detector, "Date of Birth: 1998-08-14")[PIIType.DOB] == [
        "1998-08-14"
    ]
    assert found(detector, "Date of Birth: Aug 14, 1998")[PIIType.DOB] == [
        "Aug 14, 1998"
    ]
    assert found(detector, "Date of Birth: 14th August 1998")[PIIType.DOB] == [
        "14th August 1998"
    ]


def test_distant_dob_label_does_not_capture_other_date(detector: PIIDetector) -> None:
    values = found(detector, "Filing date: 12/01/2025 Date of Birth: 14/08/1998")
    assert values[PIIType.DOB] == ["14/08/1998"]


def test_negative_numbers_are_not_pii(detector: PIIDetector) -> None:
    text = (
        "Order 123456789; Invoice 1234567890123456; Revenue 2025; "
        "Page 123; Ticket #12345; Order 9876543210; Filing date: 12/01/2025"
    )
    assert detector.detect(text) == []


def test_ssn_and_card_validation(detector: PIIDetector) -> None:
    assert found(detector, "SSN 123456789")[PIIType.SSN] == ["123456789"]
    assert found(detector, "SSN 000-12-3456")[PIIType.SSN] == []
    assert found(detector, "Card 4111-1111-1111-1111")[PIIType.CREDIT_CARD] == [
        "4111-1111-1111-1111"
    ]
    assert found(detector, "Invoice 1234567890123456")[PIIType.CREDIT_CARD] == []


def test_address_prefers_complete_span(detector: PIIDetector) -> None:
    entities = detector.detect(
        "Registered office: 221B, Green Park, New Delhi, Delhi 110001; "
        "telephone +91-98765-43210"
    )
    assert [(item.pii_type, item.text) for item in entities] == [
        (PIIType.ADDRESS, "221B, Green Park, New Delhi, Delhi 110001"),
        (PIIType.PHONE, "+91-98765-43210"),
    ]


def test_ip_validation(detector: PIIDetector) -> None:
    assert found(detector, "192.168.1.1")[PIIType.IP] == ["192.168.1.1"]
    assert found(detector, "999.1.1.1")[PIIType.IP] == []
    assert found(detector, "2001:db8::1")[PIIType.IP] == ["2001:db8::1"]
    assert found(detector, "::1")[PIIType.IP] == ["::1"]


def test_overlap_resolution_does_not_double_count_nested_values(detector: PIIDetector) -> None:
    entities = detector.detect("Address: 123 Example Street, +91 9876543210")
    assert len(entities) == 1
    assert entities[0].pii_type == PIIType.ADDRESS
