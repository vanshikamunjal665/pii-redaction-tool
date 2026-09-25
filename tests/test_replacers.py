from __future__ import annotations

from src.models import Entity, PIIType
from src.replacers import ReplacementRegistry


def entity(pii_type: PIIType, text: str) -> Entity:
    return Entity(text=text, pii_type=pii_type, start=0, end=len(text))


def test_repeated_values_map_consistently() -> None:
    registry = ReplacementRegistry(seed=1337)
    first = registry.replacement_for(entity(PIIType.PERSON, "Rashi Patil"))
    second = registry.replacement_for(entity(PIIType.PERSON, "Rashi Patil"))
    assert first == second

    phone_a = registry.replacement_for(entity(PIIType.PHONE, "+91 98765 43210"))
    phone_b = registry.replacement_for(entity(PIIType.PHONE, "+91-98765-43210"))
    assert "".join(c for c in phone_a if c.isdigit()) == "".join(
        c for c in phone_b if c.isdigit()
    )
    assert phone_a != "+91 98765 43210"


def test_replacements_use_reserved_or_test_values() -> None:
    registry = ReplacementRegistry(seed=1337)
    email = registry.replacement_for(entity(PIIType.EMAIL, "real.person@gmail.com"))
    ip = registry.replacement_for(entity(PIIType.IP, "192.168.1.10"))
    card = registry.replacement_for(entity(PIIType.CREDIT_CARD, "4111 1111 1111 1111"))
    assert email.endswith("@example.com")
    assert ip.startswith("203.0.113.")
    assert "".join(c for c in card if c.isdigit()) == "4242424242424242"


def test_dob_mapping_is_stable_across_date_rendering_variants() -> None:
    registry = ReplacementRegistry(seed=1337)
    numeric = registry.replacement_for(entity(PIIType.DOB, "14/08/1998"))
    numeric_variant = registry.replacement_for(entity(PIIType.DOB, "14-08-1998"))
    textual = registry.replacement_for(entity(PIIType.DOB, "August 14, 1998"))
    textual_variant = registry.replacement_for(entity(PIIType.DOB, "Aug 14 1998"))
    assert numeric == "23/05/1997"
    assert numeric_variant == "23-05-1997"
    assert textual == "May 23, 1997"
    assert textual_variant == "May 23 1997"


def test_replacement_is_different_when_source_matches_a_fixed_pool_value() -> None:
    registry = ReplacementRegistry(seed=1337)
    for pii_type, value in [
        (PIIType.ORG, "Asteron Technologies Pvt. Ltd."),
        (PIIType.ADDRESS, "101 Example Avenue, New Delhi, Delhi 110001"),
    ]:
        replacement = registry.replacement_for(entity(pii_type, value))
        assert replacement.casefold() != value.casefold()


def test_card_replacements_are_luhn_valid_for_supported_lengths() -> None:
    registry = ReplacementRegistry(seed=1337)
    for length in range(13, 20):
        original = "4" * length
        replacement = registry.replacement_for(entity(PIIType.CREDIT_CARD, original))
        digits = "".join(c for c in replacement if c.isdigit())
        assert len(digits) == length
        assert registry._luhn_valid(digits)
