"""Deterministic synthetic replacement generation and text redaction."""

from __future__ import annotations

import re
from typing import Iterable, Optional

from .models import Entity, PIIType

try:  # Faker is listed in requirements, but keep a small offline fallback.
    from faker import Faker  # type: ignore
except Exception:  # pragma: no cover - exercised only before dependencies install
    Faker = None  # type: ignore[assignment]


_FALLBACK_FIRST_NAMES = [
    "Aarav", "Maya", "Rohan", "Priya", "Kabir", "Neha", "Vikram", "Sneha",
    "Arjun", "Meera", "Rahul", "Ananya", "Yash", "Kavya", "Aditya", "Isha",
]
_FALLBACK_LAST_NAMES = [
    "Mehta", "Carter", "Shah", "Morgan", "Kapoor", "Reed", "Nair", "Bennett",
    "Joshi", "Rivera", "Malhotra", "Foster", "Iyer", "Brooks", "Desai", "Hayes",
]
_FALLBACK_COMPANIES = [
    "Asteron Technologies Pvt. Ltd.",
    "Northstar Foods Limited",
    "Blue Harbor Systems Pvt. Ltd.",
    "Cedar Grove Solutions Limited",
    "Silverline Industries Pvt. Ltd.",
    "Maplebridge Services Limited",
]
_FALLBACK_INDIA_ADDRESSES = [
    "101 Example Avenue, New Delhi, Delhi 110001",
    "22 Sample Road, Pune, Maharashtra 411001",
    "14 Demonstration Lane, Bengaluru, Karnataka 560001",
    "8 Synthetic Colony, Chennai, Tamil Nadu 600001",
]
_FALLBACK_US_ADDRESSES = [
    "100 Example Street, Example City, NY 10001",
    "200 Sample Avenue, Example Town, CA 90001",
    "14 Placeholder Road, Exampleville, TX 75001",
]

_MONTH_NUMBERS = {
    "jan": 1,
    "january": 1,
    "feb": 2,
    "february": 2,
    "mar": 3,
    "march": 3,
    "apr": 4,
    "april": 4,
    "may": 5,
    "jun": 6,
    "june": 6,
    "jul": 7,
    "july": 7,
    "aug": 8,
    "august": 8,
    "sep": 9,
    "sept": 9,
    "september": 9,
    "oct": 10,
    "october": 10,
    "nov": 11,
    "november": 11,
    "dec": 12,
    "december": 12,
}
_MONTH_TOKEN = r"(?:jan(?:uary)?|feb(?:ruary)?|mar(?:ch)?|apr(?:il)?|may|jun(?:e)?|jul(?:y)?|aug(?:ust)?|sep(?:t(?:ember)?)?|oct(?:ober)?|nov(?:ember)?|dec(?:ember)?)"


def _normalise_key(value: str) -> str:
    return re.sub(r"\s+", " ", value).strip().casefold()


def _dob_parts(value: str) -> Optional[tuple[int, int, int, str]]:
    """Return year, month, day, and display style for a supported DOB."""

    text = re.sub(r"\s+", " ", value.strip())
    numeric = re.fullmatch(
        r"(?P<a>\d{1,4})[./-](?P<b>\d{1,2})[./-](?P<c>\d{1,4})", text
    )
    if numeric:
        a, b, c = numeric.group("a", "b", "c")
        if len(a) == 4:
            year, month, day, style = int(a), int(b), int(c), "year-first"
        else:
            day, month, year, style = int(a), int(b), int(c), "day-first"
        return year, month, day, style

    textual = re.fullmatch(
        rf"(?P<month>{_MONTH_TOKEN})\s+(?P<day>\d{{1,2}})(?:st|nd|rd|th)?"
        rf"(?:\s*,\s*|\s+)(?P<year>\d{{4}})",
        text,
        re.IGNORECASE,
    )
    if textual:
        month = _MONTH_NUMBERS[textual.group("month").casefold()]
        return (
            int(textual.group("year")),
            month,
            int(textual.group("day")),
            "text-first",
        )

    textual = re.fullmatch(
        rf"(?P<day>\d{{1,2}})(?:st|nd|rd|th)?\s+(?P<month>{_MONTH_TOKEN})"
        rf"(?:\s*,\s*|\s+)(?P<year>\d{{4}})",
        text,
        re.IGNORECASE,
    )
    if textual:
        month = _MONTH_NUMBERS[textual.group("month").casefold()]
        return (
            int(textual.group("year")),
            month,
            int(textual.group("day")),
            "text-day",
        )
    return None


def _slug(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9]+", ".", value).strip(".").lower()
    return value or "user"


def _format_dob_like(template: str, parts: tuple[int, int, int, str]) -> str:
    """Render a synthetic date in the source's numeric/textual style."""

    year, month, day, style = parts
    if style in {"text-first", "text-day"}:
        month_name = (
            "January", "February", "March", "April", "May", "June",
            "July", "August", "September", "October", "November", "December",
        )[month - 1]
        rendered = re.sub(r"\b[A-Za-z]+\b", month_name, template, count=1)
        # Replace the day first, then the year.  This avoids treating the day
        # digits inside an ordinal (``14th``) as the year.
        rendered = re.sub(r"\d{1,2}", str(day), rendered, count=1)
        suffix = "th" if day in {11, 12, 13} else {1: "st", 2: "nd", 3: "rd"}.get(day % 10, "th")
        rendered = re.sub(
            r"(?<=\d)(?:st|nd|rd|th)\b", suffix, rendered, count=1
        )
        return re.sub(r"(?<!\d)(?:19|20)\d{2}\b", str(year), rendered)

    ordered = (
        (year, month, day)
        if style == "year-first"
        else (day, month, year)
    )
    iterator = iter(ordered)

    def render_number(match: re.Match[str]) -> str:
        value = next(iterator)
        width = len(match.group(0))
        return str(value) if width == 1 and value < 10 else f"{value:0{width}d}"

    return re.sub(r"\d+", render_number, template)


class ReplacementRegistry:
    """Maintain a stable original-value/type to synthetic-value mapping.

    A seeded Faker instance is used when available, but the fallback pools and
    reserved example domains/IPs make the output deterministic and safe even
    in a minimal offline installation.
    """

    def __init__(
        self,
        seed: int = 1337,
        reserved: Optional[Iterable[str]] = None,
    ) -> None:
        self.seed = seed
        self._faker = None
        if Faker is not None:
            try:
                self._faker = Faker("en_IN")
                self._faker.seed_instance(seed)
            except Exception:
                self._faker = None
        self._mapping: dict[tuple[PIIType, str], str] = {}
        self._used: dict[PIIType, set[str]] = {pii_type: set() for pii_type in PIIType}
        self._address_index = 0
        # Original document values are reserved so a generated replacement can
        # never coincide with real data.  Without this, a seeded generator may
        # pick the very name it is meant to replace, leaving the original value
        # in the output.
        self._reserved: set[str] = set()
        if reserved is not None:
            self.reserve(reserved)

    def reserve(self, values: Iterable[str]) -> None:
        """Record original values that replacements must never reproduce."""

        for value in values:
            if value and value.strip():
                self._reserved.add(_normalise_key(value))

    def _conflicts_with_reserved(self, candidate: str) -> bool:
        return _normalise_key(candidate) in self._reserved

    @property
    def mapping(self) -> dict[tuple[PIIType, str], str]:
        return dict(self._mapping)

    @property
    def synthetic_values(self) -> set[str]:
        return {value.casefold() for value in self._mapping.values()}

    @staticmethod
    def _mapping_key(entity: Entity) -> tuple[PIIType, str]:
        # Cross-unit fragments carry the full logical identity so a name split
        # over two DOCX paragraphs receives the same deterministic replacement
        # as its intact occurrences.
        if entity.identity:
            return entity.pii_type, _normalise_key(entity.identity)
        if entity.pii_type in {
            PIIType.PHONE,
            PIIType.SSN,
            PIIType.CREDIT_CARD,
            PIIType.IP,
        }:
            # Separators and display case do not create a new identity.
            return entity.pii_type, "".join(char for char in entity.text if char.isdigit())
        if entity.pii_type == PIIType.DOB:
            parts = _dob_parts(entity.text)
            if parts is not None:
                year, month, day, style = parts
                # The canonical date keeps the replacement calendar identity
                # stable across separators and month-name spelling, while the
                # style keeps numeric and textual rendering readable.
                return entity.pii_type, f"date|{year:04d}-{month:02d}-{day:02d}|{style}"
            return entity.pii_type, _normalise_key(entity.text)
        return entity.pii_type, _normalise_key(entity.text)

    def replacement_for(self, entity: Entity) -> str:
        key = self._mapping_key(entity)
        if key in self._mapping:
            existing = self._mapping[key]
            if entity.pii_type == PIIType.DOB:
                existing_parts = _dob_parts(existing)
                if existing_parts is not None:
                    return _format_dob_like(entity.text, existing_parts)
            if entity.pii_type in {
                PIIType.PHONE,
                PIIType.SSN,
                PIIType.CREDIT_CARD,
            }:
                existing_digits = "".join(char for char in existing if char.isdigit())
                return self._replace_digits_like(entity.text, existing_digits)
            return existing

        if entity.pii_type == PIIType.PERSON:
            value = self._new_name(entity.text)
        elif entity.pii_type == PIIType.EMAIL:
            value = self._new_email(entity.text)
        elif entity.pii_type == PIIType.PHONE:
            value = self._new_phone(entity.text)
        elif entity.pii_type == PIIType.ORG:
            value = self._new_company(entity.text)
        elif entity.pii_type == PIIType.ADDRESS:
            value = self._new_address(entity.text)
        elif entity.pii_type == PIIType.SSN:
            value = self._new_ssn(entity.text)
        elif entity.pii_type == PIIType.CREDIT_CARD:
            value = self._new_credit_card(entity.text)
        elif entity.pii_type == PIIType.DOB:
            value = self._new_dob(entity.text)
        elif entity.pii_type == PIIType.IP:
            value = self._new_ip(entity.text)
        else:  # pragma: no cover - exhaustive enum guard
            raise ValueError(f"Unsupported PII type: {entity.pii_type}")

        self._mapping[key] = value
        self._used[entity.pii_type].add(value.casefold())
        return value

    def _new_name(self, original: str = "") -> str:
        original_key = _normalise_key(original)
        for _ in range(20):
            if self._faker is not None:
                candidate = self._faker.name()
            else:
                first = _FALLBACK_FIRST_NAMES[self._address_index % len(_FALLBACK_FIRST_NAMES)]
                last = _FALLBACK_LAST_NAMES[self._address_index % len(_FALLBACK_LAST_NAMES)]
                candidate = f"{first} {last}"
                self._address_index += 1
            if (
                candidate.casefold() != original_key
                and candidate.casefold() not in self._used[PIIType.PERSON]
                and not self._conflicts_with_reserved(candidate)
            ):
                return candidate
        return f"Example Person {len(self._used[PIIType.PERSON]) + 1}"

    def _new_email(self, original: str = "") -> str:
        name = self._new_name()
        local = _slug(name)
        candidate = f"{local}@example.com"
        suffix = 2
        while (
            candidate.casefold() in self._used[PIIType.EMAIL]
            or candidate.casefold() == _normalise_key(original)
            or self._conflicts_with_reserved(candidate)
        ):
            candidate = f"{local}{suffix}@example.com"
            suffix += 1
        return candidate

    def _new_company(self, original: str = "") -> str:
        # Keep legal suffixes in replacements as well as in detection.  The
        # fixed fictional pool avoids accidentally selecting a real company
        # name from a general Faker provider.
        original_key = _normalise_key(original)
        for offset in range(len(_FALLBACK_COMPANIES)):
            candidate = _FALLBACK_COMPANIES[
                (self._address_index + offset) % len(_FALLBACK_COMPANIES)
            ]
            if (
                candidate.casefold() not in self._used[PIIType.ORG]
                and candidate.casefold() != original_key
                and not self._conflicts_with_reserved(candidate)
            ):
                self._address_index += 1
                return candidate
        return f"Example Synthetic Holdings {len(self._used[PIIType.ORG]) + 1} Limited"

    def _new_address(self, original: str) -> str:
        pool = _FALLBACK_US_ADDRESSES if self._looks_us(original) else _FALLBACK_INDIA_ADDRESSES
        original_key = _normalise_key(original)
        for offset in range(len(pool)):
            candidate = pool[(self._address_index + offset) % len(pool)]
            if (
                candidate.casefold() not in self._used[PIIType.ADDRESS]
                and _normalise_key(candidate) != original_key
                and not self._conflicts_with_reserved(candidate)
            ):
                self._address_index += 1
                return candidate
        return "999 Example Street, Example City 00001"

    @staticmethod
    def _looks_us(original: str) -> bool:
        return bool(re.search(r"\b(?:AL|AK|AZ|AR|CA|CO|CT|DE|FL|GA|HI|ID|IL|IN|IA|KS|KY|LA|ME|MD|MA|MI|MN|MS|MO|MT|NE|NV|NH|NJ|NM|NY|NC|ND|OH|OK|OR|PA|RI|SC|SD|TN|TX|UT|VT|VA|WA|WV|WI|WY)\b", original))

    @staticmethod
    def _replace_digits_like(original: str, digits: str) -> str:
        iterator = iter(digits)
        return "".join(
            next(iterator, char) if char.isdigit() else char for char in original
        )

    def _new_phone(self, original: str) -> str:
        original_digits = [char for char in original if char.isdigit()]
        serial = len(self._used[PIIType.PHONE])
        country_match = re.match(r"(\s*\+\d{1,3})", original)
        if country_match:
            country = country_match.group(1)
            country_digits = "".join(char for char in country if char.isdigit())
            national_count = max(7, min(10, len(original_digits) - len(country_digits)))
            if country_digits == "91":
                national = "9" + "".join(str((index * 7 + 3) % 10) for index in range(national_count - 1))
            elif country_digits == "1" and national_count == 10:
                national = f"202555{serial + 1:04d}"[-10:]
            else:
                national = "".join(str((index * 3 + 2) % 10) for index in range(national_count))
            replacement_digits = country_digits + national
        else:
            count = len(original_digits)
            if count == 10:
                replacement_digits = "9" + "".join(str((index * 7 + 3) % 10) for index in range(9))
            else:
                replacement_digits = "".join(str((index * 5 + 1) % 10) for index in range(max(7, count)))
        replacement_digits = replacement_digits[: len(original_digits) or 7]
        candidate = self._replace_digits_like(original, replacement_digits)
        if candidate == original:
            candidate = candidate + "7"
        return candidate

    def _new_ssn(self, original: str) -> str:
        # 900-xx-xxxx is intentionally outside the valid US SSN allocation.
        serial = len(self._used[PIIType.SSN])
        digits = f"900{serial % 100:02d}{(serial + 1234) % 10000:04d}"
        return self._replace_digits_like(original, digits)

    @staticmethod
    def _luhn_valid(value: str) -> bool:
        digits = [int(char) for char in value if char.isdigit()]
        if not digits:
            return False
        parity = len(digits) % 2
        total = 0
        for index, digit in enumerate(digits):
            if index % 2 == parity:
                digit *= 2
                if digit > 9:
                    digit -= 9
            total += digit
        return total % 10 == 0

    def _new_credit_card(self, original: str) -> str:
        # Use the public 4242 payment-test prefix and calculate the final
        # digit so 13- through 19-digit replacements remain Luhn-valid.
        count = len([char for char in original if char.isdigit()])
        count = max(13, count)
        prefix = ("4242" * ((count + 3) // 4))[: count - 1]
        for check_digit in range(10):
            digits = prefix + str(check_digit)
            if self._luhn_valid(digits):
                return self._replace_digits_like(original, digits)
        # This is unreachable for the supported lengths, but keeps the method
        # total and deterministic if the algorithm is changed in the future.
        return self._replace_digits_like(original, prefix + "0")

    def _new_dob(self, original: str) -> str:
        parts = _dob_parts(original)
        if parts is None:
            return "23/05/1997"
        style = parts[3]
        return _format_dob_like(original, (1997, 5, 23, style))

    def _new_ip(self, original: str) -> str:
        serial = len(self._used[PIIType.IP])
        if ":" in original:
            return f"2001:db8::{serial + 1:x}"
        return f"203.0.113.{10 + (serial % 200)}"

    def redact_text(
        self, text: str, entities: Iterable[Entity]
    ) -> tuple[str, dict[tuple[PIIType, str], str]]:
        """Replace non-overlapping entities from right to left."""

        ordered = sorted(entities, key=lambda item: (item.start, item.end), reverse=True)
        output = text
        for entity in ordered:
            replacement = self.replacement_for(entity)
            output = output[: entity.start] + replacement + output[entity.end :]
        return output, self.mapping
