"""Hybrid PII detectors.

The structured categories use regular expressions plus validation.  Names and
organizations use conservative context rules, with an optional spaCy backend
when a compatible model is installed.  The fallback is deliberately usable
without a model download, which keeps the project reproducible in a clean
Python environment.
"""

from __future__ import annotations

import ipaddress
import re
from datetime import date
from typing import Iterable, Optional

from .models import Entity, PIIType

# ---------------------------------------------------------------------------
# Structured patterns
# ---------------------------------------------------------------------------

EMAIL_RE = re.compile(
    r"(?<![\w.+-])[A-Za-z0-9.!#$%&'*+/=?^_`{|}~-]+@"
    r"[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+(?![\w.-])",
    re.IGNORECASE,
)

IPV4_RE = re.compile(
    r"(?<![\w.])(?:[0-9]{1,3}\.){3}[0-9]{1,3}(?![\w.])"
)
IPV6_RE = re.compile(
    r"(?<![0-9A-Fa-f:])(?:[0-9A-Fa-f]{0,4}:){2,}"
    r"[0-9A-Fa-f]{0,4}(?![0-9A-Fa-f:])"
)

SSN_RE = re.compile(
    r"(?<!\d)(?P<value>\d{3}[- ]\d{2}[- ]\d{4}|\d{9})(?!\d)"
)

CREDIT_CARD_RE = re.compile(
    r"(?<!\d)(?P<value>(?:\d[ -]?){12,18}\d)(?!\d)"
)

# The expression is intentionally permissive about separators; validation
# below rejects ordinary long numbers, dates, and identifiers.
PHONE_RE = re.compile(
    r"(?<![\w])(?P<value>"
    r"(?:\+\d{1,3}[\s.\-]?)?"
    r"(?:\(\d{1,4}\)[\s.\-]?)?"
    r"\d(?:[\s.\-]?\d){6,14}"
    r")(?!\d)"
)

NUMERIC_DOB_RE = re.compile(
    r"(?<!\d)(?P<value>"
    r"(?P<day>0?[1-9]|[12]\d|3[01])"
    r"[\/\-.](?P<month>0?[1-9]|1[0-2])"
    r"[\/\-.](?P<year>(?:19|20)\d{2})"
    r")(?!\d)"
)
YEAR_FIRST_DOB_RE = re.compile(
    r"(?<!\d)(?P<value>"
    r"(?P<year>(?:19|20)\d{2})"
    r"[\/\-.](?P<month>0?[1-9]|1[0-2])"
    r"[\/\-.](?P<day>0?[1-9]|[12]\d|3[01])"
    r")(?!\d)"
)

DOB_MONTH_PATTERN = (
    r"(?:January|February|March|April|May|June|July|August|September|"
    r"October|November|December|Jan|Feb|Mar|Apr|Jun|Jul|Aug|Sept|Sep|"
    r"Oct|Nov|Dec)"
)
TEXTUAL_DOB_RE = re.compile(
    r"(?i)(?<!\w)(?P<value>"
    r"(?P<day>0?[1-9]|[12]\d|3[01])(?:st|nd|rd|th)?\s+"
    rf"(?P<month_name>{DOB_MONTH_PATTERN})\s+"
    r"(?P<year>(?:19|20)\d{2})"
    r"|"
    rf"(?P<month_name2>{DOB_MONTH_PATTERN})\s+"
    r"(?P<day2>0?[1-9]|[12]\d|3[01])(?:st|nd|rd|th)?,?\s+"
    r"(?P<year2>(?:19|20)\d{2})"
    r")(?!\w)"
)

DOB_CONTEXT_RE = re.compile(
    r"(?i)(?:\bd\.?\s*o\.?\s*b\.?\b|\bdate\s+of\s+birth\b|"
    r"\bbirth\s*date\b|\bborn\b)"
)

# Legal suffixes and a few common organization head words.  The legal suffix
# is the strongest signal; ordinary capitalized words are not organizations
# by themselves.
ORG_SUFFIX_PATTERN = (
    r"(?:Pvt\.?\s*Ltd\.?|Private\s+Limited|Limited|Ltd\.?|LLP|LLC|Inc\.?|"
    r"Incorporated|Corporation|Corp\.?|Company|Co\.|P\.C\.?|PLC|GmbH|S\.A\.?|"
    r"Technologies|Technology|"
    r"Solutions|Services|Industries|Enterprises|Group|Holdings)"
)
ORG_RE = re.compile(
    rf"(?<![A-Za-z0-9])(?:[A-Z][A-Za-z0-9&'’.-]*\s+){{1,5}}"
    rf"{ORG_SUFFIX_PATTERN}(?![A-Za-z0-9])"
)
ORG_CONTEXT_RE = re.compile(
    r"(?i)\b(?:company|issuer|registrant|promoter|undertaking|vendor|supplier|"
    r"bank|name\s+of\s+company)\s*(?:name\s*)?(?:[:\-]|\bis\b)\s*"
    r"(?P<value>[A-Z][A-Za-z0-9&'’., -]{2,100}?)(?=[,;\n]|$)"
)

TITLE_NAME_RE = re.compile(
    r"\b(?:Mr|Mrs|Ms|Miss|Dr|Prof|Shri|Smt)\.?\s+"
    r"(?P<value>[A-Z][A-Za-z'’.-]*(?:\s+[A-Z][A-Za-z'’.-]*){1,3})"
)

LABELED_NAME_RE = re.compile(
    r"(?i)\b(?:full\s+name|name|director|promoter|chairman|signatory|"
    r"contact\s+person|beneficial\s+owner|partner|executive)\s*"
    r"(?:name\s*)?(?:[:\-]|\bis\b)\s*"
    r"(?P<value>[A-Z][A-Za-z'’.-]*(?:\s+[A-Z][A-Za-z'’.-]*){1,3})"
)

ROLE_AFTER_NAME_RE = re.compile(
    r"(?<!\w)(?P<value>[A-Z][A-Za-z'’.-]*(?:\s+[A-Z][A-Za-z'’.-]*){1,3})"
    r"\s*[,;:-]?\s*(?i:director|promoter|chairman|signatory|partner|"
    r"contact\s+person|beneficial\s+owner)\b"
)

# A small general-purpose first-name list is used only for a bare,
# context-free two/three-word candidate.  It is a precision-oriented fallback,
# not a claim that these are the only names in a language or region.
PERSON_FIRST_NAMES = {
    "aarav", "aditi", "amaya", "ananya", "arjun", "ashwin", "bhavya",
    "charlotte", "daniel", "david", "deepak", "elena", "emily", "george",
    "harsh", "isabel", "james", "jane", "john", "joseph", "kabir", "kavya",
    "lucas", "maria", "maya", "meera", "michael", "neha", "noah", "olivia",
    "patel", "priya", "rashi", "ravi", "rohan", "sarah", "sneha", "sophia",
    "smith", "vikram", "yash",
}
PERSON_SUFFIX_ORG_WORDS = {
    "technologies", "technology", "limited", "ltd", "pvt", "company",
    "corporation", "corp", "inc", "llp", "services", "solutions", "group",
    "holdings", "industries", "enterprises", "bank", "university", "school",
    "ministry", "government", "india", "global", "capital", "systems",
}

ADDRESS_KEYWORD_RE = re.compile(
    r"(?i)\b(?:house|flat|apartment|appt|building|residence|road|rd\.?|"
    r"street|st\.?|lane|sector|colony|nagar|marg|avenue|ave\.?|boulevard|"
    r"drive|dr\.?|floor|plot|block|tower|villa|flat)\b"
)
ADDRESS_LABEL_RE = re.compile(
    r"(?i)\b(?:registered\s+office|corporate\s+office|principal\s+office|"
    r"office\s+address|home\s+address|mailing\s+address|address)\s*"
    r"(?:is|at)?\s*[:\-]"
)
POSTAL_CODE_RE = re.compile(r"(?<!\d)\d{6}(?!\d)")
ADDRESS_NUMBER_RE = re.compile(r"(?<!\w)[A-Z]?\d{1,4}[A-Z]?(?:[-/]\d+)?(?=\s|[,])", re.I)


# ---------------------------------------------------------------------------
# Small validation and formatting helpers
# ---------------------------------------------------------------------------


def _valid_date(year: int, month: int, day: int) -> bool:
    try:
        date(year, month, day)
    except ValueError:
        return False
    return True


def _has_local_dob_context(text: str, start: int, end: int) -> bool:
    """Require a nearby birth label, not a distant DOB elsewhere in a unit."""

    before = text[max(0, start - 60) : start]
    matches = list(DOB_CONTEXT_RE.finditer(before))
    if matches:
        between = before[matches[-1].end() :]
        # A sentence boundary, another date, or a different field label means
        # the context belongs to a neighboring value.  A semicolon is allowed
        # only when it is followed by a fresh birth label; otherwise
        # ``DOB: 01/01/1990; 02/02/1991`` must not label the second value.
        semicolon = between.find(";")
        semicolon_is_safe = semicolon < 0 or bool(
            DOB_CONTEXT_RE.search(between[semicolon + 1 :])
        )
        if (
            semicolon_is_safe
            and not re.search(r"\.", between)
            and not re.search(
                r"(?i)\b(?:filing|transaction|issue|reporting|dated|date)\b", between
            )
            and not re.search(r"\d{1,4}[\/\-.]\d{1,4}[\/\-.]\d{1,4}", between)
        ):
            return True
    after = text[end : end + 24]
    return bool(re.match(r"(?i)^\s*(?:\((?:d\.?\s*o\.?\s*b\.?|date\s+of\s+birth)\)|d\.?\s*o\.?\s*b\.?)\b", after))


def _luhn_valid(value: str) -> bool:
    digits = [int(char) for char in value if char.isdigit()]
    if not 13 <= len(digits) <= 19:
        return False
    checksum = 0
    parity = len(digits) % 2
    for index, digit in enumerate(digits):
        if index % 2 == parity:
            digit *= 2
            if digit > 9:
                digit -= 9
        checksum += digit
    return checksum % 10 == 0


def _looks_like_date(value: str) -> bool:
    return bool(re.fullmatch(r"\d{1,4}[\/\-.]\d{1,2}[\/\-.]\d{1,4}", value.strip()))


def _digits(value: str) -> str:
    return "".join(char for char in value if char.isdigit())


def _context_snippet(text: str, start: int, end: int, radius: int = 90) -> str:
    left = max(0, start - radius)
    right = min(len(text), end + radius)
    return re.sub(r"\s+", " ", text[left:right]).strip()


def _entity(
    text: str,
    pii_type: PIIType,
    start: int,
    end: int,
    part: str,
    detector: str,
    score: float = 1.0,
) -> Entity:
    return Entity(
        text=text[start:end],
        pii_type=pii_type,
        start=start,
        end=end,
        part=part,
        context=_context_snippet(text, start, end),
        score=score,
        detector=detector,
    )


# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------


def detect_emails(text: str, part: str = "body") -> list[Entity]:
    return [
        _entity(text, PIIType.EMAIL, match.start(), match.end(), part, "regex-email")
        for match in EMAIL_RE.finditer(text)
    ]


def detect_ips(text: str, part: str = "body") -> list[Entity]:
    entities: list[Entity] = []
    for match in IPV4_RE.finditer(text):
        candidate = match.group(0)
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        entities.append(_entity(text, PIIType.IP, match.start(), match.end(), part, "ipv4-validation"))
    for match in IPV6_RE.finditer(text):
        candidate = match.group(0)
        try:
            ipaddress.ip_address(candidate)
        except ValueError:
            continue
        entities.append(_entity(text, PIIType.IP, match.start(), match.end(), part, "ipv6-validation"))
    return entities


def detect_ssns(text: str, part: str = "body") -> list[Entity]:
    entities: list[Entity] = []
    for match in SSN_RE.finditer(text):
        value = match.group("value")
        digits = _digits(value)
        # A contiguous nine-digit value needs an SSN context signal.  The
        # separated forms are validated independently and are unlikely to be
        # ordinary financial identifiers.
        separated = bool(re.search(r"[- ]", value))
        nearby = text[max(0, match.start() - 45) : match.end() + 45]
        contextual = bool(re.search(r"(?i)\b(?:ssn|social\s+security)\b", nearby))
        if not separated and not contextual:
            continue
        if digits[0:3] in {"000", "666"} or digits[0:3].startswith("9"):
            continue
        if digits[3:5] == "00" or digits[5:] == "0000":
            continue
        entities.append(_entity(text, PIIType.SSN, match.start(), match.end(), part, "regex-ssn"))
    return entities


def detect_credit_cards(text: str, part: str = "body") -> list[Entity]:
    entities: list[Entity] = []
    for match in CREDIT_CARD_RE.finditer(text):
        value = match.group("value")
        if _luhn_valid(value):
            entities.append(
                _entity(text, PIIType.CREDIT_CARD, match.start(), match.end(), part, "luhn")
            )
    return entities


def detect_phones(text: str, part: str = "body") -> list[Entity]:
    entities: list[Entity] = []
    for match in PHONE_RE.finditer(text):
        value = match.group("value").strip()
        digits = _digits(value)
        if not 7 <= len(digits) <= 15:
            continue
        if _looks_like_date(value):
            continue
        nearby = text[max(0, match.start() - 45) : match.end() + 45]
        has_country_code = value.lstrip().startswith("+")
        has_phone_context = bool(
            re.search(r"(?i)\b(?:phone|mobile|telephone|tel|contact|call|fax)\b", nearby)
        )
        ten_digit_mobile = len(digits) == 10 and digits[0] in "6789"
        eleven_digit_mobile = len(digits) == 11 and digits.startswith("0") and digits[1] in "6789"
        identifier_context = bool(
            re.search(
                r"(?i)\b(?:order|invoice|account|ticket|transaction|reference|ref|"
                r"identifier|number|code|page|revenue)\b",
                nearby,
            )
        )
        if identifier_context and not has_phone_context and not has_country_code:
            ten_digit_mobile = False
            eleven_digit_mobile = False
        if not (has_country_code or has_phone_context or ten_digit_mobile or eleven_digit_mobile):
            continue
        entities.append(_entity(text, PIIType.PHONE, match.start(), match.end(), part, "context-phone"))
    return entities


def detect_dobs(text: str, part: str = "body") -> list[Entity]:
    entities: list[Entity] = []
    for match in NUMERIC_DOB_RE.finditer(text):
        if not _has_local_dob_context(text, match.start(), match.end()):
            continue
        if not _valid_date(int(match.group("year")), int(match.group("month")), int(match.group("day"))):
            continue
        entities.append(_entity(text, PIIType.DOB, match.start(), match.end(), part, "context-dob"))

    for match in YEAR_FIRST_DOB_RE.finditer(text):
        if not _has_local_dob_context(text, match.start(), match.end()):
            continue
        if not _valid_date(int(match.group("year")), int(match.group("month")), int(match.group("day"))):
            continue
        entities.append(_entity(text, PIIType.DOB, match.start(), match.end(), part, "context-dob"))

    for match in TEXTUAL_DOB_RE.finditer(text):
        if not _has_local_dob_context(text, match.start(), match.end()):
            continue
        if match.group("month_name"):
            month_name = match.group("month_name")
            day = int(match.group("day"))
        else:
            month_name = match.group("month_name2")
            day = int(match.group("day2"))
        month = {
            "jan": 1, "january": 1,
            "feb": 2, "february": 2,
            "mar": 3, "march": 3,
            "apr": 4, "april": 4,
            "may": 5,
            "jun": 6, "june": 6,
            "jul": 7, "july": 7,
            "aug": 8, "august": 8,
            "sep": 9, "sept": 9, "september": 9,
            "oct": 10, "october": 10,
            "nov": 11, "november": 11,
            "dec": 12, "december": 12,
        }[month_name.lower()]
        year = int(match.group("year") or match.group("year2"))
        if not _valid_date(year, month, day):
            continue
        entities.append(_entity(text, PIIType.DOB, match.start(), match.end(), part, "context-dob"))
    return entities


def _clean_name(value: str) -> Optional[str]:
    # A capitalized label may be followed by a new sentence.  Do not let a
    # name rule consume that next sentence (for example ``Jane Smith. Green
    # Park``); initials such as ``J. Smith`` are left intact.
    sentence_boundary = re.search(r"\b[A-Za-z]{2,}\.(?=\s+[A-Z])", value)
    if sentence_boundary:
        value = value[: sentence_boundary.end() - 1]
    value = re.sub(r"\s+", " ", value).strip(" \t,;:-.")
    value = re.sub(r"^(?:Mr|Mrs|Ms|Miss|Dr|Prof|Shri|Smt)\.?\s+", "", value, flags=re.I)
    value = re.sub(r"\s+(?:Jr|Sr|III|II|Ltd)\.?$", "", value, flags=re.I)
    tokens = value.split()
    if not 2 <= len(tokens) <= 4:
        return None
    if any(token.lower().strip(".") in PERSON_SUFFIX_ORG_WORDS for token in tokens):
        return None
    if any(
        len(token.strip(".")) < 2 and not re.fullmatch(r"[A-Za-z]\.", token)
        for token in tokens
    ):
        return None
    if not all(re.fullmatch(r"[A-Za-z'’.-]+", token) for token in tokens):
        return None
    return value


def _add_name_candidate(
    entities: list[Entity], text: str, start: int, end: int, part: str, source: str
) -> None:
    raw = text[start:end]
    cleaned = _clean_name(raw)
    if cleaned is None:
        return

    # Use the cleaned span when a rule captured punctuation, a suffix, or a
    # following sentence.  Matching token-by-token keeps the offsets valid even
    # when the source contains multiple spaces.
    pattern = r"\s+".join(re.escape(token) for token in cleaned.split())
    cleaned_match = re.search(pattern, raw, flags=re.IGNORECASE)
    if cleaned_match is not None:
        start += cleaned_match.start()
        end = start + len(cleaned_match.group(0))

    # Preserve the original span except for surrounding whitespace/punctuation.
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    entities.append(_entity(text, PIIType.PERSON, start, end, part, source, score=0.95))


def detect_persons(text: str, part: str = "body") -> list[Entity]:
    entities: list[Entity] = []
    for pattern, source in (
        (TITLE_NAME_RE, "title-name"),
        (LABELED_NAME_RE, "context-name"),
        (ROLE_AFTER_NAME_RE, "role-name"),
    ):
        for match in pattern.finditer(text):
            start = match.start("value")
            end = match.end("value")
            _add_name_candidate(entities, text, start, end, part, source)

    # A bare name is accepted only when its first token is in a small general
    # first-name list and it is not an organization-like phrase.  Scanning
    # tokens instead of greedily matching a whole capitalized phrase avoids
    # losing ``Rashi Patil`` when a label such as ``Contact`` precedes it.
    token_re = re.compile(r"[A-Z](?:[A-Za-z'’.-]*[A-Za-z'’])?")
    tokens = list(token_re.finditer(text))
    for index, first_token in enumerate(tokens):
        if first_token.group(0).casefold() not in PERSON_FIRST_NAMES:
            continue
        for length in (2, 3, 4):
            if index + length > len(tokens):
                continue
            last_token = tokens[index + length - 1]
            between = text[first_token.end() : last_token.start()]
            if between.strip():
                continue
            candidate = text[first_token.start() : last_token.end()]
            if any(
                token.lower().strip(".") in PERSON_SUFFIX_ORG_WORDS
                for token in candidate.split()
            ):
                continue
            _add_name_candidate(
                entities,
                text,
                first_token.start(),
                last_token.end(),
                part,
                "name-heuristic",
            )
            break
    return entities


def _clean_org(value: str) -> Optional[str]:
    value = re.sub(r"\s+", " ", value).strip(" \t,;:-")
    # Do not let a sentence fragment become an organization.
    if len(value) < 3 or len(value.split()) > 8:
        return None
    if value.lower().startswith(("the ", "a ", "an ")):
        return None
    if re.search(r"(?i)\b(?:email|phone|address|date|director|promoter)\b", value):
        return None
    if not re.search(r"[A-Za-z]", value):
        return None
    return value


def detect_organizations(text: str, part: str = "body") -> list[Entity]:
    entities: list[Entity] = []
    for match in ORG_RE.finditer(text):
        cleaned = _clean_org(match.group(0))
        if cleaned is None:
            continue
        start = match.start() + (match.group(0).find(cleaned))
        end = start + len(cleaned)
        entities.append(_entity(text, PIIType.ORG, start, end, part, "legal-suffix", score=0.98))

    for match in ORG_CONTEXT_RE.finditer(text):
        cleaned = _clean_org(match.group("value"))
        if cleaned is None:
            continue
        value_start = match.start("value")
        start = value_start + (match.group("value").find(cleaned))
        end = start + len(cleaned)
        entities.append(_entity(text, PIIType.ORG, start, end, part, "organization-context", score=0.9))
    return entities


def _address_score(line: str) -> int:
    score = 0
    if ADDRESS_KEYWORD_RE.search(line):
        score += 2
    if POSTAL_CODE_RE.search(line):
        score += 2
    if line.count(",") >= 1:
        score += 1
    if ADDRESS_NUMBER_RE.search(line):
        score += 1
    if re.search(r"(?i)\b(?:city|state|district|province|postal\s+code|pin\s*code)\b", line):
        score += 1
    return score


def detect_addresses(text: str, part: str = "body") -> list[Entity]:
    """Find complete address-like lines without treating a lone city as PII.

    The detector intentionally requires an address keyword, a house/building
    number plus locality structure, or a postal code with multiple components.
    It is a practical high-precision rule for RHP contact blocks; a production
    system can replace this method with a trained address NER model.
    """

    entities: list[Entity] = []
    for line_match in re.finditer(r"[^\r\n]*", text):
        line = line_match.group(0)
        if not line.strip():
            continue
        # Treat semicolon-delimited fields independently.  Without this split
        # a line such as "name; phone; address" would be truncated at the first
        # semicolon and the address would never be considered.
        if ";" in line:
            cursor = 0
            for chunk in line.split(";"):
                chunk_start = line_match.start() + cursor
                for sub_entity in detect_addresses(chunk, part):
                    entities.append(
                        _entity(
                            text,
                            sub_entity.pii_type,
                            chunk_start + sub_entity.start,
                            chunk_start + sub_entity.end,
                            part,
                            sub_entity.detector,
                            score=sub_entity.score,
                        )
                    )
                cursor += len(chunk) + 1
            continue
        if _address_score(line) < 3:
            continue
        # A PIN alone is not an address.
        if not ADDRESS_KEYWORD_RE.search(line):
            if not (POSTAL_CODE_RE.search(line) and line.count(",") >= 1 and ADDRESS_NUMBER_RE.search(line)):
                continue

        start = line_match.start()
        end = line_match.end()
        label = ADDRESS_LABEL_RE.search(line)
        if label:
            start += label.end()

        # A semicolon commonly separates a complete address from a following
        # telephone/email field.  Do not absorb that next field into the
        # address span.
        semicolon = line.find(";", max(0, start - line_match.start()))
        if semicolon >= 0:
            end = line_match.start() + semicolon

        # Prefer a house/building number after a label.  Otherwise begin at the
        # first address keyword; this preserves the street/locality span.
        number = ADDRESS_NUMBER_RE.search(line, max(0, start - line_match.start()))
        keyword = ADDRESS_KEYWORD_RE.search(line, max(0, start - line_match.start()))
        candidates: list[int] = []
        if number:
            candidates.append(line_match.start() + number.start())
        if keyword:
            # Include a preceding title such as "Green" in "Green Park Road".
            prefix = line[: keyword.start()]
            words = re.findall(r"[A-Za-z][A-Za-z .'-]*$", prefix)
            if words:
                candidates.append(line_match.start() + prefix.rfind(words[-1].strip()))
            candidates.append(line_match.start() + keyword.start())
        if not candidates:
            # Numeric postal address without a street keyword.
            candidates = [start]
        start = min(candidates)

        # Trim sentence punctuation and whitespace without touching internal
        # commas or periods in legitimate locality names.
        while start < end and (text[start].isspace() or text[start] in ":-,"):
            start += 1
        while end > start and (text[end - 1].isspace() or text[end - 1] in ".,;:"):
            end -= 1
        if end <= start or not text[start:end].strip():
            continue
        # Reject a line that is only a label or a bare postal code.
        candidate_text = text[start:end]
        if len(candidate_text) < 8 or _looks_like_date(candidate_text):
            continue
        entities.append(_entity(text, PIIType.ADDRESS, start, end, part, "address-context", score=0.96))
    return entities


# ---------------------------------------------------------------------------
# Optional NER adapter and overlap resolution
# ---------------------------------------------------------------------------


class OptionalSpacyDetector:
    """Load spaCy lazily; do not make a model download a hard requirement."""

    def __init__(self, model_name: str = "en_core_web_sm") -> None:
        self.model_name = model_name
        self._nlp = None
        self._attempted = False

    def entities(self, text: str, part: str) -> list[Entity]:
        if not self._attempted:
            self._attempted = True
            try:
                import spacy  # type: ignore

                self._nlp = spacy.load(self.model_name)
            except Exception:
                self._nlp = None
        if self._nlp is None:
            return []
        try:
            doc = self._nlp(text)
        except Exception:
            return []
        output: list[Entity] = []
        for ent in doc.ents:
            if ent.label_ not in {"PERSON", "ORG"}:
                continue
            pii_type = PIIType.PERSON if ent.label_ == "PERSON" else PIIType.ORG
            if pii_type == PIIType.PERSON:
                cleaned = _clean_name(ent.text)
                if cleaned is None:
                    continue
            output.append(
                Entity(
                    text=ent.text,
                    pii_type=pii_type,
                    start=ent.start_char,
                    end=ent.end_char,
                    part=part,
                    context=_context_snippet(text, ent.start_char, ent.end_char),
                    score=0.9,
                    detector="spacy",
                )
            )
        return output


_PRIORITY = {
    PIIType.ADDRESS: 100,
    PIIType.CREDIT_CARD: 98,
    PIIType.SSN: 97,
    PIIType.EMAIL: 96,
    PIIType.IP: 95,
    PIIType.DOB: 94,
    PIIType.PHONE: 90,
    PIIType.ORG: 80,
    PIIType.PERSON: 70,
}


def resolve_overlaps(entities: Iterable[Entity]) -> list[Entity]:
    """Prefer complete/structured entities and remove nested duplicates."""

    unique: dict[tuple[int, int, PIIType], Entity] = {}
    for entity in entities:
        key = (entity.start, entity.end, entity.pii_type)
        current = unique.get(key)
        if current is None or entity.score > current.score:
            unique[key] = entity

    ordered = sorted(
        unique.values(),
        key=lambda item: (item.start, -(item.end - item.start), -_PRIORITY[item.pii_type], -item.score),
    )
    selected: list[Entity] = []
    for candidate in ordered:
        conflict = next(
            (
                existing
                for existing in selected
                if candidate.start < existing.end and existing.start < candidate.end
            ),
            None,
        )
        if conflict is None:
            selected.append(candidate)
            continue
        candidate_priority = (_PRIORITY[candidate.pii_type], candidate.end - candidate.start, candidate.score)
        conflict_priority = (_PRIORITY[conflict.pii_type], conflict.end - conflict.start, conflict.score)
        if candidate_priority > conflict_priority:
            selected.remove(conflict)
            selected.append(candidate)
    return sorted(selected, key=lambda item: (item.start, item.end))


class PIIDetector:
    """Facade combining all category detectors."""

    def __init__(self, use_spacy: bool = True, spacy_model: str = "en_core_web_sm") -> None:
        self.optional_spacy = OptionalSpacyDetector(spacy_model) if use_spacy else None

    def detect(
        self, text: str, part: str = "body", context_prefix: str = ""
    ) -> list[Entity]:
        """Detect entities in one text unit.

        ``context_prefix`` is an optional already-extracted neighbouring label
        (for example, a table-cell label immediately before a DOB value).  It
        is used only for contextual detectors and is never emitted as an
        entity itself.
        """

        entities: list[Entity] = []
        entities.extend(detect_emails(text, part))
        entities.extend(detect_ips(text, part))
        entities.extend(detect_ssns(text, part))
        entities.extend(detect_credit_cards(text, part))
        entities.extend(detect_phones(text, part))
        if context_prefix:
            prefix = context_prefix.rstrip() + "\n"
            prefix_entities = detect_dobs(prefix + text, part)
            for entity in prefix_entities:
                if entity.start >= len(prefix):
                    entities.append(
                        Entity(
                            text=entity.text,
                            pii_type=entity.pii_type,
                            start=entity.start - len(prefix),
                            end=entity.end - len(prefix),
                            part=entity.part,
                            context=_context_snippet(text, entity.start - len(prefix), entity.end - len(prefix)),
                            score=entity.score,
                            detector=entity.detector,
                        )
                    )
        else:
            entities.extend(detect_dobs(text, part))
        entities.extend(detect_addresses(text, part))
        entities.extend(detect_organizations(text, part))
        entities.extend(detect_persons(text, part))
        if self.optional_spacy is not None:
            entities.extend(self.optional_spacy.entities(text, part))
        return resolve_overlaps(entities)

    def detect_text(self, text: str, part: str = "body") -> list[Entity]:
        """Alias useful to callers that want to emphasize text-only use."""

        return self.detect(text, part)
