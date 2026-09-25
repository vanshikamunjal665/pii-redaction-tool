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

# A Luhn-valid sixteen-digit string is not proof of a card.  These two
# patterns let an identifier label veto the match unless a card word says
# otherwise, which is what keeps registration and reference numbers clear.
CARD_IDENTIFIER_CONTEXT_RE = re.compile(
    r"(?i)\b(?:order|invoice|account|ticket|transaction|reference|ref|"
    r"identifier|number|no|code|page|revenue|receipt|cheque|check)\b"
)
CARD_CONTEXT_RE = re.compile(
    r"(?i)\b(?:card|credit\s+card|debit\s+card|vis[ae]|mastercard|amex|"
    r"maestro|rupay|cvv|cvc|expiry|expiration)\b"
)

# The expression is intentionally permissive about separators; validation
# below rejects ordinary long numbers, dates, and identifiers.
PHONE_RE = re.compile(
    r"(?<![\w])(?P<value>"
    r"(?:\+\s*\d{1,3}[\s.\-]?)?"
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

# Legal suffixes are the strongest organization signal.  Weak business
# suffixes (for example ``Services`` or ``Corporation``) are handled separately
# because they also occur in ordinary prose.
ORG_LEGAL_SUFFIX_PATTERN = (
    r"(?<![A-Za-z0-9])(?:Private\s+Limited|Pvt\.?\s*Ltd\.?|Limited|Ltd\.?|LLP|LLC|Inc\.?|"
    r"Incorporated|Corporation|Corp\.?|Co\.|P\.C\.?|PLC|GmbH|S\.A\.?|"
    r"AB|N\.A\.)(?:\s+of\s+India)?(?![A-Za-z0-9])"
)
ORG_BUSINESS_SUFFIX_PATTERN = (
    r"(?<![A-Za-z0-9])(?:Technologies|Technology|Solutions|Services|Industries|Enterprises|"
    r"Group|Holdings|Corporation|Company|Trust|Foundation|Association|"
    r"Associates|Partners|Partnership|Consultants|Advisors|Advisers)(?![A-Za-z0-9])"
)
ORG_TOKEN_PATTERN = r"(?:[A-Z][A-Za-z0-9&'’().-]*|\([A-Z][A-Za-z0-9&'’().-]*\)|\d+|and|of|the|for|&)"
# Retained as a public-ish constant for callers that want the complete suffix
# vocabulary, but the main matcher below uses the stronger legal form.
ORG_SUFFIX_PATTERN = rf"(?:{ORG_LEGAL_SUFFIX_PATTERN}|{ORG_BUSINESS_SUFFIX_PATTERN})"
ORG_RE = re.compile(
    rf"(?<![A-Za-z0-9])(?:(?:{ORG_TOKEN_PATTERN})\s+){{1,10}}"
    rf"{ORG_LEGAL_SUFFIX_PATTERN}(?![A-Za-z0-9])"
)
ORG_BUSINESS_RE = re.compile(
    rf"(?<![A-Za-z0-9])(?:(?:{ORG_TOKEN_PATTERN})\s+){{1,8}}"
    rf"{ORG_BUSINESS_SUFFIX_PATTERN}(?![A-Za-z0-9])"
)
# Formatting variants in the source include all-caps promoter lists.  Keep a
# separate case-insensitive matcher for those units instead of globally
# ignoring case, which would turn ordinary prose such as ``prepared ... by``
# into an organization candidate.
ORG_UPPER_RE = re.compile(
    rf"(?<![A-Za-z0-9])(?:(?:{ORG_TOKEN_PATTERN})\s+){{1,10}}"
    rf"{ORG_LEGAL_SUFFIX_PATTERN}(?![A-Za-z0-9])",
    re.IGNORECASE,
)
ORG_BUSINESS_UPPER_RE = re.compile(
    rf"(?<![A-Za-z0-9])(?:(?:{ORG_TOKEN_PATTERN})\s+){{1,8}}"
    rf"{ORG_BUSINESS_SUFFIX_PATTERN}(?![A-Za-z0-9])",
    re.IGNORECASE,
)
ORG_CONTEXT_RE = re.compile(
    r"(?i)\b(?:company|issuer|registrant|promoter|undertaking|vendor|supplier|"
    r"bank|name\s+of\s+company)\s*(?:name\s*)?(?:[:\-]|\bis\b)\s*"
    r"(?P<value>[A-Z][A-Za-z0-9&'’.,() -]{2,100}?)(?=[,;\n]|$)"
)
ORG_LIST_CONTEXT_RE = re.compile(
    r"(?i)\b(?:top\s+\d+\s+)?(?:customers|suppliers|vendors|service\s+providers)\s+"
    r"(?:include|comprise|are)\s+"
)
ORG_LOOSE_CONTEXT_RE = re.compile(
    r"(?<![A-Za-z0-9])(?P<value>[A-Z][A-Za-z'’.-]+(?:\s+[A-Z][A-Za-z'’.-]+){1,3})"
    r"(?![A-Za-z0-9])"
)
ORG_LOOSE_HEAD_WORDS = {
    "associates",
    "partners",
    "consultants",
    "advisors",
    "advisers",
    "technologies",
    "technology",
    "systems",
    "solutions",
    "services",
    "industries",
    "industry",
    "capital",
    "ventures",
    "engineering",
    "electricals",
    "electronics",
    "transformers",
    "switchgear",
    "motors",
    "products",
    "energy",
    "power",
    "steel",
    "copper",
    "corporation",
    "company",
    "holdings",
}

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
    r"\s*[,;:-]?\s*(?i:chief\s+executive\s+officer|chief\s+financial\s+officer|"
    r"company\s+secretary|compliance\s+officer|technical\s+director|"
    r"joint\s+managing\s+director|managing\s+director|whole-time\s+director|"
    r"executive\s+director|independent\s+director|non-executive\s+director|"
    r"director|promoter|chairman|signatory|authori[sz]ed\s+signatory|partner|"
    r"contact\s+person|beneficial\s+owner)\b"
)

# A capitalised sequence is a useful high-recall candidate only when a
# person-oriented trigger or a table label surrounds it.  The cleanup function
# below removes headings, role phrases, organization names, and all-caps
# prospectus labels.
PERSON_SEQUENCE_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?P<value>(?:[A-Z][A-Za-z'’.-]*|[A-Z]\.|[A-Z]{2,5})"
    r"(?:\s+(?:[A-Z][A-Za-z'’.-]*|[A-Z]\.|[A-Z]{2,5})){1,3})"
    r"(?![A-Za-z0-9])"
)
PERSON_CONTEXT_TRIGGER_RE = re.compile(
    r"(?i)\b(?:contact\s+person|being|namely|allotted\s+to|"
    r"(?:appointed|regularized|regularised)\s+(?:as|to|in)|"
    r"in\s+relation\s+to|led\s+by|including|our\s+promoters?|"
    r"promoter\s+group|promoter\s+selling\s+shareholders?|"
    r"name\s+of\s+(?:the\s+)?(?:promoter|shareholder|director|person))\b"
)
PERSON_TABLE_CONTEXT_RE = re.compile(
    r"(?i)\b(?:name\s+of\s+(?:the\s+)?(?:promoter|shareholder|director|person)|"
    r"contact\s+person|promoters?|promoter\s+group|designation|din|"
    r"key\s+managerial\s+personnel|senior\s+management)\b"
)
# Share-transfer rows label the parties only through the transfer sentence.
PERSON_TRANSFER_CUE_RE = re.compile(
    r"(?i)\btransfer\s+of\s+shares?\s+(?:to|from|by)\s+"
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
# Section titles and defined terms that are title-cased exactly like a person
# name.  A cue such as ``see "General Information"`` must not be read as a
# name, and these words must not seed document-level name propagation.
PERSON_HEADING_WORDS = {
    "general", "information", "risk", "factors", "objects", "industry",
    "overview", "business", "management", "corporate", "governance",
    "financial", "statements", "accounting", "policies", "capital",
    "structure", "dividend", "tax", "regulatory", "disclosures", "material",
    "events", "development", "intellectual", "property", "plant",
    "machinery", "history", "scheme", "main", "board", "terms", "the",
    "issue", "offer", "undertaking", "market", "price", "distribution",
    "share", "shares", "conflict", "interest", "related", "transaction",
    "litigation", "promoters", "group", "sales", "profits", "facilities",
    "infrastructure", "use", "proceeds", "valuation", "credit", "rating",
    "government", "approvals", "definitions", "abbreviations", "glossary",
    "documents", "inspection", "contracts", "licence", "licenses",
    "subsidiaries", "report", "profile", "instruments", "statistics",
    "summary", "details", "contents", "annexure", "memorandum", "articles",
    "certificate", "declaration", "undertakings", "resolution", "resolutions",
    "benefits", "employees", "insurance", "litigations", "regulations",
    "guidelines", "policies", "policy", "standards", "codes", "rules",
}

PERSON_SUFFIX_ORG_WORDS = {
    "technologies", "technology", "limited", "ltd", "pvt", "company",
    "corporation", "corp", "inc", "llp", "services", "solutions", "group",
    "holdings", "industries", "enterprises", "bank", "university", "school",
    "ministry", "government", "india", "global", "capital", "systems",
    "private", "public", "trust", "foundation", "association", "industrial",
    "park", "road", "street", "floor", "building", "apartment", "village",
    "taluka", "district", "state", "office", "campus", "website", "email",
    "telephone", "phone", "registration", "sebi", "icdr", "offer", "bids",
    "chartered", "accountants", "auditors", "statutory", "statutorily",
    "practicing", "professional", "engineer", "consultant", "advisor",
    "book", "running", "lead", "managers", "manager", "exchange", "london",
    "metal", "metropolitan", "region", "development", "authority", "kamgar",
    "sangathna", "land", "leasehold", "freehold", "assets", "proceeds",
    "anchor", "investor", "investors", "institutional", "non", "qib", "qibs",
    "retail", "individual", "bidders", "bidder", "shares", "share", "care",
    "report", "risk", "factors", "companies", "act", "supa", "facility",
    "manufacturing", "facilities", "other", "materiality", "policy",
    "gross", "state", "insurance", "contributions", "provident", "funds",
    "miscellaneous", "provisions", "tax", "department", "office", "road",
    "show", "presentation", "questions", "strategy", "including", "details",
    "red", "herring", "prospectus", "eligible", "nris", "ksh", "infra",
    "key", "managerial", "careedge", "research", "related", "party",
    "transactions", "analytics", "advisory", "national", "payments",
    "corporation", "stock", "financial", "statements", "assets", "liabilities",
    "board", "shareholders", "provisions", "main", "articles", "memorandum",
    "goods", "services", "bankers", "escrow", "collection", "offer", "net",
    "syndicate", "members", "bonus", "issue", "specified", "locations", "client",
    "id", "pension", "fund", "regulatory", "social", "responsibility", "committee",
    "csr", "allotment", "advice", "branch", "parents", "maharashtra", "pollution",
    "control", "family", "trust", "no", "s", "society", "building", "floor",
    "road", "marg", "centre", "center", "house", "flat", "apartment", "plot",
}
# Document-reference words that look like name tokens in running text
# ("MoA dated June 29, 1979", "shareholders agreement").
PERSON_DOCUMENT_WORDS = {
    "moa", "aoa", "aod", "sha", "dated", "date", "amendment", "addendum",
    "memorandum", "articles", "agreement", "deed", "undertaking",
    "resolution", "certificate", "consent", "affidavit", "declaration",
    "petition", "commission", "report", "order", "form", "schedule",
}

PERSON_NON_NAME_WORDS = {
    "a", "an", "and", "are", "as", "at", "be", "being", "by", "chief",
    "compliance", "company", "contact", "corporate", "director", "executive",
    "for", "from", "full", "in", "including", "is", "our", "person", "promoter",
    "promoters", "register", "registered", "registrar", "selling", "signatory",
    "shareholder", "shareholders", "technical", "the", "to", "being", "name",
    "names", "secretary", "website", "with", "and", "or", "of", "on", "chairman",
    "managing", "joint", "whole-time", "independent", "non-executive", "beneficial",
    "owner", "kmp", "sm", "ceo", "cfo", "cs", "compliance", "officer",
    "financial", "executive", "management", "personnel", "details", "of",
    "promoter", "selling", "shareholder", "offer", "face", "value", "equity",
    "shares", "date", "acquisition", "number", "price", "revenue", "sector",
    "generation", "transmission", "distribution", "industry", "market", "floor",
}

ADDRESS_STRONG_KEYWORD_RE = re.compile(
    r"(?i)\b(?:house|flat|apartment|appt|residence|road|rd\.?|street|st\.?|"
    r"lane|colony|nagar|marg|avenue|ave\.?|boulevard|drive|dr\.?|plot|"
    r"tower|villa|village|taluka|district|gat|wing|campus|complex|"
    r"chambers|hospital|industrial\s+area|industrial\s+estate|center|centre)\b"
)
ADDRESS_WEAK_KEYWORD_RE = re.compile(
    r"(?i)\b(?:building|floor|block|sector|office|department|level|park)\b"
)
ADDRESS_KEYWORD_RE = re.compile(
    r"(?i)\b(?:house|flat|apartment|appt|residence|road|rd\.?|street|st\.?|"
    r"lane|colony|nagar|marg|avenue|ave\.?|boulevard|drive|dr\.?|plot|"
    r"tower|villa|village|taluka|district|gat|wing|campus|complex|"
    r"industrial\s+area|industrial\s+estate|center|centre|building|floor|"
    r"block|sector|office|department|level|park)\b"
)
ADDRESS_LABEL_RE = re.compile(
    r"(?i)\b(?:registered\s+office|corporate\s+office|principal\s+office|"
    r"office\s+address|home\s+address|mailing\s+address|address|"
    r"contact\s+details?)\b\s*(?:(?:is|at)\s+|:\s*)"
)
# A label/cue is deliberately stricter than a bare mention of ``office``.
# It marks the beginning of a value which may be split across table cells.
ADDRESS_CUE_RE = re.compile(
    r"(?i)\b(?:registered\s+office|corporate\s+office|principal\s+office|"
    r"office\s+address|home\s+address|mailing\s+address|address|"
    r"contact\s+details?)\b\s*(?:(?:is|at)\s+|:\s*)"
)
ADDRESS_IDENTIFIER_LABEL_RE = re.compile(
    r"(?i)\b(?:cin|corporate\s+identity\s+number|firm\s+registration|"
    r"peer\s+review|registration\s+number|reference\s+number|"
    r"identifier\s+number)\b"
)
ADDRESS_FIELD_BOUNDARY_RE = re.compile(
    r"(?i)\b(?:telephone|phone|mobile|e-?mail|email|website|web\s+site|"
    r"contact\s+person)\s*:"
)
POSTAL_CODE_RE = re.compile(r"(?<![\w])\d{3}\s?\d{3}(?![\w])")
# Include ordinals and alphanumeric house/flat identifiers.  The old pattern
# started at the digits in ``10th`` and left ``th`` outside the address span.
ADDRESS_NUMBER_RE = re.compile(
    r"(?<!\w)(?:[A-Z]\.\s*)?(?:[A-Z]?\d{1,4}[A-Za-z]{0,3}"
    r"(?:[-/]\d+)?)(?=\s|[,.;])",
    re.IGNORECASE,
)
ADDRESS_PREFIX_RE = re.compile(
    r"(?i)(?<!\w)(?:[A-Z]\.\s*no\.?|s\.?\s*no\.?|gat\s+no\.?|"
    r"flat\s+no\.?|plot\s+no\.?|house\s+no\.?)\s*\.?\s*"
)
ADDRESS_PROSE_RE = re.compile(
    r"(?i)\b(?:form|filed|filing|incorporation|challan|application|reservation|"
    r"intimation|certificate|dated|respectively|approval|license|licence|"
    r"registration|commission|consent|dated)\b"
)


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
        if not _luhn_valid(value):
            continue
        # A Luhn-valid sixteen-digit string is not proof of a card.  The policy
        # treats identifier numbers as non-PII, so an identifier label in the
        # lead-in suppresses the match unless a card word is also present.
        lead_in = text[max(0, match.start() - 45) : match.start()]
        if CARD_IDENTIFIER_CONTEXT_RE.search(lead_in) and not CARD_CONTEXT_RE.search(
            text[max(0, match.start() - 45) : match.end() + 45]
        ):
            continue
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
        # Only the text *before* the number can label it.  A contact word that
        # happens to appear later in the sentence ("Ticket No. 9876543210,
        # please contact us") describes the sentence, not the number.
        lead_in = text[max(0, match.start() - 45) : match.start()]
        has_country_code = value.lstrip().startswith("+")
        has_phone_context = bool(
            re.search(r"(?i)\b(?:phone|mobile|telephone|tel|contact|call|fax)\b", lead_in)
        )
        ten_digit_mobile = len(digits) == 10 and digits[0] in "6789"
        eleven_digit_mobile = len(digits) == 11 and digits.startswith("0") and digits[1] in "6789"
        identifier_context = bool(
            re.search(
                r"(?i)\b(?:order|invoice|account|ticket|transaction|reference|ref|"
                r"identifier|number|code|page|revenue)\b",
                lead_in,
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

    # Prospectus headings and role phrases are often title-cased in the same
    # way as names.  An all-caps heading is never accepted by the fallback
    # rule; title-case headings are filtered through the explicit stop list.
    if value.isupper():
        return None
    normalized = [token.casefold().strip(".,") for token in tokens]
    if any(
        token in PERSON_SUFFIX_ORG_WORDS or token in PERSON_NON_NAME_WORDS
        for token in normalized
    ):
        return None
    if any(
        len(token.strip(".")) < 2 and not re.fullmatch(r"[A-Za-z]\.", token)
        for token in tokens
    ):
        return None
    # A name made only of section-title/defined-term words is prose, not a
    # person ("General Information", "Risk Factors").
    if all(token in PERSON_HEADING_WORDS for token in normalized):
        return None
    # Document references such as "MoA dated June" or "shareholders agreement"
    # are reference phrases, never people.
    if any(token in PERSON_DOCUMENT_WORDS for token in normalized):
        return None
    if not all(re.fullmatch(r"[A-Za-z'’.-]+", token) for token in tokens):
        return None
    if any(token.isdigit() for token in tokens):
        return None
    return value


def _add_name_candidate(
    entities: list[Entity], text: str, start: int, end: int, part: str, source: str
) -> None:
    raw = text[start:end]
    token_matches = list(re.finditer(r"[A-Za-z][A-Za-z'’.-]*", raw))
    if len(token_matches) < 2:
        return

    # Try the longest prefix first.  This handles a rule that captured a role
    # or field label after the name (``Chitra Raste Website``) while retaining
    # the exact source offsets of the name itself.
    chosen: Optional[tuple[str, int, int]] = None
    for length in range(min(4, len(token_matches)), 1, -1):
        first = token_matches[0]
        last = token_matches[length - 1]
        raw_candidate = raw[first.start() : last.end()]
        cleaned = _clean_name(raw_candidate)
        if cleaned is not None:
            chosen = (cleaned, first.start(), last.end())
            break
    if chosen is None:
        return

    cleaned, relative_start, relative_end = chosen
    pattern = r"\s+".join(re.escape(token) for token in cleaned.split())
    cleaned_match = re.search(pattern, raw[relative_start:relative_end], flags=re.IGNORECASE)
    if cleaned_match is not None:
        start += relative_start + cleaned_match.start()
        end = start + len(cleaned_match.group(0))
    else:
        start += relative_start
        end = start + relative_end - relative_start

    # Preserve the original span except for surrounding whitespace/punctuation.
    while start < end and text[start].isspace():
        start += 1
    while end > start and text[end - 1].isspace():
        end -= 1
    entities.append(_entity(text, PIIType.PERSON, start, end, part, source, score=0.95))


def _person_unit_is_name_like(text: str) -> bool:
    value = text.strip()
    if not value or len(value) > 90 or value.isupper():
        return False
    if re.search(r"\d|₹|\$|@|https?://|www\\.", value, flags=re.IGNORECASE):
        return False
    if ADDRESS_STRONG_KEYWORD_RE.search(value) or ADDRESS_WEAK_KEYWORD_RE.search(value):
        return False
    if re.search(r"[,:;()\[\]{}]", value):
        # Footnote markers and a single trailing separator are harmless; an
        # internal comma/semicolon usually means a list or neighboring field.
        trimmed = re.sub(r"[*&^]+", "", value.strip()).rstrip(",;")
        if re.search(r"[,;:()\[\]{}]", trimmed):
            return False
    return True


def _person_trigger_segments(text: str) -> list[tuple[int, str]]:
    """Return only short spans following person-oriented markers.

    Generic prospectus prose often contains ``being`` or ``including`` in a
    non-person sense.  A marker is therefore accepted only when the preceding
    clause supplies a person/role signal, except for the explicit contact and
    allotment/consent forms.
    """

    person_prior = re.compile(
        r"(?i)\b(?:chairman|director|promoter|secretary|officer|auditor|"
        r"engineer|management|manager|kmp|sm|person|shareholder|individual|"
        r"consent|expert)\b"
    )
    # The fourth element marks a list-style cue whose value continues past a
    # comma (``alloted to A, B and C``).  Value extraction itself is driven by
    # the name-sequence scanner, so an early comma stop is not needed.
    markers: tuple[tuple[re.Pattern[str], int, bool, bool], ...] = (
        (re.compile(r"(?i)\bcontact\s+person\b"), 150, False, False),
        (re.compile(r"(?i)\bbeing\s*,?\s*"), 110, True, False),
        (re.compile(r"(?i)\bnamely\s*,?\s*"), 150, True, False),
        (re.compile(r"(?i)\ballotted\s+to\s+"), 140, False, True),
        (re.compile(r"(?i)\bin\s+relation\s+to\s+"), 100, True, False),
        (re.compile(r"(?i)\b(?:appointed|regularized|regularised)\s+(?:as|to|in)\s+"), 110, True, False),
        (re.compile(r"(?i)\bled\s+by\s+"), 280, True, False),
        (re.compile(r"(?i)\bincluding\s*,?\s*"), 280, True, False),
        (re.compile(r"(?i)\bour\s+promoters?\s*[:,]?\s*"), 280, False, False),
        (re.compile(r"(?i)\bpromoter\s+group\s*[:,]?\s*"), 280, False, False),
    )
    segments: list[tuple[int, str]] = []
    for pattern, window, requires_person_prior, _list_style in markers:
        for match in pattern.finditer(text):
            if requires_person_prior:
                prior = text[max(0, match.start() - 180) : match.start()]
                following = text[match.end() : match.end() + 120]
                if not person_prior.search(prior) and not person_prior.search(following):
                    continue
            start = match.end()
            tail = text[start : start + window]
            # Stop at a field separator or sentence boundary.  A period in an
            # initial (``S.``) is retained by requiring whitespace after it.
            # A comma only ends the segment for markers that introduce a single
            # value; list-style cues keep scanning so every listed name is kept.
            stop = re.search(
                r"(?i)(?:;|(?<![A-Z])\.(?=\s+[A-Z])|(?<![A-Z])\.(?=\s*$)|"
                r"\b(?:telephone|email| website)\s*:)",
                tail,
            )
            if stop:
                tail = tail[: stop.start()]
            if tail.strip():
                segments.append((start, tail))

    # A consent sentence often says "consent ... from <natural person>" rather
    # than using one of the generic markers above.
    for match in re.finditer(r"(?i)\bfrom\b", text):
        prior = text[max(0, match.start() - 150) : match.start()]
        if not re.search(r"(?i)\b(?:consent|name|secretary|auditor|engineer)\b", prior):
            continue
        start = match.end()
        tail = text[start : start + 120]
        stop = re.search(r"(?i)(?:,|(?<![A-Z])\.(?=\s+[A-Z]))", tail)
        if stop:
            tail = tail[: stop.start()]
        if tail.strip():
            segments.append((start, tail))
    return segments


def _name_token_gap_ok(between: str) -> bool:
    """Return whether the gap between two name tokens is acceptable.

    A comma, semicolon, ampersand, or sentence period separates names, but the
    period of an initial (``Karunakar N. Bhandary``) is part of the name and
    must not be treated as a boundary.
    """

    without_initials = re.sub(r"(?<![A-Za-z])[A-Z]\.", "", between)
    return re.search(r"[.;:!?&=]", without_initials) is None


def _iter_person_sequences(segment: str) -> list[tuple[int, int]]:
    """Yield non-overlapping plausible name spans from a short text segment."""

    token_re = re.compile(
        r"(?<![A-Za-z0-9])(?:[A-Z]\.|[A-Z][A-Za-z'’.-]*[A-Za-z'’]|[A-Z][A-Za-z'’.-]*\.)"
    )
    tokens = list(token_re.finditer(segment))
    candidates: list[tuple[int, int, int]] = []
    for index, first in enumerate(tokens):
        chosen: Optional[tuple[int, int]] = None
        for length in range(min(4, len(tokens) - index), 1, -1):
            last = tokens[index + length - 1]
            between = segment[first.end() : last.start()]
            # Commas and slashes separate names in contact/promoter lists.  An
            # ampersand is deliberately not accepted: it usually joins an
            # organization (``Kirtane & Pandit``) rather than two people.
            if not _name_token_gap_ok(between):
                continue
            raw = segment[first.start() : last.end()]
            if _clean_name(raw) is None:
                continue
            chosen = (first.start(), last.end())
            break
        if chosen is not None:
            candidates.append((chosen[0], chosen[1], -(chosen[1] - chosen[0])))

    # Prefer a longer candidate at the same start, then remove candidates
    # nested in an already selected span.  This lets ``Kushal Subbayya Hegde``
    # survive when a preceding generic token would otherwise hide it.
    candidates.sort(key=lambda item: (item[0], item[2], -item[1]))
    selected: list[tuple[int, int]] = []
    for start, end, _ in candidates:
        if any(start < old_end and old_start < end for old_start, old_end in selected):
            continue
        selected.append((start, end))
    return sorted(selected)


def _clean_transfer_name(value: str) -> Optional[str]:
    """Validate a person name taken from a share-transfer row.

    The surrounding sentence is explicit ("transfer of shares to <name>"), so
    the remaining risk is a neighbouring capitalised acronym or regulation
    name.  Every token must therefore look like a name token: a capitalised
    word, an initial with a period, or a very short all-caps initialism.
    """

    value = re.sub(r"\s+", " ", value).strip(" \t,;:-.")
    tokens = value.split()
    if not 2 <= len(tokens) <= 4:
        return None
    normalized = [token.casefold().strip(".,") for token in tokens]
    if any(
        token in PERSON_SUFFIX_ORG_WORDS or token in PERSON_NON_NAME_WORDS
        for token in normalized
    ):
        return None
    if all(token in PERSON_HEADING_WORDS for token in normalized):
        return None
    if any(token in PERSON_DOCUMENT_WORDS for token in normalized):
        return None
    for token in tokens:
        if re.fullmatch(r"[A-Za-z]\.", token):
            continue
        if re.fullmatch(r"[A-Z][a-z][A-Za-z'’-]*", token):
            continue
        # Short all-caps initialisms such as ``DM``/``SA`` occur in Indian
        # name records; a longer acronym is a regulator or a defined term.
        if re.fullmatch(r"[A-Z]{1,3}", token):
            continue
        return None
    return value


def _iter_transfer_sequences(segment: str) -> list[tuple[int, int]]:
    """Yield person-name spans from a share-transfer row segment."""

    token_re = re.compile(
        r"(?<![A-Za-z0-9])(?:[A-Z]\.|[A-Z][A-Za-z'’-]*|[A-Z]{1,3})(?![a-z])"
    )
    tokens = list(token_re.finditer(segment))
    candidates: list[tuple[int, int, int]] = []
    for index, first in enumerate(tokens):
        for length in range(min(4, len(tokens) - index), 1, -1):
            last = tokens[index + length - 1]
            between = segment[first.end() : last.start()]
            if not _name_token_gap_ok(between) or "," in between:
                continue
            if _clean_transfer_name(segment[first.start() : last.end()]) is None:
                continue
            candidates.append((first.start(), last.end(), -length))
            break
    candidates.sort(key=lambda item: (item[0], item[2], -item[1]))
    selected: list[tuple[int, int]] = []
    for start, end, _ in candidates:
        if any(start < old_end and old_start < end for old_start, old_end in selected):
            continue
        selected.append((start, end))
    return sorted(selected)


def detect_persons(
    text: str, part: str = "body", context_prefix: str = ""
) -> list[Entity]:
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

    recent_context = context_prefix[-600:]
    has_table_context = bool(PERSON_TABLE_CONTEXT_RE.search(recent_context))
    for segment_start, segment in _person_trigger_segments(text):
        # A cue can be followed by a cross-reference instead of a person:
        # ``see "General Information" on pages 74 and 26``.  Quoted spans and
        # page references are not name values.
        if re.match(r"\s*[\"“‘']", segment):
            continue
        if re.match(r"\s*(?:page|pages|section|chapter|part)\b", segment, re.IGNORECASE):
            continue
        for relative_start, relative_end in _iter_person_sequences(segment):
            _add_name_candidate(
                entities,
                text,
                segment_start + relative_start,
                segment_start + relative_end,
                part,
                "context-name",
            )

    # A share-transfer row names the transferor/transferee without any role
    # label, so the whole row after the explicit cue is scanned with the
    # stricter transfer-name validator.
    for match in PERSON_TRANSFER_CUE_RE.finditer(text):
        start = match.end()
        tail = text[start : start + 200]
        stop = re.search(
            r"(?i)(?:;|(?<![A-Z])\.(?=\s+[A-Z])|(?<![A-Z])\.(?=\s*$)|"
            r"\b(?:telephone|email| website)\s*:)",
            tail,
        )
        if stop:
            tail = tail[: stop.start()]
        for relative_start, relative_end in _iter_transfer_sequences(tail):
            _add_name_candidate(
                entities,
                text,
                start + relative_start,
                start + relative_end,
                part,
                "transfer-name",
            )

    if has_table_context and _person_unit_is_name_like(text):
        for relative_start, relative_end in _iter_person_sequences(text):
            _add_name_candidate(
                entities,
                text,
                relative_start,
                relative_end,
                part,
                "table-name",
            )

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


ORG_GENERIC_PHRASES = {
    "our company",
    "our group",
    "our promoter",
    "our promoter selling shareholders",
    "promoter selling shareholders",
    "private limited",
    "india limited",
    "practicing company",
    "cloud services",
    "systemically important non banking financial company",
    "advisory private limited",
    "company",
    "group",
    "holdings",
    "registered with the registrar of companies",
    "the company",
    "the group",
    "offer for sale",
    "stock exchanges",
    "systemically important non-banking financial company",
    "cloud services vendor",
    "main provisions of the articles of association",
    "articles of association",
    "memorandum of association",
    "financial statements of assets and liabilities of the company",
    "board and shareholders of the company",
    "goods and services",
    "promoters and promoter group",
    "net proceeds of the offer",
    "us gaap",
    "us gaap and ifrs",
}

ORG_GENERIC_WORDS = {
    "a",
    "an",
    "and",
    "at",
    "bank",
    "by",
    "company",
    "conducted",
    "for",
    "formerly",
    "from",
    "group",
    "holding",
    "holdings",
    "india",
    "limited",
    "ltd",
    "name",
    "of",
    "office",
    "offer",
    "our",
    "promoter",
    "registered",
    "registrar",
    "shareholders",
    "stock",
    "the",
    "trust",
    "family",
    "with",
    "financial",
    "statements",
    "assets",
    "liabilities",
    "board",
    "promoters",
    "goods",
    "services",
    "memorandum",
    "articles",
    "provisions",
    "net",
    "proceeds",
    "gaap",
    "ifrs",
}

# Words that make a weak-suffix candidate look like a person rather than an
# organization.  This is intentionally conservative; the contextual PERSON
# rules remain the authority for names.
ORG_PERSON_LIKE_WORDS = {
    "company",
    "secretary",
    "practicing",
    "independent",
    "professional",
    "chartered",
    "accountant",
    "accountants",
    "auditor",
    "auditors",
    "consultant",
    "advisor",
    "adviser",
}


def _org_flatten(value: str) -> str:
    return re.sub(r"[^a-z0-9]+", " ", value.casefold()).strip()


def _strip_org_leading_context(value: str) -> tuple[str, int]:
    """Remove labels which precede a legal name in a prospectus sentence."""

    # Keep the original offset so the caller can emit the actual name rather
    # than a label such as ``Company KSH International Limited``.
    # ``The`` is normally an article in a prospectus sentence, but it is part
    # of a few legal names (``The Federal Bank Limited``).  Preserve that
    # capitalized form while still trimming a lowercase ``the`` prefix.
    if value.startswith("The ") and re.search(
        rf"(?:{ORG_LEGAL_SUFFIX_PATTERN})\s*$", value[4:], flags=re.IGNORECASE
    ):
        return value, 0

    prefix_pattern = re.compile(
        r"^(?:(?:our|a|an|the|formerly|registered|corporate|office|"
        r"escrow|collection|bankers?|share|promoter|group|company|"
        r"bank|registered|with|of|at|to|name|and|or|&|known|namely|"
        r"collectively|offer)\b[\s:.-]*)+",
        re.IGNORECASE,
    )
    match = prefix_pattern.match(value)
    if match:
        return value[match.end() :], match.end()
    return value, 0


def _clean_org(value: str) -> Optional[str]:
    value = re.sub(r"\s+", " ", value).strip(" \t,;:-")
    if len(value) < 3 or len(value.split()) > 12:
        return None

    value, _ = _strip_org_leading_context(value)
    value = re.sub(r"^(?:and|or|&)\s+", "", value, flags=re.IGNORECASE)
    value = value.strip(" \t,;:-")
    if not value:
        return None

    flat = _org_flatten(value)
    if flat in ORG_GENERIC_PHRASES:
        return None
    if re.match(
        r"(?i)^(?:us\s+gaap|net\s+proceeds|financial\s+statements|"
        r"board\s+and\s+shareholders|main\s+provisions|articles\s+of|"
        r"memorandum\s+of|goods\s+and\s+services|promoters\s+and|"
        r"stock\s+exchanges)\b",
        flat,
    ):
        return None
    if re.search(r"(?i)\b(?:our|the)\s+(?:company|group)\s*$", value):
        return None
    if re.search(r"(?i)\b(?:email|phone|address|date|director|website|contact)\b", value):
        return None
    if not re.search(r"[A-Za-z]", value):
        return None

    tokens = value.split()
    if not tokens:
        return None

    # A legal suffix is enough for a named entity, provided the name is not a
    # generic fragment (``India Limited``) or a sentence fragment ending in
    # ``Company`` after a person's name.
    has_legal_suffix = bool(
        re.search(
            rf"(?:{ORG_LEGAL_SUFFIX_PATTERN})\s*$",
            value,
            flags=re.IGNORECASE,
        )
    )
    prefix = re.sub(
        rf"(?:{ORG_LEGAL_SUFFIX_PATTERN}|{ORG_BUSINESS_SUFFIX_PATTERN})\s*$",
        "",
        value,
        flags=re.IGNORECASE,
    ).strip(" ,;:-")
    prefix_tokens = prefix.split()

    if not has_legal_suffix:
        # Weak business words need at least one distinctive proper-name token
        # and a second token in the candidate.  This rejects ``Cloud Services``
        # and ``Our Group`` without dropping ``Nuvama Wealth Management``.
        if not prefix_tokens:
            return None
        if len(prefix_tokens) == 1 and prefix_tokens[0].casefold().strip(".,") in ORG_GENERIC_WORDS:
            return None
        if prefix_tokens[0].casefold().strip(".,") in ORG_GENERIC_WORDS:
            return None
        if flat in {"systemically important non banking financial company", "practicing company"}:
            return None

    if flat in {"india limited", "private limited", "advisory private limited"}:
        return None
    if flat.endswith("company") and _clean_name(prefix) is not None:
        return None
    if any(
        token.casefold().strip(".,") in ORG_PERSON_LIKE_WORDS
        for token in prefix_tokens
    ) and not has_legal_suffix:
        return None

    # A legal name consisting solely of a generic suffix/head word is not an
    # organization.  Acronyms (``BSE Limited``) and multi-word proper names
    # remain eligible.
    distinctive = [
        token
        for token in prefix_tokens
        if token.casefold().strip(".,") not in ORG_GENERIC_WORDS
        and token.casefold().strip(".,") not in {"corporation", "company", "services"}
    ]
    if has_legal_suffix and not distinctive:
        return None
    return value


def _org_entity(
    text: str,
    part: str,
    match_start: int,
    raw_value: str,
    detector: str,
    score: float,
) -> Optional[Entity]:
    cleaned = _clean_org(raw_value)
    if cleaned is None:
        return None
    # Locate the cleaned value in the raw match after whitespace normalization.
    # The source can contain tabs in table cells, so search token-by-token.
    raw_normalized_start = match_start
    token_pattern = r"\s+".join(re.escape(token) for token in cleaned.split())
    match = re.search(token_pattern, raw_value, flags=re.IGNORECASE)
    if match is None:
        return None
    start = raw_normalized_start + match.start()
    end = start + len(match.group(0))
    return _entity(text, PIIType.ORG, start, end, part, detector, score=score)


def _contextual_loose_org_entity(
    text: str, part: str, start: int, end: int
) -> Optional[Entity]:
    """Validate a named organization in a customer/supplier list.

    Some disclosed counterparties are divisions or trading names without a
    legal suffix (for example ``Sterlite Copper``).  They are accepted only in
    the explicitly labelled list context and only when a business-like head
    word is present; arbitrary capitalized prose is not promoted to ORG.
    """

    raw = text[start:end].strip()
    tokens = re.findall(r"[A-Za-z][A-Za-z'’.-]*", raw)
    if len(tokens) < 2 or len(tokens) > 4:
        return None
    if any(token.casefold().strip(".") in ORG_GENERIC_WORDS for token in tokens):
        return None
    if not any(token.casefold().strip(".") in ORG_LOOSE_HEAD_WORDS for token in tokens):
        return None
    if not raw or raw != re.sub(r"\s+", " ", raw).strip():
        return None
    # A loose name must be a complete capitalized sequence, not a sentence
    # fragment containing a lowercase connector or punctuation.
    if not re.fullmatch(r"[A-Z][A-Za-z'’.-]*(?:\s+[A-Z][A-Za-z'’.-]*){1,3}", raw):
        return None
    pattern = r"\s+".join(re.escape(token) for token in tokens)
    match = re.search(pattern, text[start:end], flags=re.IGNORECASE)
    if match is None:
        return None
    exact_start = start + match.start()
    exact_end = exact_start + len(match.group(0))
    return _entity(
        text,
        PIIType.ORG,
        exact_start,
        exact_end,
        part,
        "organization-list",
        score=0.9,
    )


def _contextual_organization_lists(text: str, part: str) -> list[Entity]:
    entities: list[Entity] = []
    for context in ORG_LIST_CONTEXT_RE.finditer(text):
        tail_start = context.end()
        boundary = re.search(
            r"(?i)\bNames?\s+of\s+other\b|\.\s", text[tail_start:]
        )
        tail_end = tail_start + boundary.start() if boundary else len(text)
        tail = text[tail_start:tail_end]
        cursor = 0
        for segment in re.split(r";", tail):
            segment_start = cursor
            cursor += len(segment) + 1
            raw_segment = segment
            leading = len(raw_segment) - len(raw_segment.lstrip())
            segment = re.sub(r"(?i)^\s*(?:and|or)\s+", "", raw_segment).strip()
            if not segment:
                continue
            segment_abs = tail_start + segment_start + leading
            connector = re.match(r"(?i)^(?:and|or)\s+", raw_segment.lstrip())
            if connector is not None:
                segment_abs = tail_start + segment_start + leading + len(connector.group(0))
            # A list item can contain a legal name followed by a named
            # division/trading name without punctuation.  The legal entity is
            # already covered by ORG_RE; inspect only the words after its
            # suffix (for example ``Sterlite Copper``).
            suffix_match = re.search(
                ORG_LEGAL_SUFFIX_PATTERN,
                segment,
                flags=re.IGNORECASE,
            )
            if suffix_match:
                remainder = segment[suffix_match.end() :].strip(" ,")
                if remainder:
                    remainder_leading = len(segment[suffix_match.end() :]) - len(
                        segment[suffix_match.end() :].lstrip()
                    )
                    loose = _contextual_loose_org_entity(
                        text,
                        part,
                        segment_abs + suffix_match.end() + remainder_leading,
                        segment_abs + len(segment),
                    )
                    if loose is not None:
                        entities.append(loose)
                continue
            if _has_org_suffix(segment):
                continue
            loose = _contextual_loose_org_entity(
                text, part, segment_abs, segment_abs + len(segment)
            )
            if loose is not None:
                entities.append(loose)
    return entities


def _has_org_suffix(value: str) -> bool:
    return bool(
        re.search(
            rf"(?:{ORG_LEGAL_SUFFIX_PATTERN}|{ORG_BUSINESS_SUFFIX_PATTERN})\s*$",
            value,
            flags=re.IGNORECASE,
        )
    )


def _org_candidate_fragments(raw_value: str) -> list[tuple[int, str]]:
    """Split a list match such as ``Nuvama ... and ICICI ...``.

    Ampersands inside a legal name (``Kirtane & Pandit LLP``) are retained;
    only an ``and`` separator with a suffix-bearing entity on both sides is
    treated as a list boundary.
    """

    fragments: list[tuple[int, str]] = [(0, raw_value)]
    changed = True
    while changed:
        changed = False
        next_fragments: list[tuple[int, str]] = []
        for offset, fragment in fragments:
            pieces = list(re.finditer(r"(?i)\s+and\s+", fragment))
            split_at: Optional[re.Match[str]] = None
            for piece in pieces:
                left = fragment[: piece.start()]
                right = fragment[piece.end() :]
                if left.strip() and right.strip() and _has_org_suffix(left) and _has_org_suffix(right):
                    split_at = piece
                    break
            if split_at is None:
                next_fragments.append((offset, fragment))
                continue
            next_fragments.append((offset, fragment[: split_at.start()]))
            next_fragments.append((offset + split_at.end(), fragment[split_at.end() :]))
            changed = True
        fragments = next_fragments
    return [(offset, value) for offset, value in fragments if value.strip()]


def _is_all_caps_org_match(value: str) -> bool:
    """Return whether a case-insensitive match is an all-caps name variant."""

    value = re.sub(r"^\s*\([ivxIVX]+\)\s*", "", value)
    letters = [char for char in value if char.isalpha()]
    return bool(letters) and all(not char.islower() for char in letters)


# One run of all-caps words inside a case-insensitive match.  The uppercase
# patterns must be trimmed to such a run, because their token pattern also
# matches lowercase lead-in words ("The Promoters of our Company are ...").
_ORG_ALL_CAPS_RUN_RE = re.compile(
    r"(?<![A-Za-z0-9])"
    r"[A-Z][A-Z0-9&'’.,/-]*"
    r"(?:\s+(?:[A-Z][A-Z0-9&'’.,/-]*|AND|OF|&)){0,9}"
)


def _all_caps_org_fragments(raw_value: str) -> list[tuple[int, str]]:
    """Return the all-caps organization candidates inside a case-insensitive match."""

    fragments: list[tuple[int, str]] = []
    for run in _ORG_ALL_CAPS_RUN_RE.finditer(raw_value):
        if not _has_org_suffix(run.group(0)):
            continue
        for offset, fragment in _org_candidate_fragments(run.group(0)):
            fragment = fragment.strip(" \t,;:-")
            if fragment and _is_all_caps_org_match(fragment):
                fragments.append((run.start() + offset, fragment))
    return fragments


def detect_organizations(text: str, part: str = "body") -> list[Entity]:
    entities: list[Entity] = []
    for pattern, source, score, upper_only in (
        (ORG_RE, "legal-suffix", 0.98, False),
        (ORG_BUSINESS_RE, "business-suffix", 0.93, False),
        (ORG_UPPER_RE, "legal-suffix-caps", 0.98, True),
        (ORG_BUSINESS_UPPER_RE, "business-suffix-caps", 0.93, True),
    ):
        for match in pattern.finditer(text):
            raw_match = match.group(0)
            if upper_only:
                candidates = _all_caps_org_fragments(raw_match)
            else:
                candidates = _org_candidate_fragments(raw_match)
            for relative_start, fragment in candidates:
                entity = _org_entity(
                    text,
                    part,
                    match.start() + relative_start,
                    fragment,
                    source,
                    score,
                )
                if entity is not None:
                    entities.append(entity)

    for match in ORG_CONTEXT_RE.finditer(text):
        entity = _org_entity(
            text,
            part,
            match.start("value"),
            match.group("value"),
            "organization-context",
            0.9,
        )
        if entity is not None:
            entities.append(entity)
    entities.extend(_contextual_organization_lists(text, part))
    return entities


def _address_score(line: str, context_hint: bool = False) -> int:
    """Score address structure, with strong/weak keyword separation."""

    score = 0
    if ADDRESS_STRONG_KEYWORD_RE.search(line):
        score += 3
    elif ADDRESS_WEAK_KEYWORD_RE.search(line):
        score += 1
    if POSTAL_CODE_RE.search(line):
        score += 3
    if line.count(",") >= 1:
        score += 1
    if ADDRESS_NUMBER_RE.search(line):
        score += 1
    if re.search(r"(?i)\b(?:city|state|district|province|postal\s+code|pin\s*code)\b", line):
        score += 1
    if context_hint and len(line.strip()) <= 80:
        score += 1
        if re.search(r"(?i)\b(?:maharashtra|india|country|state)\b", line):
            score += 2
    return score


# A location preposition introduces the value that follows it, so a sentence
# that ends with ``... at 221B, Green Park, New Delhi, Delhi 110001`` is an
# address even though the sentence itself carries no address keyword.
LOCATION_PREPOSITION_RE = re.compile(
    r"(?i)\b(?:located\s+at|situated\s+at|premises\s+at|adjacent\s+to|next\s+to|"
    r"at|near|opposite|off|above|behind|beside)\s+(?=[A-Z0-9])"
)


def _location_introduced_value(segment: str) -> bool:
    """Return whether prose introduces a complete address after ``at``/``near``.

    Both structural signals are required.  A preposition alone is far too weak:
    ``listed at 45.50 per share`` must stay out of the address category, while a
    preposition followed by a structural number and a six-digit PIN is an
    address tail.
    """

    match = LOCATION_PREPOSITION_RE.search(segment)
    if match is None:
        return False
    tail = segment[match.end() :]
    return bool(POSTAL_CODE_RE.search(tail)) and _has_structural_address_number(tail)


def _address_context_hint(context_prefix: str) -> bool:
    if not context_prefix:
        return False
    recent = context_prefix[-500:]
    return bool(
        re.search(
            r"(?i)\b(?:registered\s+office|corporate\s+office|office\s+address|"
            r"address|contact\s+details?)\b",
            recent,
        )
    )


def _has_structural_address_number(line: str) -> bool:
    """Return whether a numeric token looks like an address identifier.

    The generic numeric regex also sees dates, years, percentages, and
    registration identifiers.  A token is structural when it has a slash or
    letter suffix, is an ordinal, is adjacent to a house/plot keyword, or is a
    value at the beginning of a short address-looking line.
    """

    for match in ADDRESS_NUMBER_RE.finditer(line):
        token = match.group(0)
        digits = _digits(token)
        if re.fullmatch(r"(?:19|20)\d{2}", digits):
            continue
        if "/" in token or re.search(r"[A-Za-z]", token):
            return True
        if match.start() >= 2 and line[match.start() - 2 : match.start()] == "-":
            prefix = line[max(0, match.start() - 3) : match.start() - 1]
            if re.fullmatch(r"[A-Za-z]", prefix):
                return True
        before = line[max(0, match.start() - 24) : match.start()]
        after = line[match.end() : match.end() + 28]
        if re.search(
            r"(?i)\b(?:tower|flat|house|plot|gat|floor|wing|building|room|shop|"
            r"basement|block|sector|no)\.?\s*$",
            before,
        ):
            return True
        if re.match(
            r"\s*(?:,|;)?\s*(?:tower|flat|house|plot|gat|floor|wing|building|"
            r"room|shop|road|street|marg|colony|village|taluka)\b",
            after,
            flags=re.IGNORECASE,
        ):
            return True
        if match.start() <= 2 and re.match(r"\s*[A-Za-z]", after):
            return True
    return False


def _address_span_end(line: str, start: int, end: int) -> int:
    """Stop an address before the next sentence or contact field."""

    boundary = ADDRESS_FIELD_BOUNDARY_RE.search(line, start)
    if boundary:
        end = min(end, boundary.start())
    sentence = re.search(
        r"(?<!\bNo)(?<!\bS)(?<!\bMr)(?<!\bMrs)(?<!\bDr)(?<!\bSt)(?<!\bCo)"
        r"(?<!\bInc)(?<!\bLtd)(?<!\bOpp)\.(?=\s+[A-Z])"
        r"|\.(?=$)|;|\||\band\s+its\s*$|\band\s+its\s+(?:corporate|registered|principal)\s+office\b",
        line[start:end],
        flags=re.IGNORECASE,
    )
    if sentence:
        end = min(end, start + sentence.start())
    return end


def _address_value_start(line: str, start: int, end: int, labelled: bool, context_hint: bool) -> int:
    """Find the value start, then recover a trimmed building/unit designator."""

    inner = _address_value_start_inner(line, start, end, labelled, context_hint)
    if inner <= start:
        return start
    # ``Pushpakamal Apartment, Flat - 1, S. no. 245/104, ...`` and ``Unit no.
    # 1601, B- wing BKC, ...`` both open with a building or unit designator that
    # belongs to the address.  The structural rules below deliberately prefer a
    # number or a later keyword as the start, which would leave the building
    # name in the clear, so walk the start back over such a designator.
    head = line[start:inner]
    if _opens_with_address_designator(head):
        return start
    return inner


# A building or unit designator at the head of a value is part of the address.
_ADDRESS_UNIT_WORDS = frozenset(
    {
        "apartment", "flat", "unit", "tower", "building", "house", "centre",
        "center", "suite", "shop", "block", "wing", "room", "no", "plot",
        "survey", "gst", "premises",
    }
)


def _opens_with_address_designator(head: str) -> bool:
    """Return whether a trimmed head is a building/unit designator, not a name."""

    text = head.strip()
    if not text:
        return False
    words = {word.lower().strip(".") for word in re.findall(r"[A-Za-z][A-Za-z.]*", text)}
    if not words & _ADDRESS_UNIT_WORDS:
        return False
    for token in re.split(r"[,;–—-]|\s+", text):
        token = token.strip()
        if not token:
            continue
        if token.lower().strip(".") in _ADDRESS_UNIT_WORDS:
            continue
        if token.isdigit():
            continue
        # An organization name in the head (``ICICI Bank,``) must stay trimmable,
        # so every other token has to be a capitalized building or number.
        if not token[:1].isupper():
            return False
    return True


def _address_value_start_inner(
    line: str, start: int, end: int, labelled: bool, context_hint: bool
) -> int:
    """Find the value start, excluding a leading organization label."""

    # The cue regex consumes at most one preposition, so a value such as
    # ``Registered Office is at 11/3, ...`` can begin with the leftover ``at``.
    # Cue words are not part of the address; location lead-ins such as
    # ``Opposite``/``Near`` are, and are handled below.
    lead_in = re.match(
        r"(?i)\s*(?:(?:is\s+)?(?:located|situated|found|stationed)\s+at\s+"
        r"|(?:is|are|was|were)\s+at\s+|at\s+|of\s+)",
        line[start:end],
    )
    if lead_in is not None and lead_in.end() < end - start:
        start += lead_in.end()
        if labelled:
            return start

    if labelled:
        return start

    located = re.search(r"(?i)\blocated\s+at\s+", line[start:end])
    if located is not None:
        return start + located.end()

    # Prose that ends with a location preposition introduces the value after it.
    # ``Notice may be sent to <name> at 221B, Green Park, ...`` is a sentence
    # whose address is the tail only; the sentence is not the address.
    introduced = LOCATION_PREPOSITION_RE.search(line, start, end)
    if introduced is not None:
        tail_start = introduced.end()
        tail = line[tail_start:end]
        if POSTAL_CODE_RE.search(tail) and _has_structural_address_number(tail):
            return tail_start

    first_strong = ADDRESS_STRONG_KEYWORD_RE.search(line, start, end)
    if first_strong is not None:
        prefix = line[start : first_strong.start()]
        # A value that opens with the address itself (``Pushpakamal Apartment,
        # Flat - 1, S. no. 245/104, ...``) has nothing to trim: the first strong
        # keyword is the start of the address, and a later flat/plot marker must
        # not move the start forward past the building name.
        if first_strong.start() - start <= 2:
            return start
        if re.search(
            r"(?i)\b(?:opposite|above|behind|near|next|adjacent|off)\b", prefix
        ):
            # These are part of the physical-address description, not an
            # organization label to discard.
            return start
        building_prefix = re.search(
            r"([A-Z][A-Za-z0-9&'’.-]*\s+"
            r"(?:Bhavan|Building|House|Centre|Center|Tower))\s*,?\s*$",
            prefix,
        )
        if building_prefix is not None:
            return start + building_prefix.start()
        explicit_prefix = ADDRESS_PREFIX_RE.search(line, start, end)
        if explicit_prefix is not None:
            return start + explicit_prefix.start()
        suffixes = list(
            re.finditer(
                rf"(?:{ORG_LEGAL_SUFFIX_PATTERN}|{ORG_BUSINESS_SUFFIX_PATTERN})",
                prefix,
                flags=re.IGNORECASE,
            )
        )
        if suffixes:
            candidate = suffixes[-1].end()
            while candidate < first_strong.start() and line[candidate].isspace():
                candidate += 1
            if candidate < first_strong.start():
                return start + candidate
        # Common table cells place a bank/organization name before the actual
        # building address without a legal suffix (for example ``ICICI Bank,
        # 3rd Floor``).  Strip only this narrow prefix; a department that follows
        # the bank name belongs to the address row.
        bank_prefix = re.match(
            r"(?i)^(?:the\s+)?[A-Z][A-Za-z&'’.-]*\s+bank\s*,\s*",
            line[start:end],
        )
        if bank_prefix is not None:
            return start + bank_prefix.end()

    explicit_prefix = ADDRESS_PREFIX_RE.search(line, start, end)
    if explicit_prefix is not None:
        return start + explicit_prefix.start()

    # A short, self-contained address with a PIN should retain its complete
    # value rather than starting at the first street keyword.  This covers
    # building names (``Pratik Bunglow, Senapati Bapat Road``) and flat/unit
    # identifiers (``C-101, Embassy 247``).
    if POSTAL_CODE_RE.search(line, start, end) and len(line[start:end].strip()) <= 190:
        return start
    return _address_span_start(line, start, end, labelled, context_hint)


def _address_span_start(line: str, start: int, end: int, labelled: bool, context_hint: bool) -> int:
    """Choose the first physical-address token rather than a nearby date."""

    if labelled:
        return start

    candidates: list[int] = []
    prefix = ADDRESS_PREFIX_RE.search(line, start, end)
    if prefix:
        # An explicit flat/plot/gat marker is the most reliable value start;
        # do not let a broad preceding prose phrase win the minimum.
        return prefix.start()
    for match in ADDRESS_NUMBER_RE.finditer(line, start, end):
        if _has_structural_address_number(line):
            # A date in a long prose paragraph is not a house number.  Accept
            # numeric starts only when they are near an address keyword or at
            # the beginning of the line.
            before = line[max(start, match.start() - 35) : match.start()]
            after = line[match.end() : min(end, match.end() + 35)]
            if (
                match.start() <= 2
                or re.search(
                    r"(?i)\b(?:tower|flat|house|plot|gat|floor|wing|building|room|shop|"
                    r"no|s\.?\s*no)\.?\s*$",
                    before,
                )
                or re.search(r"(?i)\b(?:road|street|marg|colony|village|taluka|block)\b", after)
            ):
                candidates.append(match.start())
    if (
        context_hint
        and not labelled
        and not POSTAL_CODE_RE.search(line, start, end)
        and not _has_structural_address_number(line)
    ):
        return start
    keyword = ADDRESS_STRONG_KEYWORD_RE.search(line, start, end)
    if keyword and not re.match(r"(?i)^house$", line[keyword.start() : keyword.end()]):
        # Include a short building/locality title immediately before a road or
        # centre component (for example ``Tara Chambers, ... Road``).
        before = line[start : keyword.start()]
        title = re.search(r"(?:[A-Za-z][A-Za-z'’.-]*)(?:\s+[A-Za-z][A-Za-z'’.-]*){0,2}$", before)
        if title:
            candidates.append(start + title.start())
        candidates.append(keyword.start())
    if not candidates:
        # A short continuation such as ``Pune – 411 001`` or a named
        # building/centre is meaningful only when the caller supplied an
        # address label.  Starting at the line boundary preserves the full
        # continuation value in that case.
        return start
    return min(candidates)


def _is_address_cell(line: str) -> bool:
    """Return whether a short single-line unit is itself an address cell.

    A table that lays an address out over several cells gives the continuation
    cells no neighbouring cue: ``Pune - 411 038`` or ``One World Centre`` sits on
    its own row with nothing but a bank name nearby.  Treating such a short,
    self-contained line as its own context lets the ordinary structural gates
    decide, instead of requiring a cue that the layout never provides.
    """

    text = line.strip()
    if not text or len(text) > 90 or len(text.split()) > 12:
        return False
    # A sentence is prose, whatever address words it happens to contain.
    if re.search(r"[.;?!]", text) or re.search(r"(?i)\b(?:and|or|of|the|our|its)\b", text):
        return False
    return bool(
        ADDRESS_STRONG_KEYWORD_RE.search(text) or POSTAL_CODE_RE.search(text)
    )


def detect_addresses(
    text: str, part: str = "body", context_prefix: str = ""
) -> list[Entity]:
    """Find physical address spans while rejecting identifiers and prose.

    Address values in the source RHP occur both as standalone table cells and
    as values embedded after ``Registered Office at``/``Corporate Office at``
    cues.  The detector therefore operates on cue-bounded segments and keeps
    ordinary years, CINs, registration numbers, and road-show prose out of the
    address category.
    """

    entities: list[Entity] = []
    context_hint = False

    for line_match in re.finditer(r"[^\r\n]*", text):
        line = line_match.group(0)
        if not line.strip():
            continue
        # A short standalone cell carries its own context.
        context_hint = _address_context_hint(context_prefix) or _is_address_cell(line)

        # Semicolon-separated contact fields are independent values.  Keep
        # offsets in the original paragraph rather than recursively redetecting
        # a substring with a different coordinate system.
        chunks: list[tuple[int, str]] = []
        if ";" in line:
            cursor = 0
            for chunk in line.split(";"):
                chunks.append((cursor, chunk))
                cursor += len(chunk) + 1
        else:
            chunks.append((0, line))

        for chunk_offset, chunk in chunks:
            if not chunk.strip():
                continue
            absolute_chunk = line_match.start() + chunk_offset

            # A labelled prose paragraph can contain two complete addresses.
            # Split at the next explicit address cue before evaluating the
            # structural evidence for each value.
            cue_matches = list(ADDRESS_CUE_RE.finditer(chunk))
            segments: list[tuple[int, int, bool]] = []
            if cue_matches:
                for index, cue in enumerate(cue_matches):
                    segment_start = cue.end()
                    segment_end = (
                        cue_matches[index + 1].start()
                        if index + 1 < len(cue_matches)
                        else len(chunk)
                    )
                    segments.append((segment_start, segment_end, True))
            else:
                segments.append((0, len(chunk), False))

            for segment_start, segment_end, labelled in segments:
                if segment_end <= segment_start:
                    continue
                segment = chunk[segment_start:segment_end]
                if not segment.strip():
                    continue

                has_label = labelled or bool(ADDRESS_LABEL_RE.search(segment))
                has_postal = bool(POSTAL_CODE_RE.search(segment))
                has_number = _has_structural_address_number(segment)
                has_strong = bool(ADDRESS_STRONG_KEYWORD_RE.search(segment))
                if re.search(r"(?i)\bin[- ]house\b", segment):
                    # ``in-house product development`` is prose, not a street
                    # address merely because it contains the word ``house``.
                    has_strong = False
                has_weak = bool(ADDRESS_WEAK_KEYWORD_RE.search(segment))
                if not has_postal and not has_strong and ADDRESS_PROSE_RE.search(segment):
                    continue

                if ADDRESS_IDENTIFIER_LABEL_RE.search(segment) and not (
                    has_postal and has_strong
                ):
                    continue
                if re.search(
                    r"(?i)\b(?:road\s+show|roadshow|presentation|schedules?)\b",
                    segment,
                ) and not (has_postal or has_number):
                    continue
                if not (
                    has_label
                    or has_postal
                    or has_number
                    or (has_strong and context_hint)
                ):
                    continue
                # A label alone (``our office is located``) is not an address
                # value.  Require a street/locality component or a PIN.
                if has_label and not (has_postal or has_strong):
                    continue
                if not (
                    has_strong
                    or has_postal
                    or (has_number and has_weak)
                    or (has_number and context_hint and len(segment.strip()) <= 80)
                ):
                    continue

                # A postal-only value is a continuation of a labelled address;
                # it is not independently sufficient in ordinary prose.  A value
                # that a location preposition introduces is the exception: the
                # sentence is not the address, the value after the preposition
                # is, and it carries a structural number and a PIN.
                if (
                    has_postal
                    and not has_strong
                    and not has_label
                    and not context_hint
                    and not (has_number and _location_introduced_value(segment))
                ):
                    continue
                # A long paragraph without a cue, postal code, or explicit
                # address keyword is prose.  A long paragraph with a concrete
                # ``Plot/House/Road`` token is handled below.
                if len(segment) > 220 and not has_label and not has_postal and not (
                    has_strong and has_number
                ):
                    continue

                start = _address_value_start(
                    segment, 0, len(segment), labelled=has_label, context_hint=context_hint
                )
                end = _address_span_end(segment, start, len(segment))
                while start < end and segment[start].isspace():
                    start += 1
                while end > start and segment[end - 1].isspace():
                    end -= 1
                if end <= start:
                    continue
                candidate_text = segment[start:end].strip(" \t,;:-")
                if len(candidate_text) < 8 or _looks_like_date(candidate_text):
                    continue
                if re.search(
                    r"(?i)\b(?:national\s+automated\s+clearing\s+house|"
                    r"corporate\s+identity\s+number|firm\s+registration|"
                    r"peer\s+review\s+number)\b",
                    candidate_text,
                ):
                    continue

                global_start = absolute_chunk + segment_start + start
                # ``strip`` above can remove leading punctuation; locate the
                # exact remaining span in the segment rather than shifting by
                # a guessed amount.
                leading_trim = len(segment[start:end]) - len(segment[start:end].lstrip(" \t,;:-"))
                global_start += leading_trim
                global_end = global_start + len(candidate_text)
                entities.append(
                    _entity(
                        text,
                        PIIType.ADDRESS,
                        global_start,
                        global_end,
                        part,
                        "address-context",
                        score=0.96,
                    )
                )

    return sorted(entities, key=lambda item: (item.start, item.end))


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
        if context_prefix and context_prefix.strip():
            # A rolling neighbour context is useful for table labels, but a DOB
            # label several paragraphs away must not validate an unrelated
            # date in the current unit.  Only the immediately preceding line
            # participates in DOB contextual validation.
            context_lines = context_prefix.rstrip().splitlines()
            context_line = context_lines[-1] if context_lines else ""
            prefix = context_line + "\n"
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
        entities.extend(detect_addresses(text, part, context_prefix=context_prefix))
        entities.extend(detect_organizations(text, part))
        entities.extend(detect_persons(text, part, context_prefix=context_prefix))
        if self.optional_spacy is not None:
            entities.extend(self.optional_spacy.entities(text, part))
        return resolve_overlaps(entities)

    def detect_text(self, text: str, part: str = "body") -> list[Entity]:
        """Alias useful to callers that want to emphasize text-only use."""

        return self.detect(text, part)
