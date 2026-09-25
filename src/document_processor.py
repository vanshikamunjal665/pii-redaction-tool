"""DOCX/PDF document processing with formatting-preserving substitutions."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable, Optional

from docx import Document
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from docx.oxml.ns import qn

from .detectors import DOB_CONTEXT_RE, PIIDetector, resolve_overlaps
from .models import Entity, PIIType, TextUnit
from .replacers import ReplacementRegistry

XML_NS = "http://www.w3.org/XML/1998/namespace"


@dataclass
class _DocxUnit:
    part: str
    unit_id: str
    element: Any
    text: str


@dataclass
class RedactionResult:
    predictions: list[Entity]
    source_units: list[TextUnit]
    redacted_units: list[TextUnit]
    output_path: Path

    def prediction_dicts(self) -> list[dict[str, Any]]:
        return [entity.as_dict() for entity in self.predictions]


def _part_name(part: Any) -> str:
    value = str(getattr(part, "partname", "unknown"))
    return value.lstrip("/")


def _text_segments(paragraph: Any) -> tuple[str, list[tuple[Any, int, int]]]:
    """Return visible text and editable ``w:t`` node ranges.

    Tabs and breaks are included in offsets so a detector never sees a false
    adjacency across a line break, while only text nodes are modified.
    """

    pieces: list[str] = []
    text_nodes: list[tuple[Any, int, int]] = []
    position = 0
    for node in paragraph.iter():
        if node.tag == qn("w:t"):
            value = node.text or ""
            pieces.append(value)
            text_nodes.append((node, position, position + len(value)))
            position += len(value)
        elif node.tag in {qn("w:tab"), qn("w:br"), qn("w:cr")}:
            pieces.append("\n" if node.tag != qn("w:tab") else "\t")
            position += 1
    return "".join(pieces), text_nodes


def _set_text_node(node: Any, value: str) -> None:
    node.text = value
    if value[:1].isspace() or value[-1:].isspace():
        node.set(f"{{{XML_NS}}}space", "preserve")
    else:
        node.attrib.pop(f"{{{XML_NS}}}space", None)


def _replace_span(paragraph: Any, start: int, end: int, replacement: str) -> bool:
    """Replace a character span while retaining the first run's formatting."""

    _, nodes = _text_segments(paragraph)
    overlapping = [(node, left, right) for node, left, right in nodes if left < end and start < right]
    if not overlapping:
        return False
    first_index = 0
    last_index = len(overlapping) - 1
    for index, (node, left, right) in enumerate(overlapping):
        local_start = max(0, start - left)
        local_end = min(right - left, end - left)
        current = node.text or ""
        prefix = current[:local_start]
        suffix = current[local_end:]
        if index == first_index:
            _set_text_node(node, prefix + replacement + (suffix if index == last_index else ""))
        else:
            _set_text_node(node, suffix if index == last_index else "")
    return True


def _iter_part_elements(document: Any) -> list[tuple[str, Any, Any]]:
    """Return unique document/header/footer/notes XML parts."""

    parts: list[tuple[str, Any, Any]] = []
    seen_parts: set[int] = set()
    seen_elements: set[int] = set()

    def add(part: Any) -> None:
        if part is None or id(part) in seen_parts:
            return
        seen_parts.add(id(part))
        element = getattr(part, "element", None)
        if element is None or id(element) in seen_elements:
            return
        seen_elements.add(id(element))
        parts.append((_part_name(part), part, element))

    add(document.part)
    for section in document.sections:
        for accessor in (
            "header",
            "first_page_header",
            "even_page_header",
            "footer",
            "first_page_footer",
            "even_page_footer",
        ):
            try:
                story = getattr(section, accessor)
                # Accessing a linked story can materialize a new empty
                # header/footer part in python-docx.  Only process stories that
                # are explicitly present in the source package.
                if getattr(story, "is_linked_to_previous", False):
                    continue
                add(story.part)
            except Exception:
                # python-docx can expose read-only/unsupported story parts
                # for some producer-specific documents.
                continue

    # Include notes/comments when the package exposes their XML parts.  This
    # is best effort and does not require optional python-docx APIs.
    try:
        for part in document.part.package.parts:
            name = _part_name(part)
            if name.endswith(("/footnotes.xml", "/endnotes.xml", "/comments.xml")):
                add(part)
    except Exception:
        pass
    return parts


def _collect_docx_units(document: Any) -> list[_DocxUnit]:
    units: list[_DocxUnit] = []
    for part_name, _part, element in _iter_part_elements(document):
        paragraph_index = 0
        for paragraph in element.iter(qn("w:p")):
            text, _ = _text_segments(paragraph)
            unit_id = f"{part_name}:p{paragraph_index:04d}"
            units.append(_DocxUnit(part_name, unit_id, paragraph, text))
            paragraph_index += 1
    return units


def _public_units(units: Iterable[_DocxUnit]) -> list[TextUnit]:
    return [TextUnit(unit.part, unit.unit_id, unit.text) for unit in units]


def extract_docx_units(path: str | Path) -> list[TextUnit]:
    """Extract paragraph/table/header/footer units from a DOCX."""

    document = Document(str(path))
    return _public_units(_collect_docx_units(document))


def extract_docx_text(path: str | Path) -> str:
    return "\n".join(unit.text for unit in extract_docx_units(path))


def _update_hyperlink_targets(
    document: Any, email_replacements: dict[str, str]
) -> None:
    """Update both relationship targets and Word field-code mailto links.

    Word documents produced by several office suites store a hyperlink either
    as an external relationship or as a ``HYPERLINK "mailto:..."`` field
    instruction inside ``w:instrText``.  Redacting only the former leaves the
    original address in the package XML even when the visible text is clean.
    """

    if not email_replacements:
        return
    substitutions = tuple(
        (re.compile(re.escape(original), re.IGNORECASE), replacement)
        for original, replacement in email_replacements.items()
    )

    def updated_value(value: str) -> str:
        for pattern, replacement in substitutions:
            value = pattern.sub(replacement, value)
        return value

    for _part_name_value, part, element in _iter_part_elements(document):
        for relationship in list(getattr(part, "rels", {}).values()):
            if getattr(relationship, "reltype", "") != RT.HYPERLINK:
                continue
            target = getattr(relationship, "target_ref", "")
            updated = updated_value(target)
            if updated != target:
                # python-docx's relationship object stores the external target
                # in _target; assigning it preserves the relationship ID.
                relationship._target = updated

        for node in element.iter():
            if node.tag == qn("w:instrText") and node.text:
                node.text = updated_value(node.text)
            # ``w:fldSimple`` can carry the instruction in an attribute instead
            # of a child text node.
            for attribute in (qn("w:instr"), "instr"):
                value = node.get(attribute)
                if value:
                    node.set(attribute, updated_value(value))


def _neighbor_context(units: list[_DocxUnit], index: int, window: int = 2) -> str:
    """Return a short rolling context for adjacent DOCX table cells.

    A two-cell window is enough for labels/values split by table structure,
    while avoiding the document-wide address/person hints that caused false
    positives in the first real-RHP pass.  Newlines preserve logical unit
    boundaries for the contextual detectors.
    """

    recent = [unit.text for unit in units[max(0, index - window) : index] if unit.text]
    return "\n".join(recent)[-800:]


def _value_pattern(value: str) -> Optional[str]:
    """Build a whole-value pattern; internal whitespace is matched loosely.

    Lookarounds are used instead of ``\\b`` so values that start or end with a
    non-word character (a phone number with a ``+`` prefix, a house number) are
    handled as well.
    """

    parts = [re.escape(part) for part in value.strip().split()]
    if not parts:
        return None
    return rf"(?<![A-Za-z0-9_]){r'\s+'.join(parts)}(?![A-Za-z0-9_])"


def contains_original_value(haystack: str, value: str) -> bool:
    """Return whether ``value`` survives in ``haystack`` as a whole value.

    A plain substring test produces false alarms that hide real ones: the
    redacted fragment ``Broad`` (from a promoter name split across two table
    cells) occurs inside the ordinary words ``abroad`` and ``broader`` in the
    risk factors, while a genuine leak inside a longer word would still be
    reported.  Matching whole values keeps the residual check meaningful.
    """

    pattern = _value_pattern(value)
    return pattern is not None and bool(re.search(pattern, haystack, re.IGNORECASE))


def _known_value_pattern(value: str) -> Optional[re.Pattern[str]]:
    """Build a whitespace/case-insensitive pattern for document propagation."""

    value = value.strip()
    if not value:
        return None
    # Keep periods in initials (``B.``) and punctuation in legal names, but
    # compare tokens across tabs, line-wrap whitespace, and capitalization.
    tokens = re.findall(r"[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*\.?", value)
    if not tokens:
        return None
    if "&" in value:
        separator = r"(?:\s*&\s*)"
    else:
        separator = r"\s+"
    return re.compile(
        r"(?<![A-Za-z0-9])" + separator.join(re.escape(token) for token in tokens) + r"(?![A-Za-z0-9])",
        flags=re.IGNORECASE,
    )


def _token_pattern(tokens: list[str]) -> Optional[re.Pattern[str]]:
    if len(tokens) < 2:
        return None
    joined = r"\s+".join(re.escape(token) for token in tokens)
    return re.compile(rf"(?<![A-Za-z0-9]){joined}(?![A-Za-z0-9])", re.IGNORECASE)


# A one-token half of a split name (``DHAULAGIRI`` | ``FAMILY TRUST``) is only
# accepted when that token is a distinctive capitalised word.  Generic legal and
# prospectus words are excluded so an ordinary neighbouring cell is never
# redacted just because it happens to sit next to the other half.
CROSS_UNIT_STOP_WORDS = frozenset(
    {
        "and", "the", "for", "its", "new", "not", "one", "our", "two", "of",
        "any", "all", "are", "has", "his", "her", "per", "was", "who", "will",
        "bank", "capital", "company", "corporate", "finance", "financial",
        "group", "holdings", "india", "industries", "international",
        "limited", "national", "private", "public", "services", "state",
        "trust", "llp", "llc", "inc", "corp", "pvt", "sri", "smt", "mr",
        "mrs", "ms", "dr", "prof", "m/s", "s/o", "w/o", "l td", "p ltd",
    }
)


def _is_boundary_token(token: str, unit_text: str) -> bool:
    """Return whether a single token can stand as one half of a split name."""

    bare = token.rstrip(".").casefold()
    if len(bare) < 3 or bare in CROSS_UNIT_STOP_WORDS:
        return False
    # The token has to be capitalised in the unit it would be redacted from;
    # lower-case prose is not half of a name.  The search is case-insensitive
    # because the seeded value may be the all-caps variant of the name, but the
    # source spelling is what decides.
    match = re.search(
        rf"(?<![A-Za-z0-9]){re.escape(token)}", unit_text, re.IGNORECASE
    )
    return match is not None and match.group(0)[:1].isupper()


def _cross_unit_fragments(
    left_text: str,
    right_text: str,
    value: str,
    pii_type: PIIType,
    left_part: str,
    right_part: str,
) -> list[tuple[str, int, int, str, int, int]]:
    """Return matching left/right fragments for a value split at a unit edge."""

    # Ampersands and punctuation-heavy legal names are better handled inside a
    # single unit.  The cross-unit pass targets the common table/line-wrap
    # break between ordinary name tokens.
    if "&" in value:
        return []
    tokens = re.findall(r"[A-Za-z0-9]+(?:\.[A-Za-z0-9]+)*\.?", value)
    if len(tokens) < 2:
        return []
    results: list[tuple[str, int, int, str, int, int]] = []
    for split in range(1, len(tokens)):
        left_tokens = tokens[:split]
        right_tokens = tokens[split:]
        left_pattern = _token_pattern(left_tokens)
        right_pattern = _token_pattern(right_tokens)
        if left_pattern is None:
            if not (len(left_tokens) == 1 and _is_boundary_token(left_tokens[0], left_text)):
                continue
            left_pattern = re.compile(
                rf"(?<![A-Za-z0-9]){re.escape(left_tokens[0])}", re.IGNORECASE
            )
        if right_pattern is None:
            if not (len(right_tokens) == 1 and _is_boundary_token(right_tokens[0], right_text)):
                continue
            right_pattern = re.compile(
                rf"(?<![A-Za-z0-9]){re.escape(right_tokens[0])}", re.IGNORECASE
            )
        left_match = re.search(
            left_pattern.pattern + r"\s*[,;]?\s*$", left_text, re.IGNORECASE
        )
        right_match = re.match(r"\s*" + right_pattern.pattern, right_text, re.IGNORECASE)
        if left_match is None or right_match is None:
            continue
        # A boundary match must not be part of a structured value.
        left_start, left_end = left_match.span()
        right_start, right_end = right_match.span()
        left_context = left_text[max(0, left_start - 12) : left_end + 12]
        right_context = right_text[max(0, right_start - 12) : right_end + 12]
        if "@" in left_context or "@" in right_context or "://" in left_context + right_context:
            continue
        results.append(
            (
                left_text[left_start:left_end],
                left_start,
                left_end,
                right_text[right_start:right_end],
                right_start,
                right_end,
            )
        )
    return results


# A table can lay a single name out one token per cell ("KSH" | "Distriparks" |
# "Private Limited") or wrap it over several paragraphs inside one cell.  The
# window pass only accepts a value that appears whole across consecutive units,
# so unrelated neighbouring cells are never swept in.
CROSS_UNIT_MAX_WINDOW = 6


def _cross_unit_window_fragments(
    unit_texts: list[str], combined: Optional[re.Pattern[str]], named: dict[str, tuple[str, PIIType]]
) -> list[tuple[int, list[tuple[int, int, int]], str]]:
    """Find values laid out across consecutive units.

    Returns ``(first_unit_index, [(index, start, end), ...], value)`` triples.
    Only the first and last unit of a match may contribute a partial span; every
    unit in between must be consumed completely, which is what distinguishes a
    name split across cells from two unrelated cells that happen to be
    adjacent.
    """

    if combined is None:
        return []
    results: list[tuple[int, list[tuple[int, int, int]], str]] = []
    for start_index in range(len(unit_texts)):
        for width in range(2, min(CROSS_UNIT_MAX_WINDOW, len(unit_texts) - start_index) + 1):
            window = unit_texts[start_index : start_index + width]
            joined = " ".join(window)
            bounds: list[tuple[int, int]] = []
            cursor = 0
            for text in window:
                bounds.append((cursor, cursor + len(text)))
                cursor += len(text) + 1
            for match in combined.finditer(joined):
                group = match.lastgroup
                if group is None or group not in named:
                    continue
                first = last = -1
                for position, (begin, end) in enumerate(bounds):
                    if begin <= match.start() < end:
                        first = position
                    if begin <= match.end() - 1 < end:
                        last = position
                if first < 0 or last < first:
                    continue
                if any(
                    not (match.start() <= bounds[middle][0] and bounds[middle][1] <= match.end())
                    for middle in range(first + 1, last)
                ):
                    continue
                fragments: list[tuple[int, int, int]] = []
                for position in range(first, last + 1):
                    begin, end = bounds[position]
                    fragments.append(
                        (
                            start_index + position,
                            max(match.start(), begin) - begin,
                            min(match.end(), end) - begin,
                        )
                    )
                if not all(unit_texts[index][start:end].strip() for index, start, end in fragments):
                    continue
                results.append((start_index, fragments, named[group][0]))
    return results


def _propagate_document_values(
    units: list[_DocxUnit], detections: list[list[Entity]]
) -> list[list[Entity]]:
    """Propagate high-confidence names/entities across formatting variants.

    RHP tables often put a person's name in one run in title case and repeat
    it in another run in all caps.  A first pass supplies reliable seeds from
    labelled/role/table contexts; the second pass finds exact repetitions of
    those values without broadening the generic person scanner to arbitrary
    capitalized prose.  A final boundary pass covers a value split between two
    adjacent paragraph/table-cell units.
    """

    person_values: dict[str, str] = {}
    organization_values: dict[str, str] = {}
    for entities in detections:
        for entity in entities:
            value = re.sub(r"\s+", " ", entity.text).strip()
            key = value.casefold()
            if entity.pii_type == PIIType.PERSON and entity.detector in {
                "context-name",
                "role-name",
                "title-name",
                "table-name",
            }:
                if len(value.split()) >= 2:
                    person_values.setdefault(key, value)
            elif entity.pii_type == PIIType.ORG and entity.detector in {
                "legal-suffix",
                "legal-suffix-caps",
                "business-suffix",
                "business-suffix-caps",
                "organization-list",
            }:
                # Do not propagate a merged list or a conjunction-prefixed
                # fragment.  The detector's per-entity pass still handles it.
                if (
                    len(value.split()) >= 2
                    and not re.search(r"(?i)\band\b", value)
                    and not value.casefold().startswith(("and ", "or "))
                ):
                    organization_values.setdefault(key, value)

    propagated: list[list[Entity]] = []
    for unit, entities in zip(units, detections):
        additions: list[Entity] = []
        occupied = [(entity.start, entity.end) for entity in entities]
        for value, pii_type, source in (
            *[(item, PIIType.PERSON, "document-person") for item in person_values.values()],
            *[(item, PIIType.ORG, "document-organization") for item in organization_values.values()],
        ):
            pattern = _known_value_pattern(value)
            if pattern is None:
                continue
            for match in pattern.finditer(unit.text):
                start, end = match.span()
                if any(start < old_end and old_start < end for old_start, old_end in occupied):
                    continue
                left = unit.text[max(0, start - 2) : start]
                right = unit.text[end : end + 2]
                # Do not treat a name-like substring of an email/URL as a
                # separate entity.  Structured detectors own those values.
                if "@" in left or "@" in right or "://" in unit.text[max(0, start - 12) : end + 12]:
                    continue
                additions.append(
                    Entity(
                        text=unit.text[start:end],
                        pii_type=pii_type,
                        start=start,
                        end=end,
                        part=unit.unit_id,
                        context=unit.text[max(0, start - 90) : min(len(unit.text), end + 90)],
                        score=0.99,
                        detector=source,
                        identity=value,
                    )
                )
                occupied.append((start, end))
        propagated.append(resolve_overlaps([*entities, *additions]))

    # Handle logical values split at an adjacent-unit boundary.  Each side is
    # emitted as a local span so the DOCX replacement remains paragraph-safe;
    # the shared identity keeps the synthetic replacement deterministic.
    cross_values = [
        *[(value, PIIType.PERSON) for value in person_values.values()],
        *[(value, PIIType.ORG) for value in organization_values.values()],
    ]
    for index in range(len(units) - 1):
        left_unit = units[index]
        right_unit = units[index + 1]
        left_additions: list[Entity] = []
        right_additions: list[Entity] = []
        left_occupied = [(entity.start, entity.end) for entity in propagated[index]]
        right_occupied = [(entity.start, entity.end) for entity in propagated[index + 1]]
        for value, pii_type in cross_values:
            for (
                left_text,
                left_start,
                left_end,
                right_text,
                right_start,
                right_end,
            ) in _cross_unit_fragments(
                left_unit.text,
                right_unit.text,
                value,
                pii_type,
                left_unit.unit_id,
                right_unit.unit_id,
            ):
                if any(
                    left_start < old_end and old_start < left_end
                    for old_start, old_end in left_occupied
                ) or any(
                    right_start < old_end and old_start < right_end
                    for old_start, old_end in right_occupied
                ):
                    continue
                left_additions.append(
                    Entity(
                        text=left_text,
                        pii_type=pii_type,
                        start=left_start,
                        end=left_end,
                        part=left_unit.unit_id,
                        context=left_unit.text[
                            max(0, left_start - 90) : min(len(left_unit.text), left_end + 90)
                        ],
                        score=0.98,
                        detector="document-cross-unit",
                        identity=value,
                    )
                )
                right_additions.append(
                    Entity(
                        text=right_text,
                        pii_type=pii_type,
                        start=right_start,
                        end=right_end,
                        part=right_unit.unit_id,
                        context=right_unit.text[
                            max(0, right_start - 90) : min(len(right_unit.text), right_end + 90)
                        ],
                        score=0.98,
                        detector="document-cross-unit",
                        identity=value,
                    )
                )
                left_occupied.append((left_start, left_end))
                right_occupied.append((right_start, right_end))
        if left_additions:
            propagated[index] = resolve_overlaps([*propagated[index], *left_additions])
        if right_additions:
            propagated[index + 1] = resolve_overlaps(
                [*propagated[index + 1], *right_additions]
            )

    # Finally, cover a value laid out over three or more consecutive units, and
    # a two-unit value whose halves are both at a unit boundary.  One combined
    # pattern keeps the scan linear in the number of units.
    named: dict[str, tuple[str, PIIType]] = {}
    alternatives: list[str] = []
    for position, (value, pii_type) in enumerate(cross_values):
        pattern = _value_pattern(value)
        if pattern is None:
            continue
        group = f"v{position}"
        named[group] = (value, pii_type)
        alternatives.append(f"(?P<{group}>{pattern})")
    combined = (
        re.compile("|".join(alternatives), re.IGNORECASE) if alternatives else None
    )
    unit_texts = [unit.text for unit in units]
    for _, fragments, value_text in _cross_unit_window_fragments(unit_texts, combined, named):
        pii_type = next(
            pii_type for value, pii_type in cross_values if value == value_text
        )
        if any(
            start < entity.end and entity.start < end
            for index, start, end in fragments
            for entity in propagated[index]
        ):
            continue
        for index, start, end in fragments:
            text = unit_texts[index]
            propagated[index] = resolve_overlaps(
                [
                    *propagated[index],
                    Entity(
                        text=text[start:end],
                        pii_type=pii_type,
                        start=start,
                        end=end,
                        part=units[index].unit_id,
                        context=text[max(0, start - 90) : min(len(text), end + 90)],
                        score=0.98,
                        detector="document-cross-unit",
                        identity=value_text,
                    ),
                ]
            )

    return propagated


def _reserved_values(entities: Iterable[Entity]) -> list[str]:
    """Collect every detected source value a replacement must not reproduce."""

    values: list[str] = []
    for entity in entities:
        values.append(entity.text)
        if entity.identity:
            values.append(entity.identity)
    return values


def redact_docx(
    input_path: str | Path,
    output_path: str | Path,
    detector: Optional[PIIDetector] = None,
    registry: Optional[ReplacementRegistry] = None,
) -> RedactionResult:
    """Redact a DOCX in place in a copied document and save it separately.

    Paragraph, table-cell, header/footer, hyperlink-display, and text-box
    ``w:p`` nodes are processed.  Existing styles and run properties are kept;
    when an entity crosses runs, the replacement is placed in the first run
    and the remaining original text is cleared.
    """

    source = Path(input_path)
    target = Path(output_path)
    if source.resolve() == target.resolve():
        raise ValueError("Input and output paths must be different")
    if source.suffix.lower() != ".docx":
        raise ValueError(f"Expected a .docx input, got: {source}")

    detector = detector or PIIDetector()
    registry = registry or ReplacementRegistry()
    document = Document(str(source))
    units = _collect_docx_units(document)
    predictions: list[Entity] = []
    email_replacements: dict[str, str] = {}

    # Detect first, then propagate only high-confidence values across nearby
    # table cells/runs.  This keeps every replacement span local to its source
    # text unit while recovering names and organizations repeated in a
    # different capitalization or run layout.
    detections: list[list[Entity]] = []
    for index, unit in enumerate(units):
        context_prefix = _neighbor_context(units, index)
        detections.append(detector.detect(unit.text, unit.unit_id, context_prefix=context_prefix))
    detections = _propagate_document_values(units, detections)

    # Replacements are generated from a seeded pool, and a generated value can
    # coincide with a real value elsewhere in the document (for example a
    # person name the generator happens to produce).  Reserving every detected
    # value makes that impossible, so verifying "no original value remains" by
    # plain text search is sound.
    registry.reserve(
        _reserved_values(entity for entities in detections for entity in entities)
    )

    for unit, entities in zip(units, detections):
        # Apply right-to-left so offsets in the original unit remain valid.
        for entity in sorted(entities, key=lambda item: (item.start, item.end), reverse=True):
            replacement = registry.replacement_for(entity)
            if _replace_span(unit.element, entity.start, entity.end, replacement):
                predictions.append(entity)
                if entity.pii_type == PIIType.EMAIL:
                    email_replacements[entity.text] = replacement
    _update_hyperlink_targets(document, email_replacements)
    target.parent.mkdir(parents=True, exist_ok=True)
    document.save(str(target))

    # Reopen explicitly so a malformed package fails during processing rather
    # than being reported as a successful run.
    reopened = Document(str(target))
    reopened_units = _collect_docx_units(reopened)
    return RedactionResult(
        predictions=predictions,
        source_units=_public_units(units),
        redacted_units=_public_units(reopened_units),
        output_path=target,
    )


def _pdf_page_units(pdf_path: str | Path) -> list[TextUnit]:
    try:
        import pdfplumber  # type: ignore
    except ImportError as exc:  # pragma: no cover - dependency error path
        raise RuntimeError("PDF input requires pdfplumber; install requirements.txt") from exc

    units: list[TextUnit] = []
    with pdfplumber.open(str(pdf_path)) as pdf:
        for page_number, page in enumerate(pdf.pages, start=1):
            text = page.extract_text() or ""
            if text.strip():
                units.append(TextUnit("source", f"page-{page_number:03d}", text))
    return units


def redact_pdf(
    input_path: str | Path,
    output_path: str | Path,
    detector: Optional[PIIDetector] = None,
    registry: Optional[ReplacementRegistry] = None,
) -> RedactionResult:
    """Extract PDF text and create a readable DOCX containing redacted text.

    PDF layout is not reconstructed as vector-perfect DOCX.  Page boundaries,
    line breaks, and paragraph text are retained; this is safer than claiming
    exact formatting that pdfplumber cannot round-trip.
    """

    source = Path(input_path)
    target = Path(output_path)
    if source.resolve() == target.resolve():
        raise ValueError("Input and output paths must be different")
    if source.suffix.lower() != ".pdf":
        raise ValueError(f"Expected a .pdf input, got: {source}")

    detector = detector or PIIDetector()
    registry = registry or ReplacementRegistry()
    source_units = _pdf_page_units(source)
    document = Document()
    per_unit: list[list[Entity]] = [
        detector.detect(unit.text, unit.unit_id) for unit in source_units
    ]
    # See ``redact_docx``: replacements must never reproduce a detected value.
    registry.reserve(
        _reserved_values(entity for entities in per_unit for entity in entities)
    )
    predictions: list[Entity] = []
    for unit, entities in zip(source_units, per_unit):
        redacted, _ = registry.redact_text(unit.text, entities)
        predictions.extend(entities)
        document.add_heading(f"Source page {unit.unit_id.split('-')[-1]}", level=2)
        for line in redacted.splitlines() or [""]:
            document.add_paragraph(line)

    target.parent.mkdir(parents=True, exist_ok=True)
    document.save(str(target))
    reopened = Document(str(target))
    return RedactionResult(
        predictions=predictions,
        source_units=source_units,
        redacted_units=_public_units(_collect_docx_units(reopened)),
        output_path=target,
    )


def redact_document(
    input_path: str | Path,
    output_path: str | Path,
    detector: Optional[PIIDetector] = None,
    registry: Optional[ReplacementRegistry] = None,
) -> RedactionResult:
    suffix = Path(input_path).suffix.lower()
    if suffix == ".docx":
        return redact_docx(input_path, output_path, detector, registry)
    if suffix == ".pdf":
        return redact_pdf(input_path, output_path, detector, registry)
    raise ValueError("Supported input formats are .docx and .pdf")
