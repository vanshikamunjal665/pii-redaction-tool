from __future__ import annotations

from pathlib import Path
from zipfile import ZipFile

import pytest
from docx import Document
from docx.opc.constants import RELATIONSHIP_TYPE as RT
from docx.oxml import OxmlElement
from docx.oxml.ns import qn

from src.detectors import PIIDetector
from src.document_processor import (
    contains_original_value,
    extract_docx_text,
    extract_docx_units,
    redact_docx,
)
from src.models import PIIType
from src.replacers import ReplacementRegistry


def add_hyperlink(paragraph, text: str, target: str) -> None:
    relationship_id = paragraph.part.relate_to(target, RT.HYPERLINK, is_external=True)
    hyperlink = OxmlElement("w:hyperlink")
    hyperlink.set(qn("r:id"), relationship_id)
    run = OxmlElement("w:r")
    text_node = OxmlElement("w:t")
    text_node.text = text
    run.append(text_node)
    hyperlink.append(run)
    paragraph._p.append(hyperlink)


def test_docx_redaction_preserves_structure_and_updates_hyperlink(tmp_path: Path) -> None:
    source = tmp_path / "source.docx"
    target = tmp_path / "redacted.docx"
    document = Document()
    document.add_heading("Issuer details", level=1)
    paragraph = document.add_paragraph("Contact: Rashi Patil; email: ")
    add_hyperlink(paragraph, "rashi.patil@gmail.com", "mailto:rashi.patil@gmail.com")
    split_name = document.add_paragraph("Authorised signatory: ")
    split_name.add_run("Rashi ")
    split_name.add_run("Patil")
    table = document.add_table(rows=2, cols=2)
    table.cell(0, 0).text = "Registered office"
    table.cell(0, 1).text = "221B, Green Park, New Delhi, Delhi 110001"
    table.cell(1, 0).text = "Date of Birth"
    table.cell(1, 1).text = "14/08/1998"
    document.sections[0].header.paragraphs[0].text = "Acme Technologies Pvt. Ltd."
    document.sections[0].footer.paragraphs[0].text = "Page 1"
    document.save(source)

    result = redact_docx(
        source,
        target,
        detector=PIIDetector(use_spacy=False),
        registry=ReplacementRegistry(seed=7),
    )
    assert target.is_file()
    assert result.predictions
    text = extract_docx_text(target)
    assert "Rashi Patil" not in text
    assert "rashi.patil@gmail.com" not in text
    assert "Acme Technologies Pvt. Ltd." not in text
    assert "14/08/1998" not in text
    assert "Issuer details" in text
    assert "Page 1" in text

    units = extract_docx_units(target)
    assert any("example.com" in unit.text for unit in units)
    # Reopening the package and inspecting relationships catches stale mailto
    # targets that a plain text-only implementation would miss.
    reopened = Document(str(target))
    targets = [
        rel.target_ref
        for rel in reopened.part.rels.values()
        if rel.reltype == RT.HYPERLINK
    ]
    assert targets
    assert all("rashi.patil@gmail.com" not in target for target in targets)
    assert all("example.com" in target for target in targets)


def test_redaction_refuses_to_overwrite_input(tmp_path: Path) -> None:
    source = tmp_path / "source.docx"
    document = Document()
    document.add_paragraph("Contact: Rashi Patil")
    document.save(source)
    with pytest.raises(ValueError, match="different"):
        redact_docx(source, source, detector=PIIDetector(use_spacy=False))


def test_residual_check_matches_whole_values_only() -> None:
    """A fragment must not count as surviving because of a longer word."""

    # The RHP promoter name "Broad Family Trust" is split across two table
    # cells, so the half "Broad" is a redacted fragment.  The risk factors
    # still contain the ordinary words "abroad" and "broader"; a plain
    # substring test would report those as a leak.
    assert not contains_original_value("standards in India or abroad,", "Broad")
    assert not contains_original_value("greater resources and broader appeal", "Broad")
    # A real leak is still found, including one embedded in longer text.
    assert contains_original_value("and Broad Family Trust,", "Broad")
    assert contains_original_value("a Broad Family Trust", "Broad Family Trust")
    # Values that start or end with a non-word character still match.
    assert contains_original_value("Telephone: +91 9876543210.", "+91 9876543210")
    assert contains_original_value("Pune - 410 501", "Pune - 410 501")
    # A value re-flowed by Word across paragraphs must still be found.
    assert contains_original_value("KSH\nDistriparks\nPrivate Limited", "KSH Distriparks Private Limited")
    assert not contains_original_value("KSH\nDistriparks\nPrivate", "KSH Distriparks Private Limited")


def add_hyperlink_field(paragraph, display: str, target: str) -> None:
    """Store a hyperlink as a Word field code, the way some suites do.

    The address then lives in ``w:fldSimple@w:instr`` (or ``w:instrText``)
    instead of a relationship, so redacting only relationship targets would
    leave the address in the package XML.
    """

    field = OxmlElement("w:fldSimple")
    field.set(qn("w:instr"), f' HYPERLINK "{target}" ')
    run = OxmlElement("w:r")
    text_node = OxmlElement("w:t")
    text_node.text = display
    run.append(text_node)
    field.append(run)
    paragraph._p.append(field)


def test_redaction_rewrites_hyperlink_field_codes(tmp_path: Path) -> None:
    source = tmp_path / "field_source.docx"
    target = tmp_path / "field_redacted.docx"
    document = Document()
    document.add_paragraph("Issuer e-mail: ")
    add_hyperlink_field(
        document.paragraphs[-1], "rashi.patil@gmail.com", "mailto:rashi.patil@gmail.com"
    )
    document.save(source)

    redact_docx(
        source,
        target,
        detector=PIIDetector(use_spacy=False),
        registry=ReplacementRegistry(seed=11),
    )

    with ZipFile(target) as package:
        package_text = "\n".join(
            package.read(name).decode("utf-8", errors="ignore")
            for name in package.namelist()
            if name.endswith((".xml", ".rels"))
        )
    assert "rashi.patil@gmail.com" not in package_text
    assert "rashi.patil@gmail.com" not in extract_docx_text(target)
    assert "HYPERLINK" in package_text  # the field itself is preserved


def test_cross_unit_name_fragments_are_both_redacted(tmp_path: Path) -> None:
    """A name split across two table cells must be redacted in both halves."""

    source = tmp_path / "split_source.docx"
    target = tmp_path / "split_redacted.docx"
    document = Document()
    # The intact form elsewhere in the document is what identifies the value;
    # the cross-unit pass then covers the split table cells.
    document.add_paragraph(
        "The Promoters of our Company are DHAULAGIRI FAMILY TRUST and "
        "EVEREST FAMILY TRUST, which are family trusts."
    )
    table = document.add_table(rows=2, cols=2)
    table.cell(0, 0).text = "DHAULAGIRI"
    table.cell(0, 1).text = "FAMILY TRUST"
    table.cell(1, 0).text = "EVEREST"
    table.cell(1, 1).text = "FAMILY TRUST"
    document.save(source)

    result = redact_docx(
        source,
        target,
        detector=PIIDetector(use_spacy=False),
        registry=ReplacementRegistry(seed=3),
    )
    text = extract_docx_text(target)
    for original in ("DHAULAGIRI", "FAMILY TRUST", "EVEREST"):
        assert original not in text
    fragments = [
        entity
        for entity in result.predictions
        if entity.pii_type is PIIType.ORG and entity.detector == "document-cross-unit"
    ]
    # Both halves of both names are covered, and each half of one name carries
    # the same identity so both sides get the same replacement.
    assert len(fragments) == 4
    identities = {entity.identity for entity in fragments}
    assert len(identities) == 2


def test_replacements_never_reproduce_a_source_value(tmp_path: Path) -> None:
    source = tmp_path / "reserve_source.docx"
    target = tmp_path / "reserve_redacted.docx"
    document = Document()
    document.add_paragraph("Contact person: Rashi Patil; e-mail: rashi.patil@gmail.com")
    document.add_paragraph("The Promoters are Rashi Patil and Rashi Kumar.")
    document.save(source)

    result = redact_docx(
        source,
        target,
        detector=PIIDetector(use_spacy=False),
        registry=ReplacementRegistry(seed=1337),
    )
    text = extract_docx_text(target)
    for original in {entity.text for entity in result.predictions}:
        assert original.casefold() not in text.casefold()
