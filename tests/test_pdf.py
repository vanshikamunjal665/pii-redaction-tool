from __future__ import annotations

from pathlib import Path

from src.detectors import PIIDetector
from src.document_processor import extract_docx_text, redact_pdf
from src.replacers import ReplacementRegistry


def write_minimal_pdf(path: Path, text: str) -> None:
    stream = f"BT /F1 12 Tf 72 720 Td ({text}) Tj ET\n".encode("ascii")
    objects = [
        b"<< /Type /Catalog /Pages 2 0 R >>",
        b"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
        b"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] "
        b"/Contents 4 0 R /Resources << /Font << /F1 5 0 R >> >> >>",
        b"<< /Length "
        + str(len(stream)).encode("ascii")
        + b" >>\nstream\n"
        + stream
        + b"endstream",
        b"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
    ]
    package = bytearray(b"%PDF-1.4\n")
    offsets = [0]
    for number, obj in enumerate(objects, start=1):
        offsets.append(len(package))
        package.extend(f"{number} 0 obj\n".encode("ascii"))
        package.extend(obj)
        package.extend(b"\nendobj\n")
    xref_offset = len(package)
    package.extend(f"xref\n0 {len(objects) + 1}\n".encode("ascii"))
    package.extend(b"0000000000 65535 f \n")
    for offset in offsets[1:]:
        package.extend(f"{offset:010d} 00000 n \n".encode("ascii"))
    package.extend(
        f"trailer\n<< /Size {len(objects) + 1} /Root 1 0 R >>\n"
        f"startxref\n{xref_offset}\n%%EOF\n".encode("ascii")
    )
    path.write_bytes(package)


def test_pdf_input_is_extracted_and_redacted_to_docx(tmp_path: Path) -> None:
    source = tmp_path / "source.pdf"
    target = tmp_path / "redacted.docx"
    write_minimal_pdf(
        source,
        "Contact Rashi Patil rashi.patil@gmail.com +91 9876543210",
    )

    result = redact_pdf(
        source,
        target,
        detector=PIIDetector(use_spacy=False),
        registry=ReplacementRegistry(seed=3),
    )
    assert target.is_file()
    assert {entity.pii_type.value for entity in result.predictions} >= {
        "PERSON",
        "EMAIL",
        "PHONE",
    }
    output = extract_docx_text(target)
    assert "Rashi Patil" not in output
    assert "rashi.patil@gmail.com" not in output
    assert "+91 9876543210" not in output
    assert "example.com" in output
