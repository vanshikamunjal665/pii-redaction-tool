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


# ---------------------------------------------------------------------------
# Regression cases taken from the real Red Herring Prospectus
# ---------------------------------------------------------------------------


def test_all_caps_organization_variants(detector: PIIDetector) -> None:
    text = (
        "OUR PROMOTERS: PUSHPA KUSHAL HEGDE, DHAULAGIRI FAMILY TRUST, "
        "EVEREST FAMILY TRUST, BROAD FAMILY TRUST"
    )
    assert set(found(detector, text)[PIIType.ORG]) == {
        "DHAULAGIRI FAMILY TRUST",
        "EVEREST FAMILY TRUST",
        "BROAD FAMILY TRUST",
    }
    # A lowercase lead-in must not hide the all-caps name, and a lowercase
    # connector must not be swallowed into the span.
    assert found(
        detector,
        "The Promoters of our Company are DHAULAGIRI FAMILY TRUST and "
        "EVEREST FAMILY TRUST.",
    )[PIIType.ORG] == ["DHAULAGIRI FAMILY TRUST", "EVEREST FAMILY TRUST"]


def test_all_caps_headings_are_not_organizations(detector: PIIDetector) -> None:
    # The uppercase patterns need a business or legal suffix, so section
    # headings and defined terms stay out of the result.
    for heading in (
        "RISK FACTORS",
        "USE OF PROCEEDS",
        "OBJECTS OF THE ISSUE",
        "HISTORY AND CORPORATE STRUCTURE",
        "MAJOR SHAREHOLDERS",
        "INTERNAL FINANCIAL RISK MANAGEMENT",
        "OUTLOOK AND PROJECTIONS",
        "BASIS OF PRESENTATION",
    ):
        assert found(detector, heading)[PIIType.ORG] == [], heading


def test_lowercase_article_is_stripped_but_capital_the_is_kept(detector: PIIDetector) -> None:
    values = found(
        detector,
        "The Offer Escrow Collection Bank for the Issuer is the BSE Limited, "
        "and the collection agent is HDFC Bank Limited. "
        "The banker is The Federal Bank Limited.",
    )[PIIType.ORG]
    assert "BSE Limited" in values
    assert "HDFC Bank Limited" in values
    assert "The Federal Bank Limited" in values
    assert not any(value.startswith("the ") for value in values)


def test_address_keeps_landmark_lead_in_and_drops_cue_word(detector: PIIDetector) -> None:
    values = found(
        detector,
        "Our Registered Office is at 11/3, 11/4 and 11/5, Village Birdewadi, "
        "Chakan Taluka - Khed, Pune - 410 501.",
    )[PIIType.ADDRESS]
    assert values == [
        "11/3, 11/4 and 11/5, Village Birdewadi, Chakan Taluka - Khed, Pune - 410 501"
    ]

    landmark = found(
        detector,
        "Registered Office at S. no. 245/ 104, Pushpakamal, Deccan Gymkhana Society, "
        "lane no. 3 Prabhat Road, opposite PYC basketball court, Deccan Gymkhana, "
        "Pune \u2013 411 004 Maharashtra, India",
    )[PIIType.ADDRESS]
    assert len(landmark) == 1
    assert landmark[0].startswith("S. no. 245/ 104")
    assert "opposite PYC basketball court" in landmark[0]


def test_filing_prose_is_not_an_address(detector: PIIDetector) -> None:
    assert (
        found(
            detector,
            "Form 1, Form 1A and Form 18 along with corresponding RoC challans "
            "for incorporation of the Company dated July 30, 1979, application "
            "for reservation of name, and intimation of registered office "
            "respectively",
        )[PIIType.ADDRESS]
        == []
    )


def test_share_transfer_row_names_are_detected(detector: PIIDetector) -> None:
    assert found(
        detector,
        "Form 7B for transfer of shares to Kushal Hegde from DM Shetty and Gopal BO.",
    )[PIIType.PERSON] == ["Kushal Hegde", "DM Shetty", "Gopal BO"]
    assert found(
        detector,
        "Form SH- 4 for transfer of shares by Kushal Hegde, Rajesh Hegde and "
        "Rohit Hegde to Pushpa Hegde.",
    )[PIIType.PERSON] == [
        "Kushal Hegde",
        "Rajesh Hegde",
        "Rohit Hegde",
        "Pushpa Hegde",
    ]


def test_share_transfer_prose_does_not_create_names(detector: PIIDetector) -> None:
    assert (
        found(
            detector,
            "Any transfer of shares by the dematerialised account holders to the "
            "Investors shall be subject to the SEBI LODR Regulations.",
        )[PIIType.PERSON]
        == []
    )


def test_allotment_list_keeps_names_with_initials(detector: PIIDetector) -> None:
    assert found(
        detector,
        "1,000 equity shares allotted to Karunakar N. Bhandary, 500 equity shares "
        "allotted to Kushal Subbayya Hegde, Narayna B. Shetty and Jayaram N. Shetty.",
    )[PIIType.PERSON] == [
        "Karunakar N. Bhandary",
        "Kushal Subbayya Hegde",
        "Narayna B. Shetty",
        "Jayaram N. Shetty",
    ]


def test_section_title_and_document_reference_are_not_persons(detector: PIIDetector) -> None:
    assert (
        found(
            detector,
            'For further details, see \u201cGeneral Information\u201d on pages 74 and 26',
        )[PIIType.PERSON]
        == []
    )
    assert (
        found(
            detector,
            "allotted to Karunakar N. Bhandary pursuant to the initial subscription "
            "to the MoA dated June 29, 1979",
        )[PIIType.PERSON]
        == ["Karunakar N. Bhandary"]
    )


def test_promoter_list_after_lead_in_is_fully_detected(detector: PIIDetector) -> None:
    assert found(
        detector,
        "We are led by our Individual Promoters Kushal Subbayya Hegde, "
        "Pushpa Kushal Hegde, Rajesh Kushal Hegde, Rohit Kushal Hegde and "
        "Rakhi Girija Shetty.",
    )[PIIType.PERSON] == [
        "Kushal Subbayya Hegde",
        "Pushpa Kushal Hegde",
        "Rajesh Kushal Hegde",
        "Rohit Kushal Hegde",
        "Rakhi Girija Shetty",
    ]


def test_possessive_role_before_a_name(detector: PIIDetector) -> None:
    assert found(
        detector,
        "our Promoter, Pushpa Hegde have been unable to trace certain documents",
    )[PIIType.PERSON] == ["Pushpa Hegde"]


def test_company_name_wins_over_a_person_in_a_transfer_row(detector: PIIDetector) -> None:
    entities = detector.detect(
        "Form 7B for transfer of shares to Kushal Hegde from "
        "Shubhkamal Leasing and Investment Private Limited"
    )
    assert [(e.pii_type, e.text) for e in entities] == [
        (PIIType.PERSON, "Kushal Hegde"),
        (PIIType.ORG, "Shubhkamal Leasing and Investment Private Limited"),
    ]


def test_standalone_address_cells_are_detected(detector: PIIDetector) -> None:
    # A table that spreads an address over several rows gives the continuation
    # cells no neighbouring cue, so a short self-contained cell must count as
    # its own context.
    for value in (
        "Pune - 411 038",
        "Pune \u2013 411 001",
        "One World Centre",
        "Koregaon Park, Pune \u2013 411 001 Maharashtra, India",
        "Bandra East, Mumbai \u2013 400 051 Maharashtra, India",
        "2401 Gen Thimmayya Road, Cantonment",
    ):
        assert found(detector, value)[PIIType.ADDRESS] == [value], value


def test_short_non_address_cells_are_rejected(detector: PIIDetector) -> None:
    # A bare number, a locality in parentheses, or a fragment of prose is not a
    # physical address just because the cell is short.
    for value in (
        "5 each thereafter",
        "1 (Taloja)",
        "Face Value of \u20b95 Each",
        "Maharashtra, India",
    ):
        assert found(detector, value)[PIIType.ADDRESS] == [], value


def test_address_after_a_preposition_in_prose(detector: PIIDetector) -> None:
    # The sentence is not the address: the value starts after the preposition
    # that introduces it, and it must still be redacted.
    assert found(
        detector,
        "Notice may be sent to Ramesh Iyer at 221B, Green Park, New Delhi, Delhi 110001",
    )[PIIType.ADDRESS] == ["221B, Green Park, New Delhi, Delhi 110001"]


def test_numbers_after_a_preposition_are_not_addresses(detector: PIIDetector) -> None:
    # A preposition is not on its own evidence.  A price, a price band, and a
    # phone number introduced by ``at`` must stay out of the address category.
    for value in (
        "The shares are listed at 45.50 per share and the band is 400-450",
        "The price band is 49.5000 to 59.5000 per share",
        "For queries contact us at 040 4004 0500 between 10 am and 5 pm",
    ):
        assert found(detector, value)[PIIType.ADDRESS] == [], value


@pytest.mark.parametrize(
    "text",
    [
        "Order Number 9876543210",
        "Ticket No. 9876543210 please contact us",
        "Invoice number 8765432109",
        "Our revenue was 9876543210 units",
    ],
)
def test_identifier_numbers_are_not_phones(detector: PIIDetector, text: str) -> None:
    """Order, ticket, and revenue numbers are identifiers, not contact details.

    The label that matters is the one *before* the number.  A contact word
    later in the sentence describes the sentence, not the number.
    """
    assert found(detector, text)[PIIType.PHONE] == []


@pytest.mark.parametrize(
    "text",
    [
        "For queries call 9876543210",
        "Contact number 9876543210",
        "Phone: 9876543210",
        "+91 9876543210",
    ],
)
def test_labelled_contact_numbers_are_still_phones(
    detector: PIIDetector, text: str
) -> None:
    assert found(detector, text)[PIIType.PHONE]


@pytest.mark.parametrize(
    "text",
    [
        "Reference number 4111111111111111",
        "Account No 4111111111111111",
        "Receipt code 4111 1111 1111 1111",
    ],
)
def test_identifier_numbers_are_not_credit_cards(
    detector: PIIDetector, text: str
) -> None:
    """A Luhn-valid sixteen-digit string in identifier context is not a card."""
    assert found(detector, text)[PIIType.CREDIT_CARD] == []


@pytest.mark.parametrize(
    "text",
    [
        "4111 1111 1111 1111",
        "Card number 4111 1111 1111 1111",
        "Visa 4111 1111 1111 1111",
    ],
)
def test_card_values_are_still_detected(detector: PIIDetector, text: str) -> None:
    """A card word outranks the generic identifier word "number"."""
    assert found(detector, text)[PIIType.CREDIT_CARD] == ["4111 1111 1111 1111"]


def test_director_identification_numbers_are_not_phones(detector: PIIDetector) -> None:
    """Eight-digit DINs and financial-year ranges must not become phones."""
    assert found(detector, "DIN: 00012345")[PIIType.PHONE] == []
    assert found(detector, "revenue recorded in 2023-2024")[PIIType.PHONE] == []
    assert found(detector, "CIN: U12345MH2020PTC123456")[PIIType.PHONE] == []
