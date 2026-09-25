# Ground-truth annotation policy

This document defines the rules used to produce the annotation sets in
`evaluation/`. It exists so that the two corpora in this repository can be
re-audited by someone who did not build the detectors.

`evaluation/ground_truth.json` covers the **synthetic fixture**
(`input/synthetic_rhp_fixture.docx`, every value fabricated).
`evaluation/real_rhp_ground_truth.json` covers the **real source document**.

The rules below are identical for both, so the two sets stay comparable.

> All examples in this file are generic placeholders. No value taken from the
> real source document is reproduced here, in the README, or in any generated
> report.

## Independence

Annotations are produced by reading the **source document text only**. The
annotator must not consult detector predictions, redacted output, or detector
source code before annotating a unit. A second pass may then compare the
annotation set against the predictions, but only to *review* decisions that were
already made from the text: every such change is recorded in
`qa_corrections.log`, and a change may never be made purely because it raises
the score.

## Units

Every non-empty paragraph, table-cell paragraph, header/footer paragraph, and
text-box paragraph has a unit id of the form `word/document.xml:pNNNN`. Offsets
are resolved later by `tools/merge_ground_truth.py`, so annotations are written
as text only. Spans are copied character-for-character, including internal tab
characters.

A span must not include:

- a leading or trailing tab, space, or cell separator;
- a trailing footnote marker (`*`);
- a trailing conjunction (`&`) or row separator (`^`);
- a role or designation that follows the name (`<Name>, Chairman` -> annotate
  `<Name>`).

## Categories

Emit one annotation per **occurrence**, not per distinct value: the same name in
ten cells is ten annotations. Repeated text within one unit is annotated once
per occurrence, in reading order.

### PERSON

Any natural person named in the document:

- full name, with or without initials;
- a shortened form that clearly refers to a person in a promoter, shareholder,
  director, transferor, or management context;
- a Hindu Undivided Family designation named after a natural person
  (`<Surname> HUF`) -> **PERSON**;
- a personal contact person in a contact-details table.

Not PERSON:

- a company, LLP, trust, foundation, firm, bank, or exchange, even when the name
  looks like a person name (that is ORG);
- a role or designation alone, with no name attached;
- section titles, defined terms, and ordinary capitalized prose.

### ORG

A **named commercial or financial legal entity** that the document presents as a
party, counterparty, group company, or service provider:

- companies with any legal suffix (`<Name> Private Limited`, `<Name> Limited`,
  `<Name> Inc.`, `<Name> N.A.`, `<Name> LLC`, `<Name> AB`);
- limited liability partnerships, partnerships, and professional firms;
- trusts, foundations, and associations;
- named commercial brands used as a legal party;
- named banks and stock exchanges.

Not ORG:

- statutory/regulatory authorities and government bodies referenced by role
  (a securities regulator, a central bank, a registrar of companies, a
  government, a state government, any ministry or department);
- pure acronyms and abbreviations used as abbreviations (`CIN`, `PAN`, `DIN`,
  `GST`, `FEMA`, `NBFC`, `KMP`, `RHP`, `DRHP`, `IPO`);
- generic lowercase nouns (`the Company`, `our Promoters`, `the Group`);
- section titles and defined terms.

A name written in all capitals is recorded in capitals. A name written with a
former-name parenthetical is two entities and is annotated twice, once per
legal name, because each is a separate redactable value.

### ADDRESS

A physical address span: street/road/lane, plot/flat/house/survey/block number,
floor/wing/building, village/taluka, post office, landmark, and the
city/state/PIN tail.

- A **continuation cell that only carries the locality tail** (for example a cell
  reading `<City> - <PIN>`) **is** an address, because a table may lay one
  address out over several cells.
- A leading location lead-in that is part of the address description
  (`opposite <landmark>`, `above <landmark>`, `near <landmark>`) and a leading
  building name are inside the span.

Not ADDRESS:

- a bare `City, State` pair with no street, number, building, or PIN component;
- a place named as a country, region, or market, and phrases such as
  `domestic market`;
- an event location described only by a city;
- identifiers and numbers: CIN, GSTIN, PAN, DIN, registration numbers, order or
  ticket numbers, share counts, dates.

### EMAIL

Any email address, including the address carried inside a `mailto:` hyperlink or
a Word field code.

### PHONE

Any telephone contact detail: mobile, landline with or without an STD/ISD code,
and the number that follows a `Telephone`/`Phone`/`Mobile` label. The country
code is included when it is written.

### Numbers that are neither contact details nor payment cards

A digit string is only a phone number or a payment card when the context
supports it. These are **not** annotated:

- company registration and tax identifiers (`CIN`, `GSTIN`, `PAN`, `DIN`);
- order, ticket, invoice, transaction, cheque, and receipt numbers;
- share counts, revenue figures, and page numbers;
- financial-year ranges and any other multi-digit span that is not a number.

The deciding label is the one **preceding** the value. `Ticket No. <10 digits>,
please contact us` is a ticket number, because `contact` labels the sentence
rather than the value. `<Contact> number <10 digits>` is a phone number, because
a contact label is unambiguous. A card word outranks the generic word `number`,
so `Card number <16 digits>` is a card. A payment-card match additionally has
to pass Luhn validation *and* carry no contradicting identifier label.

## Categories with no expected instances

`SSN`, `CREDIT_CARD`, `DOB`, and `IP` are expected to be **empty** for an
Indian RHP and are reported as `N/A - no instances present in source` rather
than as a perfect score. Dates of incorporation, board-meeting dates, and
financial-year ranges are ordinary dates, never `DOB`. `PAN`, `DIN`, and `CIN`
are identifiers and are not annotated in any category.

## What a score of 100% precision does and does not prove

Precision is measured against this ground truth, so it can only prove that the
detector agrees with the annotator. It cannot prove that the *policy* above is
right, and it cannot see a PII class that was never annotated in the first
place. The recall figure and the audit trail are the parts that carry
independent information.

## Layout-split values

A table may split one name across consecutive cells, one token per cell, or
across paragraph boundaries. Every visible piece is annotated separately,
including a bare legal-form tail, because the pieces together reconstruct the
name and the ground truth must not certify a value as removed while its
fragments remain legible.

## Value-leak rule

The ground truth is a *privacy* artefact as well as a scoring artefact. A value
that has been annotated must not be reconstructable from what the redactor
leaves behind. This is why layout-split fragments and address continuation cells
are annotated even when they are not independently identifying.

## Output format

One JSON object per line, no prose, no code fence, no trailing commas:

```json
{"unit_id": "word/document.xml:pNNNN", "type": "PERSON", "text": "<Full Name>"}
```

## Tooling and audit trail

| Step | Command |
| --- | --- |
| Split the document into review units | `python tools/make_ground_truth_chunks.py` |
| Merge the reviewed chunks into the corpus | `python tools/merge_ground_truth.py` |
| Validate every span against the source | `python tools/validate_ground_truth.py` |
| Cross-check annotations against predictions | `python tools/audit_ground_truth.py` |
| Score the run | `python -m src.evaluation` |
| Verify the redacted package | `python tools/verify_output.py` |

`merge_ground_truth.py` resolves each text span to a concrete occurrence,
reports spans that cannot be found or resolved, and drops spans contained in a
span already accepted for the same unit and category. `validate_ground_truth.py`
re-derives every offset from the source and fails on any span that does not
match. `audit_ground_truth.py` prints only shapes, counts, and unit ids; it
never echoes an entity value.
