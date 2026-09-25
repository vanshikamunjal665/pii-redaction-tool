# PII Redaction Tool

Detects PII in DOCX/PDF input and writes a separate redacted DOCX. The input is
opened read-only and never modified. No external or paid API is used.

## Approach

**Regex-based, with validation and context rules.** Validated regular expressions
find structured values, a small set of context-aware rules decides whether a
number or date is actually sensitive, and an optional spaCy NER adapter
(`--no-spacy` disables it) is available as an extra signal rather than a
dependency. Third-party libraries do the document handling: `python-docx` and
`lxml` for DOCX/OOXML, `pdfplumber` for PDF, `Faker` for seeded synthetic
replacements. Reported numbers come from the deterministic rule path
(`--no-spacy`), since spaCy is not installed in this environment.

Detection runs in three passes because per-paragraph rules alone miss two cases
the real RHP is full of:

1. **Local detection** — structured values (email, IP via `ipaddress` validation,
   SSN via format + allocation checks, cards via Luhn + length), DOB only when
   explicitly labelled, addresses from structural cues, people and
   organizations from title/role/label and legal-suffix context.
2. **Document-level propagation** — a person or organization confirmed elsewhere
   in the document is re-detected in formatting variants (all-caps runs,
   multi-token names) that the local rules miss.
3. **Cross-unit window pass** — a value split across consecutive table cells
   (`<ACME> | <Place> | Private Limited`) or paragraph boundaries is found, and
   **every fragment is redacted** so it cannot be reassembled from what remains.

Replacements are deterministic and reserved for testing: one synthetic value per
normalized `original + type` (so repeats stay consistent), using `@example.com`,
`203.0.113.0/24`, the public `4242…` test card, and an invalid-allocation SSN.
Types: `PERSON`, `ORG`, `ADDRESS`, `EMAIL`, `PHONE`, `SSN`, `CREDIT_CARD`, `DOB`,
`IP`. The source DOCX is edited in place of text only — body, tables, headers,
footers, text boxes, and hyperlinks, including `w:instrText`/`w:fldSimple` field
codes, of which the real RHP has 105 (all rewritten).

## Results

Two result sets, never mixed. The synthetic fixture is a fabricated regression
harness; the real RHP is the evidence.

| | Synthetic fixture | Real RHP |
| --- | ---: | ---: |
| Ground-truth entities | 26 | 631 |
| Predictions | 26 | 584 |
| TP / FP / FN | 26 / 0 / 0 | 584 / 0 / 47 |
| Precision | 100% | 100% |
| Recall | 100% | 92.6% |
| F1 | 100% | 96.1% |

Arbitrary text spans have no meaningful true-negative set, so binary accuracy
would mislead; the reports use **entity-decision accuracy** `TP / (GT + FP)`
(100% and 92.6% respectively). A prediction counts as a true positive only on an
exact normalized text + category match at a matching location.

Real RHP, per category (4,864 units extracted):

| Category | GT | TP | FP | FN | Precision | Recall |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| `PERSON` | 215 | 203 | 0 | 12 | 100% | 94.4% |
| `ORG` | 253 | 226 | 0 | 27 | 100% | 89.3% |
| `ADDRESS` | 75 | 67 | 0 | 8 | 100% | 89.3% |
| `EMAIL` | 52 | 52 | 0 | 0 | 100% | 100% |
| `PHONE` | 36 | 36 | 0 | 0 | 100% | 100% |
| `SSN` / `CREDIT_CARD` / `DOB` / `IP` | 0 | – | – | – | N/A | N/A |

The ground truth was produced by reading the source document independently of
the detector, under `docs/annotation_policy.md`, then validated span-by-span
against the source (0 errors). `SSN`, `CREDIT_CARD`, `DOB`, and `IP` are reported
as `N/A — no instances present in source`, not as a perfect score: a mechanical
sweep found no such value anywhere in the document.

## Verification

`tools/verify_output.py` exits non-zero unless it can show the redaction
happened, and reports no entity values:

- every detected value is absent from the **whole package XML**, not just the
  body — so a value cached in a field code, relationship, or header is caught;
- the match is **whole-value, not substring** (`(?<![A-Za-z0-9_])value(?![A-Za-z0-9_])`
  with `\s+` between tokens), because a substring test reports `Broad` surviving
  inside `abroad` and misses a value re-flowed across runs;
- no stale `mailto:` hyperlink survives in either form;
- the output reopens, and per-unit results plus input/output SHA-256 are recorded.

On the real RHP: `passed: true`, **0 residual original values**, 0 stale field
codes across 105, output reopened, 4,864 units checked. The input digest is
unchanged, confirming the source was never written to.

## Tradeoffs, false positives and false negatives

**Precision is 100% — there are no false positives at all** — but read it for
what it is: it means the detector agrees with the annotation policy and redacted
nothing the policy did not call PII. It is not evidence the policy is complete.

**All 47 misses are false negatives**, in three clusters:

- **~18 bare trading/brand names used as a party.** `ORG` keys on a legal suffix
  or a label, and propagation matches whole values rather than aliases, so a
  column writing a brand alone is missed even though the full legal name appears
  elsewhere. Most systematic gap; a document-derived alias table would fix it and
  is the next step.
- **12 one-off director names** with no title, no role prefix, and no second
  occurrence, so propagation has nothing to propagate.
- **8 short address forms** — bare house-number lists and locality-only cells
  with no street, keyword, or PIN for the structural rules to use.

**Deliberately not redacted** (policy choice, per `docs/annotation_policy.md`):
`CIN`/`GSTIN`/`PAN`/`DIN` and other registry identifiers; order, ticket, invoice,
transaction, cheque and receipt numbers; filing, board-meeting and financial-year
dates; share counts, revenue and page numbers; bare city/state pairs, countries
and markets. These are business data, not personal data — treating them as
sensitive is defensible but would be over-redaction. A number in one of these
contexts is suppressed only when the label sits **before** it, so
`Ticket No. 9876543210, please contact us` stays clear while
`Contact number 9876543210` is redacted. The real RHP contains 16 phone-shaped
strings that are not phones (financial-year ranges, a circular number, 8-digit
DINs) and these are correctly left alone.

**Other tradeoffs:** treating every detected organization as sensitive satisfies
the required `ORG` category but can redact non-personal entities. A Luhn-valid
16-digit string in an identifier context is correctly rejected, but the label
test is a keyword heuristic, so an unlabelled card value in a cell is still a
risk in a high-stakes deployment. The fallback name detector uses a small
first-name list and will miss names outside it; spaCy NER would help at the cost
of more false positives. PDF extraction can lose layout and reading order — the
output preserves extracted text and page boundaries, not the original visual
design. Synthetic replacement values are non-production by design.

## Reproduce

```bash
python -m pip install -r requirements.txt
python -m pytest -q

# synthetic fixture
python run.py --input input/synthetic_rhp_fixture.docx --output output/redacted_rhp.docx \
  --predictions evaluation/predictions.json --ground-truth evaluation/ground_truth.json \
  --report evaluation/evaluation_report.md --no-spacy

# real document (input/real/ is gitignored; the file is never modified)
python run.py --input input/real/rhp.docx --output output/real_rhp_redacted.docx \
  --predictions evaluation/real_rhp_predictions.json --no-spacy
python -m src.evaluation --ground-truth evaluation/real_rhp_ground_truth.json \
  --predictions evaluation/real_rhp_predictions.json \
  --output evaluation/real_rhp_evaluation_report.md
python tools/verify_output.py --input input/real/rhp.docx \
  --output output/real_rhp_redacted.docx \
  --predictions evaluation/real_rhp_predictions.json \
  --report evaluation/real_rhp_verification.json
```

Adding a type: add a `PIIType` member, a detector returning an `Entity` with
precise offsets, its call in `PIIDetector.detect`, a branch in
`ReplacementRegistry.replacement_for`, and tests. Report tables iterate
`SUPPORTED_TYPES`, so the new category appears in the metrics automatically.

## Notes

- The real RHP is **not committed**, and neither are
  `evaluation/real_rhp_ground_truth.json` or `evaluation/real_rhp_predictions.json`,
  because they reproduce source values by design. `output/real_rhp_redacted.docx`
  and `evaluation/real_rhp_evaluation_report.md` *are* tracked: the first contains
  only reserved test values, and the second describes entities by category, span
  shape, token count and unit id only — it never prints a value. Consequence: a
  clone can read the metrics but cannot re-derive them without re-annotating.
- Full annotation rules and the audit trail: `docs/annotation_policy.md`.
- Layout: `src/` (`detectors`, `document_processor`, `replacers`, `evaluation`,
  `models`, `main`), `tests/`, `tools/` (ground-truth build, validation, audit,
  verification), `input/`, `output/`, `evaluation/`, `docs/`.
