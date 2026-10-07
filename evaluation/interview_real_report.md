# PII Redaction Evaluation Report

## 1. Executive Summary

The entity-level evaluation contains **631** manually/semantically verified annotations and **584** detector predictions.
It produced **584 TP**, **0 FP**, and **47 FN** overall.

## 2. Dataset

- **source:** C:\Users\Vanshika Munjal\Desktop\Red Herring Prospectus.docx
- **annotation_policy:** See docs/annotation_policy.md

## 3. Evaluation Method

Predictions are matched to annotations at the entity level. A match requires the same category and the same text after Unicode normalization, whitespace collapsing, and case folding. When supplied, unit/location and context must also be compatible, which distinguishes repeated identical values. A prediction of the wrong type is a false positive for its predicted type and leaves the true annotation as a false negative.

Nested structured matches are resolved before scoring: a complete address suppresses a phone/email/card-like substring inside that address. There is no artificial true-negative set for arbitrary text spans. Accordingly, the reported **entity-decision accuracy** is `TP / (ground_truth + FP)`, while precision, recall, and F1 use the standard formulas.

## 4. Results

| Category | Ground Truth | Detected | TP | FP | FN | Precision | Recall | F1 | Accuracy |
| -------- | -----------: | -------: | -: | -: | -: | --------: | -----: | --: | --------: |
| PERSON | 215 | 203 | 203 | 0 | 12 | 1.000 | 0.944 | 0.971 | 0.944 |
| EMAIL | 52 | 52 | 52 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| PHONE | 36 | 36 | 36 | 0 | 0 | 1.000 | 1.000 | 1.000 | 1.000 |
| ORG | 253 | 226 | 226 | 0 | 27 | 1.000 | 0.893 | 0.944 | 0.893 |
| ADDRESS | 75 | 67 | 67 | 0 | 8 | 1.000 | 0.893 | 0.944 | 0.893 |
| SSN | 0 | 0 | 0 | 0 | 0 | N/A — no instances present in source | N/A — no instances present in source | N/A — no instances present in source | N/A |
| CREDIT_CARD | 0 | 0 | 0 | 0 | 0 | N/A — no instances present in source | N/A — no instances present in source | N/A — no instances present in source | N/A |
| DOB | 0 | 0 | 0 | 0 | 0 | N/A — no instances present in source | N/A — no instances present in source | N/A — no instances present in source | N/A |
| IP | 0 | 0 | 0 | 0 | 0 | N/A — no instances present in source | N/A — no instances present in source | N/A — no instances present in source | N/A |

## 5. Overall Metrics

- **Entity-decision accuracy:** 92.6% (`TP / (GT + FP)`; no artificial TN)
- **Precision:** 100.0%
- **Recall:** 92.6%
- **F1-score:** 96.1%

## 6. Error Analysis

Entity values are never printed in this report. Each item below is described by category, span shape, size, and location only, so the report can be shared without disclosing the underlying data.

No false positives were observed in the supplied ground-truth set.

False negatives (47 total, up to 20 shown):
- PERSON | 3 token(s) [Capitalized/Capitalized/Capitalized], 20 letters, 0 digits, 22 chars | at word/document.xml:p0339
- PERSON | 2 token(s) [Capitalized/Capitalized], 24 letters, 0 digits, 25 chars | at word/document.xml:p1352
- PERSON | 2 token(s) [Capitalized/Capitalized], 24 letters, 0 digits, 25 chars | at word/document.xml:p1521
- PERSON | 3 token(s) [Capitalized/Capitalized/Capitalized], 14 letters, 0 digits, 17 chars | at word/document.xml:p1543
- PERSON | 3 token(s) [Capitalized/Capitalized/Capitalized], 17 letters, 0 digits, 19 chars | at word/document.xml:p1550
- PERSON | 3 token(s) [Capitalized/Capitalized/Capitalized], 15 letters, 0 digits, 17 chars | at word/document.xml:p1557
- PERSON | 2 token(s) [Capitalized/Capitalized], 9 letters, 0 digits, 10 chars | at word/document.xml:p1564
- PERSON | 3 token(s) [Capitalized/Capitalized/Capitalized], 18 letters, 0 digits, 20 chars | at word/document.xml:p1571
- PERSON | 2 token(s) [Capitalized/Capitalized], 24 letters, 0 digits, 25 chars | at word/document.xml:p2166
- PERSON | 2 token(s) [Capitalized/Capitalized], 24 letters, 0 digits, 25 chars | at word/document.xml:p2171
- PERSON | 3 token(s) [Capitalized/Capitalized/Capitalized], 14 letters, 0 digits, 16 chars | at word/document.xml:p4126
- PERSON | 2 token(s) [Capitalized/Capitalized], 9 letters, 0 digits, 10 chars | at word/document.xml:p4130
- ORG | 1 token(s) [Capitalized], 6 letters, 0 digits, 6 chars | at word/document.xml:p0557
- ORG | 2 token(s) [Capitalized/Capitalized], 16 letters, 0 digits, 17 chars | at word/document.xml:p1141
- ORG | 2 token(s) [Capitalized/Capitalized], 16 letters, 0 digits, 17 chars | at word/document.xml:p1141
- ORG | 2 token(s) [Capitalized/Capitalized], 16 letters, 0 digits, 17 chars | at word/document.xml:p1141
- ORG | 2 token(s) [Capitalized/Capitalized], 17 letters, 0 digits, 18 chars | at word/document.xml:p1845
- ORG | 2 token(s) [Capitalized/Capitalized], 14 letters, 0 digits, 15 chars | at word/document.xml:p1857
- ORG | 5 token(s) [CAPS/Capitalized/Capitalized/lower/Capitalized], 19 letters, 1 digits, 24 chars | at word/document.xml:p1894
- ORG | 2 token(s) [CAPS/Capitalized], 16 letters, 0 digits, 17 chars | at word/document.xml:p2929

## 7. Limitations

- Regex detectors can miss unusual separators, OCR errors, and entities split across formatting runs.
- The fallback name detector uses context and a small first-name heuristic; a full deployment should provide a domain-appropriate NER model.
- Organization names are treated as sensitive under the assignment policy because the required category is explicit; this can redact non-personal organizations.
- Address detection is deliberately conservative and can miss prose-only or multi-line addresses.
- DOB detection requires explicit birth context; ordinary filing, transaction, and financial dates remain unchanged.
- PDF-to-DOCX conversion preserves extracted text and page boundaries, not the original PDF's exact visual layout.
- The report describes the dataset named in the metadata. If that dataset is a synthetic demonstration fixture rather than the assignment's RHP, its metrics must not be presented as source-document performance.
