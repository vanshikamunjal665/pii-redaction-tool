# Input directory

`synthetic_rhp_fixture.docx` is a fabricated demonstration fixture, generated
locally by `tools/create_demo_fixture.py`. Every value in it is invented, and it
exists so the detection rules, the replacement mapping, the round-trip, and the
metric code can be regression-tested without touching a real document.

It is **not** a stand-in for the real RHP and its metrics are not evidence of
performance on a real document.

The real source document is **not stored in this repository** and is never
modified. It is read from its original location and the redacted copy is written
to `output/`. To reproduce the real-document results, point the pipeline at your
copy of the source:

```bash
python run.py --input path/to/original_rhp.docx --output output/real_rhp_redacted.docx --predictions evaluation/real_rhp_predictions.json --no-spacy
```

The ground truth for that document was annotated independently under
`docs/annotation_policy.md`; rebuild it with `tools/make_ground_truth_chunks.py`
and `tools/merge_ground_truth.py` if you are working against a different RHP.
