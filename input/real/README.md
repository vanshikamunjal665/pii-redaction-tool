# Real source documents (gitignored)

Put the real RHP here as `input/real/rhp.docx` if you want the reproduction
commands to work with a relative path instead of an absolute one.

**This folder is gitignored.** Every file in it is ignored by default; only this
README is tracked. The source document contains real personal information, so it
must not be committed, and its presence in the working tree is not a reason to
commit it.

## Two consequences to be aware of

1. **Do not zip, email, or share the project folder as a whole.** A copy of
   `input/real/` travels with it, and `.gitignore` does not apply to an archive.
   Share a clean checkout instead.
2. **The source is never modified.** The pipeline reads it and writes the
   redacted copy to `output/`. The input digest recorded in
   `evaluation/real_rhp_verification.json` is the way to confirm the source is
   unchanged.

## Running against it

```bash
python run.py --input input/real/rhp.docx --output output/real_rhp_redacted.docx --predictions evaluation/real_rhp_predictions.json --no-spacy
```

The annotation and prediction JSON files that this produces are also gitignored,
because they reproduce source values by design. The redacted DOCX and the
value-free evaluation report are safe to track.
