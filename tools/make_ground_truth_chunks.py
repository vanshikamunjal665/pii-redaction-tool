"""Split the source RHP into review files for independent ground-truth annotation."""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))

from src.document_processor import extract_docx_units

SOURCE = Path(r"C:\Users\Vanshika Munjal\Desktop\Red Herring Prospectus.docx")
OUT_DIR = Path(r"C:\Users\Vanshika Munjal\AppData\Local\Temp\opencode\gt")
CHUNK_CHARS = 24000


def main() -> int:
    units = [u for u in extract_docx_units(SOURCE) if u.text.strip()]
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    chunks: list[list] = [[]]
    size = 0
    for unit in units:
        chunks[-1].append(unit)
        size += len(unit.text) + 40
        if size >= CHUNK_CHARS:
            chunks.append([])
            size = 0
    if not chunks[-1]:
        chunks.pop()

    manifest = []
    for index, chunk in enumerate(chunks, start=1):
        path = OUT_DIR / f"units_{index:02d}.txt"
        with path.open("w", encoding="utf-8", newline="\n") as handle:
            handle.write(f"# RHP ground-truth review file {index} of {len(chunks)}\n")
            handle.write(f"# Source: {SOURCE}\n")
            handle.write(f"# Units: {len(chunk)}\n")
            handle.write(
                "# Read ANNOTATION_POLICY.md first. Emit only JSON annotation "
                "lines to gt_"
                f"{index:02d}.jsonl\n\n"
            )
            for unit in chunk:
                # Tabs must stay visible so a tab-separated name can be copied
                # character-for-character.
                handle.write(f"### {unit.unit_id}\n{unit.text}\n\n")
        manifest.append(
            {
                "file": str(path),
                "output": str(OUT_DIR / f"gt_{index:02d}.jsonl"),
                "units": len(chunk),
                "chars": sum(len(u.text) for u in chunk),
                "first_unit": chunk[0].unit_id,
                "last_unit": chunk[-1].unit_id,
            }
        )

    total = sum(item["chars"] for item in manifest)
    print(f"units={len(units)} chars={total} files={len(manifest)}")
    for item in manifest:
        print(
            f"  {Path(item['file']).name} units={item['units']} "
            f"chars={item['chars']} {item['first_unit']}..{item['last_unit']}"
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
