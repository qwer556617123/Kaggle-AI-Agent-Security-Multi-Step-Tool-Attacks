"""Build the attack_priv++ (sentinel-reconstruction) submission notebook: embeds the current
attack_priv.py (base64), cloning the submission_priv notebook structure/kernel id.

Usage:  python tools/build_priv_nb.py
Outputs submission_priv_plusplus/ next to the other submission dirs.
"""
from __future__ import annotations

import base64
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_NB = ROOT / "submission_priv" / "attack-submission.ipynb"
TEMPLATE_META = ROOT / "submission_priv" / "kernel-metadata.json"
ATTACK_SRC = ROOT / "attack_priv.py"


def build() -> Path:
    src = ATTACK_SRC.read_text(encoding="utf-8")
    compile(src, "attack.py", "exec")
    b64 = base64.b64encode(src.encode("utf-8")).decode("ascii")

    nb = json.loads(TEMPLATE_NB.read_text(encoding="utf-8"))
    nb["cells"][0]["source"] = [
        "# AI Agent Security - Attack (attack_priv++: sentinel-reconstruction, G7 marker-scan coverage)"
    ]
    loader = "".join(nb["cells"][1]["source"])
    loader = re.sub(r"ATTACK_B64='[^']+'", f"ATTACK_B64='{b64}'", loader)
    if f"ATTACK_B64='{b64}'" not in loader:
        raise RuntimeError("failed to substitute ATTACK_B64")
    nb["cells"][1]["source"] = [loader]

    out_dir = ROOT / "submission_priv_plusplus"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "attack-submission.ipynb").write_text(
        json.dumps(nb, ensure_ascii=False, indent=1), encoding="utf-8")
    meta = json.loads(TEMPLATE_META.read_text(encoding="utf-8"))
    (out_dir / "kernel-metadata.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8")

    nb2 = json.loads((out_dir / "attack-submission.ipynb").read_text(encoding="utf-8"))
    code = base64.b64decode(re.search(r"ATTACK_B64='([^']+)'", "".join(nb2["cells"][1]["source"])).group(1)).decode()
    assert "reconstruct_x" in code and "_OBF_MARKER" in code
    print(f"built {out_dir.name}: {len(code)} bytes, compiles, reconstruct_x present")
    return out_dir


if __name__ == "__main__":
    build()
