"""Build fill-rate-lottery submission notebooks from attack_term.py.

Each notebook embeds attack_term.py (base64) with REPLAY_SAFE swapped to a target
value, cloning the proven submission_term_099 notebook structure. The lottery pushes
the fill rate above the reliable 0.99 to search for a fast-GPU draw that completes at
very high fill (=> a few more findings => a higher public draw). Best-of protects the
banked 91.40, so higher fill (more void-prone) is downside-free.

Usage:  python scratchpad/build_lottery_nbs.py
Outputs submission_lottery_<rs>/ dirs next to the other submission dirs.
"""
from __future__ import annotations

import base64
import copy
import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TEMPLATE_NB = ROOT / "submission_term_099" / "attack-submission.ipynb"
TEMPLATE_META = ROOT / "submission_term_099" / "kernel-metadata.json"
ATTACK_SRC = ROOT / "attack_term.py"

# REPLAY_SAFE ladder: 0.99 reliable-high, 0.995/0.998 progressively void-prone tail tickets.
FILL_RATES = (0.99, 0.995, 0.998)


def _swap_replay_safe(src: str, value: float) -> str:
    new, n = re.subn(
        r"REPLAY_SAFE:\s*Final\[float\]\s*=\s*[0-9.]+",
        f"REPLAY_SAFE: Final[float] = {value}",
        src,
    )
    if n != 1:
        raise RuntimeError(f"expected exactly 1 REPLAY_SAFE assignment, found {n}")
    return new


def _tag(value: float) -> str:
    # 0.99 -> "099", 0.995 -> "0995", 0.998 -> "0998"
    return str(value).replace(".", "")


def build_one(value: float) -> Path:
    attack_src = _swap_replay_safe(ATTACK_SRC.read_text(encoding="utf-8"), value)
    b64 = base64.b64encode(attack_src.encode("utf-8")).decode("ascii")

    nb = json.loads(TEMPLATE_NB.read_text(encoding="utf-8"))
    # cell 0 = markdown title, cell 1 = loader with ATTACK_B64='...'
    nb["cells"][0]["source"] = [
        f"# AI Agent Security - Attack (attack_term wrap-up-collapse terminal, "
        f"REPLAY_SAFE {value})"
    ]
    loader = "".join(nb["cells"][1]["source"])
    loader = re.sub(r"ATTACK_B64='[^']+'", f"ATTACK_B64='{b64}'", loader)
    if f"ATTACK_B64='{b64}'" not in loader:
        raise RuntimeError("failed to substitute ATTACK_B64")
    nb["cells"][1]["source"] = [loader]

    out_dir = ROOT / f"submission_lottery_{_tag(value)}"
    out_dir.mkdir(exist_ok=True)
    (out_dir / "attack-submission.ipynb").write_text(
        json.dumps(nb, ensure_ascii=False, indent=1), encoding="utf-8"
    )
    meta = json.loads(TEMPLATE_META.read_text(encoding="utf-8"))  # same kernel id
    (out_dir / "kernel-metadata.json").write_text(
        json.dumps(meta, ensure_ascii=False, indent=2), encoding="utf-8"
    )
    return out_dir


def _verify(out_dir: Path, value: float) -> None:
    nb = json.loads((out_dir / "attack-submission.ipynb").read_text(encoding="utf-8"))
    loader = "".join(nb["cells"][1]["source"])
    b64 = re.search(r"ATTACK_B64='([^']+)'", loader).group(1)
    code = base64.b64decode(b64).decode("utf-8")
    rs = re.search(r"REPLAY_SAFE:\s*Final\[float\]\s*=\s*([0-9.]+)", code).group(1)
    compile(code, "attack.py", "exec")  # syntax check
    assert float(rs) == value, (rs, value)
    print(f"  verified {out_dir.name}: REPLAY_SAFE={rs}, attack.py compiles, {len(code)} bytes")


if __name__ == "__main__":
    for v in FILL_RATES:
        d = build_one(v)
        _verify(d, v)
    print("done")
