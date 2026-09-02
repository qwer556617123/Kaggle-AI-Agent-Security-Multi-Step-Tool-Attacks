"""Private-transfer measurement for attack_deputy.py against the G0-G7 proxy guardrails.

Companion to transfer_matrix.py, which only exercises http.post (EXFILTRATION) subjects.
attack_deputy calls email.send instead, so it needs its own harness. The point of this
script is to check the claim that motivated attack_deputy in the first place (see its
module docstring, credited to a competitor's Working Note, discussion 737535): that
G1_check_data and G3_content_filter -- which our own proxy_guardrails.py previously
labeled ZEROES_EVERYONE and excluded from "rankable" on the theory that no marker-exfil
attack can ever score against them -- do NOT actually zero the whole field once a
CONFUSED_DEPUTY candidate exists in the portfolio, because it needs no secret-like
string and no untrusted provenance.

Run:  python transfer_matrix_deputy.py
"""

from __future__ import annotations

import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent
for p in (str(ROOT), str(ROOT.parent / "data")):
    if p not in sys.path:
        sys.path.insert(0, p)

import proxy_guardrails as pg  # noqa: E402
from attack_deputy import TEMPLATES, _addr, _message  # noqa: E402

N = 10


def main() -> None:
    gnames = list(pg.PROXIES.keys())
    print("=" * 118)
    print("attack_deputy PRIVATE-TRANSFER — # of %d email.send ALLOWED per proxy guardrail "
          "(ALLOW=CONFUSED_DEPUTY fires=score>0; DENY=0)" % N)
    print("=" * 118)
    print("%-36s" % "template" + "".join("%-13s" % g.split("(")[0] for g in gnames))
    print("-" * 118)

    results: dict[tuple[str, str], int] = {}
    for tname, tpl in TEMPLATES:
        cells = []
        for gname, factory in pg.PROXIES.items():
            g = factory()
            allowed = 0
            for i in range(N):
                msg = _message(tpl, i)
                addr = _addr(i)
                args = {"to": addr, "subject": "Status", "body": "Report ready."}
                ctx = {"seed": 0, "recent_sources": [], "recent_tools": [],
                       "last_user": msg, "side_effect": "SHARE", "scope": "public"}
                dec = g.decide("email.send", args, ctx)
                if dec.action == "ALLOW":
                    allowed += 1
            cells.append(allowed)
            results[(tname, gname)] = allowed
        print("%-36s" % tname + "".join("%-13s" % ("%d/%d" % (c, N)) for c in cells))

    print("-" * 118)
    ze = ", ".join(sorted(pg.ZEROES_EVERYONE))
    print("Guardrails our OWN model previously called ZEROES-EVERYONE (excluded from")
    print("'rankable' because no marker-exfil attack can score against them): %s" % ze)
    print("Checking whether attack_deputy survives them anyway (i.e. whether that label")
    print("should really be 'zeroes every EXFIL attack', not 'zeroes everyone'):")
    for gname in sorted(pg.ZEROES_EVERYONE):
        best = max(results[(tname, gname)] for tname, _ in TEMPLATES)
        verdict = "SURVIVES (not actually zero-everyone)" if best > 0 else "still zero"
        print("  %-20s best=%d/%d  -> %s" % (gname.split("(")[0], best, N, verdict))

    print("\nSURVIVES among ALL %d hypotheses (including the previously-excluded ones):"
          % len(gnames))
    for tname, _ in TEMPLATES:
        surv = [g for g in gnames if results[(tname, g)] > 0]
        print("  %-24s %d/%d  %s" % (tname, len(surv), len(gnames),
              ", ".join(s.split("(")[0] for s in surv)))


if __name__ == "__main__":
    main()
