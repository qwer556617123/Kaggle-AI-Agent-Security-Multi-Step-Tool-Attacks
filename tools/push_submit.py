"""Push a submission dir to the attack kernel, wait for the rerun to COMPLETE, then
create a code submission for that exact kernel version.

Pushing a kernel version is free; only competition_submit_code consumes a daily slot.

Usage:  python scratchpad/push_submit.py <submission_dir> "<message>"
Prints the new kernel version and the resulting submission ref.
"""
from __future__ import annotations

import sys
import time

from kaggle import KaggleApi

KERNEL = "qwer556617123/ai-agent-security-attack"
COMP = "ai-agent-security-multi-step-tool-attacks"


def main() -> None:
    folder, message = sys.argv[1], sys.argv[2]
    api = KaggleApi()
    api.authenticate()

    print(f"[push] {folder}")
    resp = api.kernels_push(folder)
    # find the version number on the response
    ver = None
    for attr in ("versionNumber", "version_number"):
        if getattr(resp, attr, None) is not None:
            ver = int(getattr(resp, attr))
            break
    url = getattr(resp, "url", getattr(resp, "ref", "?"))
    err = getattr(resp, "error", None) or getattr(resp, "invalidTags", None)
    print(f"[push] version={ver} url={url} error={err}")
    if ver is None:
        print("[push] could not read version number; full resp:", resp.to_json()
              if hasattr(resp, "to_json") else resp)
        sys.exit(2)

    # poll until the kernel rerun completes
    deadline = time.time() + 30 * 60
    last = None
    while time.time() < deadline:
        st = api.kernels_status(KERNEL)
        s = str(getattr(st, "status", "?"))
        if s != last:
            print(f"[wait] status={s}")
            last = s
        if "COMPLETE" in s:
            break
        if "ERROR" in s or "FAIL" in s or "CANCEL" in s:
            print(f"[wait] kernel failed: {getattr(st,'failureMessage','')}")
            sys.exit(3)
        time.sleep(20)
    else:
        print("[wait] timed out waiting for COMPLETE")
        sys.exit(4)

    print(f"[submit] version={ver} :: {message}")
    sub = api.competition_submit_code(
        file_name="submission.csv",
        message=message,
        competition=COMP,
        kernel=KERNEL,
        kernel_version=ver,
    )
    ref = getattr(sub, "ref", None)
    print(f"[submit] OK ref={ref} resp={sub.to_json() if hasattr(sub,'to_json') else sub}")


if __name__ == "__main__":
    main()
