# AI Agent Security — Multi-Step Tool Attacks

An entry for Kaggle's [AI Agent Security - Multi-Step Tool Attacks](https://www.kaggle.com/competitions/ai-agent-security-multi-step-tool-attacks)
competition (OpenAI / Google / IEEE): an algorithmic red-teaming benchmark where a submitted
`attack.py` drives a tool-using AI agent, inside a deterministic offline sandbox, toward
reproducible security-predicate violations that a hosted evaluator independently replays and
scores.

**Result:** public score 91.40 (pre-harness-update); both locked-in Final Submissions scored
**0.000 private**, placing #3613 of ~4252 — the held-out guardrail inspects the `http.post`
payload directly, defeating the entire exfiltration-based attack family regardless of technique.
Full account, including a structurally different hedge we built, validated, and didn't select:
see the Working Note's
[Epilogue](docs/WORKING_NOTE.md#epilogue-the-private-leaderboard-reveal-2026-09-02).

## Documentation

- **[docs/WORKING_NOTE.md](docs/WORKING_NOTE.md)** — the full write-up: harness
  reverse-engineering, predicate reachability, the budget-optimal attack design
  (reasoning-collapse + wrap-up-collapse latency levers), the private-guardrail transfer
  methodology (a measured proxy matrix, not a guess), defensive lessons, and the post-reveal
  epilogue.
- **[STATUS.md](STATUS.md)** — current state: the two locked-in Final Submissions and a map of
  every file in this repo.

## Reproducing a result

- `src/` — every `attack_*.py` variant plus its `local_eval_*.py` Mode-A validator (real packaged
  guardrail and scorer via a stub agent; needs the unpacked competition SDK at `data/`, which each
  script locates automatically), and `proxy_guardrails.py` / `transfer_matrix.py` /
  `transfer_matrix_deputy.py`, the `G0`–`G7` private-guardrail proxy measurement (Working Note §6).
- `probes/` — the real-model (gpt-oss / Gemma) latency and fire-rate measurement harness.
- `tools/` — builds a submission notebook from a `src/attack_*.py` source and pushes it to Kaggle.

Full method and file-by-file breakdown: the Working Note's
[Reproducibility](docs/WORKING_NOTE.md#9-reproducibility) section.

## License

MIT — see [LICENSE](LICENSE).
