# AI Agent Security — Multi-Step Tool Attacks

An entry for Kaggle's [AI Agent Security - Multi-Step Tool Attacks](https://www.kaggle.com/competitions/ai-agent-security-multi-step-tool-attacks)
competition (OpenAI / Google / IEEE): an algorithmic red-teaming benchmark where a submitted
`attack.py` drives a tool-using AI agent, inside a deterministic offline sandbox, toward
reproducible security-predicate violations that a hosted evaluator independently replays and
scores.

- **[docs/WORKING_NOTE.md](docs/WORKING_NOTE.md)** — the full write-up: how the evaluation
  harness works, which of the four scored predicates are reachable and why, the budget-optimal
  attack design (reasoning-collapse + wrap-up-collapse latency levers), the private-guardrail
  transfer methodology (a measured proxy matrix, not a guess), and defensive lessons for anyone
  building or auditing a similar guardrail.
- **[STATUS.md](STATUS.md)** — current results, the two locked-in Final Submissions, and a map
  of every file in this repo.

## Reproducing a result

Each `local_eval_*.py` script Mode-A-validates the matching `attack_*.py` against the real
packaged guardrail and scorer with a fast stub agent (needs `PYTHONPATH` pointed at the unpacked
competition SDK). `transfer_matrix.py` / `transfer_matrix_deputy.py` run the private-guardrail
proxy measurement described in the Working Note. `probes/` holds the real-model (gpt-oss /
Gemma) latency and fire-rate measurement harness referenced throughout. See the Working Note's
Reproducibility section for the full method and file-by-file breakdown.

## License

MIT — see [LICENSE](LICENSE).
