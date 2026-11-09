# aepm ownership

Repository: https://github.com/ourapps-ae/aepm.git
Producer 1 owns `aepm/{model.py,bundle.py,trust.py,crypto.mjs}` and `tests/core/**`. Producer 2 owns all remaining files except the three bootstrap instruction files.
Frozen contract: `/Users/george/Projects/com/my/.omo/pipeline/20261102-215016-ourpoker-build/interfaces.md`; ownership and acceptance: adjacent `plan.md`.
Read `workflow.md` before editing or running checks.

Current code: `aepm/{model,bundle,trust,application,verification,update,export}.py`, command entrypoint `aepm/__main__.py`, bundled renderer `aepm/diagram/`, and `tests/`. See `README.md` for commands and explicit trusted execution.
Local generation, approval and recovery are demonstrated; overall alignment remains partial. `aepm/verification.py` blocks nonempty prerequisites and deployed checks unconditionally; no validated supplied-environment path exists.
Status and evidence: `/Users/george/Projects/com/my/.opencode/knowledge/00-index.md`, section OurPoker local implementation.
