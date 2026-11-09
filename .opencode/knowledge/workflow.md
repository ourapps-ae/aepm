# Local workflow

Work on unborn local branch `work/ourpoker-proof`; local-only proof. No commits, pushes, remote changes, publishing, deployments or real signing credentials. Licence wording remains deferred.
Read-only references: `/Users/george/Projects/com/my/{mcinpoker,skull}`. Preserve existing source changes.
Use frozen McInPoker revision `19905b75dbea89fbfd424d67fe26c81aaed0e018` at `/var/folders/yk/8tzc9b_1713dlhdp5vzkgg100000gn/T/opencode/ourpoker-20261102-215016-source/mcinpoker`; never edit the snapshot.
Request changes outside your owned paths from their producer. Implementation remains uncommitted; partial alignment does not authorize advancing the completion gate.

From this checkout: `python3 -m aepm --help`; checks: `python3 -m unittest discover -s tests`. Package review check: `AEPM_REVIEW_SOURCE=/absolute/package python3 -m unittest tests.test_packaged_review -v` for a dependency-free real package. These commands are documented, not rerun by this metadata update.
Existing usage: `python3 -m aepm resolve DEFINITION --catalogue STORE/catalogue.json --out LOCK`, `python3 -m aepm install DEFINITION --lock LOCK --store STORE --policy POLICY --target APP`, `python3 -m aepm verify APP --policy POLICY --trusted`, `python3 -m aepm export APP --out DIAGRAMS`. `README.md` records review/signing, update approval and recovery commands; use separate new proof outputs only when authorized.
Preserve accepted proof targets. Update snapshots reject symbolic links, including installed dependency links; a fresh proposal does not bypass this. Install dependencies and play only in a separate copy, following `/Users/george/Projects/com/my/OurPoker/proof/README.md`.
