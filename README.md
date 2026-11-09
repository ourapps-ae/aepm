# aepm

Local exact-version application assembly using Python 3.12, Node.js Ed25519 signatures and Graphviz diagrams.

Run `python3 -m aepm --help` from this directory. For other working directories, set `PYTHONPATH` to this checkout.

```sh
python3 -m aepm pack SOURCE --store STORE
python3 -m aepm inspect DIGEST --store STORE
python3 -m aepm resolve DEFINITION --catalogue STORE/catalogue.json --out LOCK
python3 -m aepm sign STATEMENT --role release --key KEY --out SIG
python3 -m aepm review DIGEST --store STORE --policy POLICY --trusted
python3 -m aepm install DEFINITION --lock LOCK --store STORE --policy POLICY --target APP
python3 -m aepm verify APP --policy POLICY --trusted
python3 -m aepm export APP --out DIAGRAMS
python3 -m aepm propose-update APP DEFINITION --store STORE --policy POLICY --trusted --out PROPOSAL
python3 -m aepm approve PROPOSAL --key KEY --policy POLICY --out APPROVAL
python3 -m aepm apply APP PROPOSAL --approval APPROVAL --policy POLICY
python3 -m aepm recover APP
```

Installation runs no package code. Release and guardian signatures must exist before installation. Review runs before guardian signing. A guardian signs the immutable review report digest, dependency digests and complete declared scope set. Reports preserve required-local, platform and deployed partitions.

Verification requires explicit `--trusted` and every archive digest in the external policy's `trustedExecution`. `review`, `verify` and `propose-update` accept `--allow-network` for declared network preparation. Each suite receives a fresh writable copy, private home and cache paths and a credential-free environment. Package suites use their retained package root; application suites use the full generated tree. Installed tools must match their declared version or version prefix. Preparation logs are separate entries in each suite's content-addressed log index. This is trusted execution, not an operating-system sandbox: trusted code can access the host filesystem and network. Deployed checks remain blocked without authorization.

Only `external:<slug>` execution prerequisites are accepted. Unknown forms reject manifest validation. A check that lists prerequisites but has no `execution` declaration is blocked. A check with an `execution` declaration (report format 2) can use an externally supplied, owner-authorized context; actual validators check its tools, resources, destinations and permitted operations. Ordinary local coverage uses an empty requirements list. There is no passed-prerequisite override.

A `requires` entry in a component or recipe manifest has fields `id type version path` and an optional boolean `optional` (default false; a non-boolean is rejected; `provides` entries refuse it). Install and design validation demand a connection only for a requirement that is not optional; a connected optional requirement is still checked for type and version. For `optional: true` the package's visual definition must declare the input port with `required: false`, and the diagram draws it as optional.

An artefact entry may carry `component: "ourapps-ae/<name>"` (a package name other than the package itself). The artefact is installed, staged for updates, recorded in the assembly and shown in the diagram only when the design includes that component (the recipe or an instance with that package name). Ownership and collision checks apply only to installed artefacts; a missing optional component is never an error. Entries without the field always install.

A definition (format 1) may carry optional `answers` and `selections` objects of canonical JSON values (each at most 65536 canonical bytes). They are saved unchanged in `.aepm/definition.json` and covered by the definition digest and the lock's `definitionDigest`; aepm does not interpret them.

## Supplied execution contexts

```sh
python3 -m aepm execution-request --review DIGEST --store STORE --context CONTEXT --policy POLICY --execution-state STATE --expires-at UNIX_SECONDS --out REQUEST
python3 -m aepm authorize-execution REQUEST --key OWNER_KEY --policy POLICY --out AUTHORIZATION
python3 -m aepm review DIGEST --store STORE --policy POLICY --trusted --context CONTEXT --authorization AUTHORIZATION --execution-state STATE
```

For application verification, request authority with `--app APP` instead of `--review DIGEST --store STORE`, then pass the same context/authorization/state arguments to `verify`. Updates use an independently installed preview of the exact proposed assembly to derive authorization, then pass those arguments to `propose-update`. Report digests bind the evidence through ordinary owner approval and recovery.

Repeat `execution-request --suite DIGEST:ID` to select exact verified checks, such as build/unit checks without device creation. Invalid, duplicate, local-only or mode-incompatible selections reject before request/registry creation. Explicit selections are retained in `REQUEST.evidence/selection.json` and rederived when signing. Without `--suite`, all mode-compatible checks are selected. Every declaration still appears in the report; unselected external checks remain blocked for absent authority. The owner signs the currently revalidated request, not a historical command-line intent claim.

Contexts use mode `local`, `simulation` or `live`. Simulation identifies `fixture` or `local-provider`; it cannot pass native platform or deployed partitions. Live execution also requires `--allow-live`, explicit signed operations/origins and separate human authorization. No live access is authorized by the local examples. `--allow-network` remains independently required for declared network preparation.

Each authorization is single-use, bounded to exact package/suite/assembly/context/policy digests and a durable external execution registry. A consumed, interrupted or expired authorization requires a new request. Request evidence contains verified archives and public documents; private secret material stays outside archives, stores and application roots. Optional `--secrets FILE` resolves only the authorized symbolic references and credential versions. Provider/secret-bearing output is suppressed; retained results contain only closed structured assertions and fixed diagnostic codes.

Format-2 validation, preparation and checks share the original suite deadline. A declared maximumSeconds can only shorten it. Every probe receives the positive remaining suite/authorization time; input and result hashing are checked again before success. Cleanup has its separate bound and cannot authorize more test work.

Format-2 evidence lives under `contexts/`, `authorizations/`, `execution-evidence/` and `reports/`, with digest filenames. Historical validation retains originating Windows or Unix path syntax without requiring the original host; adoption rechecks the local registry, expiry and resources. Complete blocked/failed partitions remain in the same signed report.

Resource records bind bytes and modes. Read-only Apple/Java inventories record internal links without expanding aliases; Apple may explicitly bind an enclosing `Contents` inventory while keeping `Developer` as its tool path. Copied Android resources reject escaping/cyclic links and materialize ordinary files. Validated input copies remain unchanged; private working Android development-kit/cache copies use fixed protocol paths and are removed by the parent after execution. Resource bounds are 8192 executable entries, 1,000,000 records, 8 GiB/file and 64 GiB total, with a 1 MiB descriptor limit.

`aepm.environment.describe_resource(identifier, path, inventory_root=None, executables=None)` constructs resource descriptors with the same inventory used during execution. Unix hosts derive executable paths; Windows requires an explicit executable list. It hashes file contents and can be expensive for complete toolchains. Resource validation never silently drops files or escapes the signed boundary.

Windows verification uses suspended-process Job Object containment and protected private files; native execution must be verified on an actual Windows host. Windows packing and transactional update commands are unsupported. The actual-host regression in `tests/windows/` is explicitly skipped on other hosts; simulated branches do not establish native success.

On supported 64-bit macOS and Linux with the GNU C library, the runner observes child exit without reaping, finishes owned-group signals and checks, then reaps once. Default child-signal handling and exclusive ownership of child waits are required. Cooperating commands must remain in that group; deliberate session escape remains an expected failing boundary test, not a containment guarantee. Browser checks must use the shared non-detached launcher with executable/profile paths inside runner-issued `AEPM_PRIVATE_ROOT`. Failed cleanup retains private files for inspection and records their location in the step index; secret-material removal is attempted independently.

`python3 -m aepm.test_identities /absolute/temporary/identities` generates three disposable private keys and an external policy. Add reviewed archive digests to `trustedExecution` before execution. Keep this directory outside package trees and stores. No identity is a production guardian.

Configuration uses fixed grammars. Secret values are symbolic references and never enter templates. Strings must occupy quoted source/configuration positions; shell templates accept only environment names, identifiers and slugs. Component outputs belong beneath `components/<name>/`; recipe outputs own other generated source. Tests, contracts and fixtures remain under `.aepm/packages/<digest>/`. Diagrams load bundled definitions and project integer settings to numeric diagram values.

Stop application processes before applying updates. A sibling `.<name>.aepm-transaction/` directory holds the stage, report, proposal, owner approval, lock and durable recovery journal. Owner approval binds the complete original and staged trees, including unmanaged files and metadata. Any observed change invalidates approval. Recovery finds that sibling even when the application directory is absent. Committed backups remain for explicit later cleanup; remove a completed transaction directory only after retaining any required evidence. Cooperating writers use an exclusive lock; uncooperative concurrent edits are unsupported.

Run `python3 -m unittest discover -s tests` for local checks. The diagram renderer is vendored; consumers need no sibling checkout.

For a dependency-free real package, run `AEPM_REVIEW_SOURCE=/absolute/package python3 -m unittest tests.test_packaged_review -v`. This packs the actual allowlist, creates disposable external identities, performs release-verified review and permits guardian acceptance only after required-local suites pass. Optional `AEPM_REVIEW_EVIDENCE=/absolute/report.json` retains the complete report.
