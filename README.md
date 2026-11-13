# aepm

Local exact-version application assembly using Python 3.12, Node.js Ed25519 signatures and Graphviz diagrams.

Run `python3 -m aepm --help` from this directory. For other working directories, set `PYTHONPATH` to this checkout.

```sh
python3 -m aepm pack SOURCE --store STORE
python3 -m aepm inspect DIGEST --store STORE
python3 -m aepm bom DIGEST --store STORE --out NAME-VERSION.cdx.json
python3 -m aepm fetch NAME@VERSION... --store STORE [--from https://ourapps.app] [--with-dependencies]
python3 -m aepm questions RECIPE@VERSION --store STORE
python3 -m aepm design RECIPE@VERSION --store STORE [--answers ANSWERS] [--substitute SLOT=NAME@VERSION]... --out DEFINITION
python3 -m aepm alternatives RECIPE@VERSION SLOT --store STORE [--from https://ourapps.app]
python3 -m aepm resolve DEFINITION --catalogue STORE/catalogue.json --out LOCK
python3 -m aepm sign STATEMENT --role release --key KEY --out ENVELOPE
python3 -m aepm review DIGEST --store STORE --policy POLICY --trusted
python3 -m aepm install DEFINITION --lock LOCK --store STORE --policy POLICY --target APP
python3 -m aepm verify APP --policy POLICY --trusted
python3 -m aepm export APP --out DIAGRAMS
python3 -m aepm propose-update APP DEFINITION --store STORE --policy POLICY --trusted --out PROPOSAL
python3 -m aepm approve PROPOSAL --key KEY --policy POLICY --out APPROVAL
python3 -m aepm apply APP PROPOSAL --approval APPROVAL --policy POLICY
python3 -m aepm recover APP
```

Every digest and signature covers RFC 8785 canonical JSON (`aepm.model.canonical`); integers outside plus or minus 2^53-1 are refused. `identity.licence` is an SPDX licence expression.

`fetch` reads each package's catalogue entry (`/api/components/<name>/<version>`, else `/api/recipes/...`), downloads the archive through its `/bundle` link, refuses it unless its SHA-256 equals the catalogue digest and the archive validates, and adds it to the store as `pack` does. From the release named by the entry's `source` it also downloads, when present, `<name>-<version>.release.dsse.json` and `.guardian.dsse.json` into `statements/<digest>/` and the canonical review report `<name>-<version>.review.json` into `reports/<digest>.json`. `--with-dependencies` follows declared dependencies and, for a recipe, every component its `recipe.json` names at the pinned version.

Each entry of a recipe's `recipe.json` `components` is a slot: `{id, class: {provides, requires, configuration}, preferred: {name, version}, configuration, includedWhen}`; a job names its `slot` and candidates `{component, profile}` (a candidate other than the preferred component also carries `version`). A component fits a slot's class when (1) it provides every `class.provides` type and version with an interface document byte-identical to the preferred component's; (2) each of its requirements that is not `optional` has its type and version in `class.requires`; (3) each property of `class.configuration` is one of its settings with the same type and, for a string, the grammar as the anchored `pattern`, and each required setting it has without a default is in `class.configuration.required`; (4) it installs every entry module the class's interface documents declare in `x-ourapps-modules` (a TypeScript entry as an artefact destination, a native folder with an artefact beneath it). `aepm.recipe.fit` is that rule; `design` applies it to every filled slot and job candidate (`unfit:<slot>:<reason>`). `--substitute SLOT=NAME@VERSION` puts a stored component in the slot after checking it fits and records `selections[SLOT] = {component, version, reason: "substituted"}` (an unknown slot is `unknown-slot:<slot>`); a job's selection records `{component, version, profile, reason}`. `alternatives` asks the catalogue `/api/components?provides=<type>` for every type the slot's class provides, fetches each component's latest archive into the store as `fetch` does and prints `[{name, version, fits, reasons}]`.

`questions` prints a recipe's questions (id, ask, askAgent, type, options or min/max, default, askWhen). `design` applies the recipe evaluation rules 1 to 25 of the component standard (`aepm.recipe.evaluate`, CEL conditions included) to the recipe's `recipe.json` and the components' manifests and `suitability.json`, all read from the store archives, and writes the application definition. Unanswered questions take their defaults. When the answers do not give a design it prints `{"ok": false, "errors": [{code, path}]}` and exits 1, writing nothing. `aepm.recipe.World.from_directories(recipe, components)` evaluates source trees instead.

Installation runs no package code. Release and guardian attestations must exist before installation. Review runs before guardian signing. Reports preserve required-local, platform and deployed partitions.

`bom` writes a CycloneDX 1.6 JSON bill of materials for a stored archive: the package as `metadata.component` (type `library`, or `application` for a recipe) with purl `pkg:github/ourapps-ae/<repo>@v<version>` (`<repo>` is the package name, with `-recipe` added for recipes), its SPDX licence expression and the archive's SHA-256; one `file` component with its SHA-256 per packaged file; and the declared package dependencies.

Every signature is a DSSE envelope (`payloadType` `application/vnd.in-toto+json`, Ed25519, `keyid` the SHA-256 of the raw 32-byte public key) over an in-toto Statement v1 whose single subject is `{name, digest: {sha256}}`. The policy pins `publicKey` entries per role; the three role key sets must be disjoint, and each role signs only its own predicates:

| Role | Predicate | Subject | What it binds |
|---|---|---|---|
| release | `https://in-toto.io/attestation/release/v0.1` | `<name>-<version>.tar`, the archive digest; annotation `sourceTreeDigest` | `purl` and `releaseId` (the package name) |
| guardian | SLSA Verification Summary `https://slsa.dev/verification_summary/v1` | the archive | `verifier.id`, `resourceUri` (the purl), `policy.uri`, `verificationResult` `PASSED`, the review report digest in `inputAttestations`, one `verifiedLevels` entry per reviewed scope (`AEPM_REQUIRED_LOCAL`, `AEPM_PLATFORM`, `AEPM_DEPLOYED`), the dependency count in `dependencyLevels.AEPM_RELEASED` |
| owner | `https://ourapps.app/attestation/update-approval/v1` | `proposal.json`, the proposal digest | application, lock, configuration, design, assembly, report, snapshot and stage digests |
| owner | `https://ourapps.app/attestation/execution-authorization/v1` | `assembly`, the assembly digest | run, context, policy, lock and suite-set digests, execution state, granted suites, validity window |

A store keeps `statements/<digest>/release.dsse.json` and `guardian.dsse.json`; `sign` takes an in-toto Statement and writes its envelope. `aepm.trust.publish_release` and `publish_review` write both from an archive and a review report. Verification accepts standard or URL-safe base64, requires the canonical (RFC 8785) payload and envelope, a signature from a key pinned for the role whose `keyid` names that key, and exactly the expected predicate; the guardian's dependency count, scope levels and report digest must match the archive's own review binding, and the report binds the exact dependency digests. `approve` writes one envelope (`APPROVAL`), as does `authorize-execution` (`AUTHORIZATION`).

Verification requires explicit `--trusted` and every archive digest in the external policy's `trustedExecution`. `review`, `verify` and `propose-update` accept `--allow-network` for declared network preparation. Each suite receives a fresh writable copy, private home and cache paths and a credential-free environment. Package suites use their retained package root; application suites use the full generated tree. A suite's `tools` pins each tool to a version of one to three integers; components pin `MAJOR.MINOR` (`"python3": "3.12"`, `"node": "26.5"`) or `MAJOR` (`"xcrun": "72"`). Each declared tool is the executable its name finds on the user's PATH; a version-manager shim (pyenv, rbenv, nodenv, goenv, jenv, asdf, mise) is replaced by the executable the manager's `which` selects, so the suite runs the real interpreter, not the shim. The installed tool matches when the first version in its `--version` (or `-version`) output starts with the pin's components; otherwise the suite is blocked with `tool-version-mismatch`. A `prepare` step that declares `network: true` (dependency installation such as `npm ci`) runs only with `--allow-network`; without it the suite is blocked with `preparation-network-not-authorized`. Preparation logs are separate entries in each suite's content-addressed log index. This is trusted execution, not an operating-system sandbox: trusted code can access the host filesystem and network. Deployed checks remain blocked without authorization.

Only `external:<slug>` execution prerequisites are accepted. Unknown forms reject manifest validation. A check that lists prerequisites but has no `execution` declaration is blocked. A check with an `execution` declaration (report format 2) can use an externally supplied, owner-authorized context; actual validators check its tools, resources, destinations and permitted operations. Ordinary local coverage uses an empty requirements list. There is no passed-prerequisite override.

A `requires` entry in a component or recipe manifest has fields `id type version path` and an optional boolean `optional` (default false; a non-boolean is rejected; `provides` entries refuse it). Install and design validation demand a connection only for a requirement that is not optional; a connected optional requirement is still checked for type and version. For `optional: true` the package's visual definition must declare the input port with `required: false`, and the diagram draws it as optional.

A component installs into the slot the design gives it: an artefact destination must start with `components/<package short name>/`, and aepm writes it at `components/<slot id>/` (the design's instance id), so any component filling the slot lands in the same place; the assembly record, diagram and verification use those paths. A recipe's own artefacts stay outside `components/`. An artefact may carry `component` or `withoutComponent` (not both), naming a slot id of the design or a list of two or more different slot ids. A `component` artefact is installed, staged for updates, recorded and drawn only when every named slot is filled; a `withoutComponent` artefact only when they are not all filled, for example a stand-in module for an optional component. Two artefacts share a destination only when one carries `component: X` and the other `withoutComponent: X` (the same slot or set of slots); any other repeated destination is refused. Ownership and collision checks apply only to installed artefacts. Entries without either field always install.

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
