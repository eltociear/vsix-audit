# What we found scanning the most-downloaded Open VSX extensions

This is the research behind `vsix-audit`: a real scan of the top of the Open VSX registry (the one
Cursor, Windsurf, VSCodium, Gitpod and most AI editors install from), run with this exact
engine. Like [mcp-audit](https://github.com/eltociear/mcp-audit/blob/main/FINDINGS.md) and
[npm-audit](https://github.com/eltociear/npm-audit/blob/main/FINDINGS.md), it is calibrated so that
"clean" means clean before any number is reported.

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
