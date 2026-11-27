# vsix-audit

**Scan VS Code / Open VSX extensions for *malicious* patterns before you install them.** A VS Code
extension is unsandboxed Node.js: the moment it activates it runs with your user's rights, can read
`~/.ssh`, every token in your environment and the editor's own SecretStorage, and can spawn
processes. Cursor, Windsurf, VSCodium and most AI editors install from Open VSX, where review is
light. This scans the `.vsix` for what the code *does*. Zero dependencies, one file, MIT.

```bash
python vsix_audit.py --openvsx publisher.name          # download from open-vsx.org and scan
python vsix_audit.py --marketplace publisher.name@1.2.3 # download from the VS Marketplace and scan
python vsix_audit.py --installed                        # scan ~/.vscode, ~/.cursor, ~/.windsurf ... extensions
python vsix_audit.py some-extension.vsix ./unpacked-dir
# 🔴 tests/fixtures/mal-glassworm  [CRITICAL]  score=50  (2 findings, 1 info)
#     CRITICAL Invisible-Unicode Payload  extension.js:2
#              U+FE03 x57
#     CRITICAL Obfuscated Payload  extension.js:4
#              exports.activate = () => { eval(atob(Buffer.from(d(s)).toString('base64'))); };
```

**The extension is never installed and none of its code runs.** The `.vsix` (a zip) is read as
text. Exit code `2` if anything is HIGH/CRITICAL, so it drops into CI or a pre-install hook.

## Why this exists

The 2025 GlassWorm campaign put self-spreading malware into Open VSX and the VS Code Marketplace.
Its loader was encoded as **invisible Unicode variation selectors** on lines that look empty in
every editor and in code review, its C2 address was read from a **Solana transaction memo** (with
a **Google Calendar event** as backup), and it stole GitHub/npm/Open VSX tokens and wallet data to
republish itself. None of that is a CVE; no `npm audit`-style advisory lookup can see it.
Marketplace malware since has followed the same shapes: steal tokens and SSH keys on activation,
dump `process.env` to a webhook, open a reverse shell, pipe a remote script into `sh`.

## What it flags

| Pattern | Severity |
| --- | --- |
| Invisible-Unicode payload (long runs of variation selectors / tag characters / zero-width / private-use code points) | HIGH, CRITICAL with a decode/eval sink |
| Blockchain-hosted C2 (Solana memo read **+** decode **+** eval in the same file) | CRITICAL |
| Download & execute (`curl … \| sh`, `eval(fetch(…))`, `iex (iwr …)` and `irm … \| iex`, `iwr -OutFile …; Start-Process`, `certutil -urlcache`, encoded PowerShell), also inside `\x41`-escaped obfuscator strings | CRITICAL |
| Environment dump (`JSON.stringify(process.env)`) **with a network send nearby** | CRITICAL |
| Credential / SecretStorage / auth-session read **+** exfil endpoint **+** send, within 3 KB | CRITICAL |
| Reverse shell (`/dev/tcp/…`, socket piped into `/bin/sh`) | CRITICAL |
| Destructive payload (`rm -rf ~`, `fs.rmSync(os.homedir())`) | CRITICAL |
| Worm propagation (`ovsx`/`vsce publish` with a PAT, Open VSX publish-by-token, npm publish with a token) | CRITICAL |
| Exfiltration endpoint (Discord/Telegram/Slack webhooks, webhook.site, pipedream, paste sites, ngrok/cloudflared tunnels, OAST collectors) **with a send nearby** | HIGH |
| Crypto-wallet / browser credential theft (MetaMask & co. extension IDs, `Login Data`, Keychain) | HIGH |
| Obfuscated payload (`eval(atob(…))`, `new Function(Buffer.from(…,'base64'))`, `_0x` obfuscator output with eval + network) | HIGH |
| Calendar-hosted pointer (`calendar.app.google/…` **+** decode + eval) | HIGH |
| Encrypted stage executed (`createDecipheriv` with a hard-coded key **+** an embedded blob **+** eval) | HIGH |
| Remote code: a response body from a hard-coded host handed to `eval` / `new Function` (`fetch(url).then(r=>r.text()).then(eval)`) | HIGH |
| Temp-file dropper (a `.cmd`/`.bat`/`.vbs`/`.ps1`/`.exe` written to the temp dir and launched, with a download or encoded PowerShell next to it) | HIGH |
| Extension side-loading (downloads a `.vsix` and runs `--install-extension` / `installExtension(Uri.file(…))`) | HIGH (MEDIUM from the extension's own vendor host) |
| GitHub as a command channel (hard-coded `ghp_`/`github_pat_` token + issues/comments API + process spawn) | HIGH |
| DNS exfiltration (hostname / username encoded into a DNS lookup) | HIGH |
| An HTTPS *install script* (`https://host/…/install.sh`, `…-installer.ps1`, or the extension's own vendor host) piped into a shell: how coding agents install other CLIs. Plain http, raw IPs, paste/gist/tunnel hosts and payload-shaped paths stay CRITICAL | MEDIUM |
| Raw public-IP URL next to a credential/env read or eval | MEDIUM |
| `NODE_TLS_REJECT_UNAUTHORIZED = "0"` for the whole extension host | MEDIUM (a weakness, not malice) |

Any HIGH/MEDIUM finding in the entry file of an extension that activates on **every** editor start
(`"*"` / `onStartupFinished`) is raised to CRITICAL: that code runs with no user action at all.

13 scored patterns / 44 regex signatures, plus 9 file-level detectors (`invisible_unicode`,
`blockchain_c2`, `credential_exfil`, `obfuscation_heavy`, `decrypt_eval`, `remote_eval`,
`temp_dropper`, `vsix_sideload`, `github_c2`) and 8 informational patterns.
Deterministic: no LLM, and no network needed to score.

## Calibrated, not noisy

Naive scanners flag every `child_process`, every `process.env`, every `curl … | sh` string in a
help panel, and get muted within a day. Measured on the **936 most-downloaded Open VSX
extensions** (7.2 GB of extension code), then on 893 more it had never seen:

| Engine | Flagged HIGH/CRITICAL |
| --- | --- |
| Same signatures, context-blind (top 641) | 57 / 641 (8.9%) |
| v0.1: first held-out set, engine frozen (Open VSX ranks 351-650) | 9 / 300 (3.0%) |
| v0.1: second held-out set, engine frozen again (ranks 651-950) | 8 / 295 (2.7%) |
| v0.1 final engine, all 936 | 3 / 936 (0.3%), all three kept on purpose (see FINDINGS) |
| **v0.2: third held-out set, frozen** (500 Open VSX ranks 946-1449 + 400 VS Marketplace top) | **10 / 893 (1.1%)**: 7 false positives (**0.8%**), 3 real data leaks to a public request bin |
| v0.2 on the 936 calibration extensions | 3 / 937 (0.3%), the same three |

The held-out rows are the honest out-of-sample estimate. On the Marketplace top only 1 of 395 was
flagged; the Open VSX long tail is noisier (9 of 498), mostly publishers shipping their own
`ovsx publish` scripts. Those classes were fixed after the run (v0.2.1), so v0.2.1's 0 known false
positives on that set is not an independent number.

**Recall** (v0.2 adds it; v0.1 was only checked on our own canaries): 4/4 real archived malicious
extensions (v0.1: 1/4), 19/20 canaries reconstructed from published incident write-ups (v0.1: 7/20),
and **4/17 on malicious samples written by two other projects**, held out, most of which are
defanged demos with no executable sink. Real samples are scarce because registries delete them;
see [FINDINGS.md](FINDINGS.md#recall-what-v010-missed) for what was missed and why.

What it reports as **INFO** (never scored), because the most-installed extensions do all of it:
`child_process`, network clients, `process.env`, `~/.ssh` / `~/.npmrc` references, SecretStorage
and `authentication.getSession`, Solana RPC, bundled native `.node`/`.exe` binaries,
`extensionPack`/`extensionDependencies`, startup activation, npm lifecycle scripts (VS Code never
runs them on install), shell one-liners inside comments, and official vendor installers
(`astral.sh/uv`, `rustup`, `deno`, `bun`, …).

**Full results: [FINDINGS.md](FINDINGS.md)**.

## Usage

```bash
python vsix_audit.py file.vsix [dir ...]                 # local .vsix or unpacked extension (dir or dir/extension)
python vsix_audit.py --openvsx redhat.vscode-yaml        # latest from open-vsx.org
python vsix_audit.py --openvsx esbenp.prettier-vscode@11.0.0
python vsix_audit.py --marketplace ms-python.python      # VS Marketplace (latest)
python vsix_audit.py --installed                         # every editor's installed extensions
python vsix_audit.py --text "eval(atob(x))"              # a string
python vsix_audit.py --json ...                          # machine-readable
python vsix_audit.py -v ...                              # also print INFO context
```

`--installed` looks in `~/.vscode`, `~/.vscode-insiders`, `~/.vscode-oss`, `~/.cursor`,
`~/.windsurf`, `~/.vscodium`, `~/.positron`, `~/.kiro`, `~/.trae` and `~/.void`.

Requires Python 3.9+. No dependencies. Tests: `python tests/run.py` (inert canaries for each
attack shape, 20 recall canaries rebuilt from public incident write-ups in `tests/recall/`, plus
benign controls that copy what popular extensions really do). Benchmark manifests (names, versions,
SHA-256, verdicts; no samples) are in `benchmarks/`.

## Limits

Static and deterministic: it reads text, so it cannot see inside compiled `.node`/`.exe`
binaries (they are listed as INFO), code fetched at runtime from a server that is not named in
the package, or a payload clever enough to avoid every pattern here. A clean result means "none of
these attack shapes are present", not "safe". Findings are pattern matches for human review,
not verdicts.

## Related

- [mcp-audit](https://github.com/eltociear/mcp-audit): the same engine for MCP servers and AI-agent skills
- [npm-audit](https://github.com/eltociear/npm-audit): npm packages (install-script attacks, env exfil, worms)
- [homebrew-audit](https://github.com/eltociear/homebrew-audit): Homebrew formulae, casks and taps
- [skill-audit-mcp](https://github.com/eltociear/skill-audit-mcp): GitHub Action, Docker image, MCP server and hosted API

MIT licensed.
