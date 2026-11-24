#!/usr/bin/env python3
"""vsix-audit - scan VS Code / Open VSX extensions for MALICIOUS patterns before you install them.

A VS Code extension is unsandboxed Node.js: it runs with your user's full rights the moment it
activates, can read ~/.ssh, every token in your environment and the editor's own SecretStorage,
and can spawn processes. Marketplace review is light, Open VSX (the registry Cursor, Windsurf,
VSCodium and most AI editors install from) lighter still, and the 2025 GlassWorm campaign showed
what that buys an attacker: self-spreading extensions whose loader was hidden in invisible
Unicode and whose C2 address was read from a Solana transaction memo.

This is a deterministic (no LLM) static scan of the .vsix package for: invisible-Unicode payloads,
eval of decoded/fetched code, blockchain- and calendar-hosted C2 lookups, credential / token /
SecretStorage theft to external hosts, environment dumps, reverse shells, wallet and browser data
theft, extension-token worm propagation and obfuscated loaders.

Precision-tuned to near-zero false positives on the most-downloaded Open VSX extensions:
capabilities extensions use every day (child_process, network clients, process.env, bundled
native .node binaries, extension packs, startup activation) are reported as informational context
and never inflate the risk score. Risk comes from specific sinks and COMBINATIONS.

The extension is never installed and none of its code runs: the .vsix (a zip) is read as text.

Usage:
  python vsix_audit.py <file.vsix|extracted-dir> [...]  # scan local packages
  python vsix_audit.py --openvsx publisher.name[@ver]    # download from open-vsx.org and scan
  python vsix_audit.py --marketplace publisher.name[@ver] # download from the VS Marketplace
  python vsix_audit.py --installed                       # scan ~/.vscode, ~/.cursor, ~/.windsurf ... extensions
  python vsix_audit.py --text "some code"                # scan a string
  add --json for machine-readable output, --verbose to print INFO context

Exit code 2 if any target is HIGH or CRITICAL (CI-friendly).
No dependencies beyond the standard library. MIT licensed.
"""
import bisect
import gzip
import io
import json
import os
import re
try:
    import re._parser as _sre_parse  # 3.11+
except ImportError:  # pragma: no cover
    import sre_parse as _sre_parse
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile

__version__ = "0.1.0"

SCAN_EXT = (".js", ".cjs", ".mjs", ".jsx", ".ts", ".cts", ".mts", ".sh", ".ps1", ".bat", ".cmd",
            ".py", ".html", ".htm")
BINARY_EXT = (".node", ".exe", ".dll", ".so", ".dylib")
MAX_FILE = 12000000     # bytes; extensions ship single multi-MB webpack bundles
MAX_TOTAL = 60000000    # bytes of text scanned per extension

EXFIL_HOST = (
    r"(?:discord(?:app)?\.com/api/webhooks/|api\.telegram\.org/bot|hooks\.slack\.com/services/|"
    r"webhook\.site|pipedream\.net|requestbin\.(?:com|net|io)|requestb\.in|requestcatcher\.com|beeceptor\.com|"
    r"pastebin\.com/(?:api|raw)|paste\.ee/|hastebin\.com|transfer\.sh|file\.io/|"
    r"ngrok(?:-free)?\.(?:io|app|dev)|\.trycloudflare\.com|serveo\.net|localtunnel\.me|"
    r"oastify\.com|oast\.(?:fun|me|pro|live|site|online)|interact\.sh|interactsh|"
    r"burpcollaborator\.net|canarytokens\.com|dnslog\.cn|ceye\.io|requestrepo\.com)"
)
RAW_IP_URL = r"https?://(?!(?:127\.|0\.0\.0\.0|10\.|192\.168\.|172\.(?:1[6-9]|2\d|3[01])\.|169\.254\.|1\.1\.1\.1\b|1\.0\.0\.1\b|8\.8\.8\.8\b|8\.8\.4\.4\b|9\.9\.9\.9\b))\d{1,3}(?:\.\d{1,3}){3}"
NET_SEND = (r"(?:https?\.request|https?\.get|require\s*\(\s*[\"'](?:node:)?(?:https?|net|dns)[\"']\s*\)|\bfetch\s*\(|axios(?:\.\w+)?\s*\(|\.post\s*\(|"
            r"XMLHttpRequest|net\.connect|new\s+net\.Socket|dns\.(?:lookup|resolve\w*)\s*\(|"
            r"\bcurl\b|\bwget\b|request\s*\(\s*\{)")
# Invisible code points GlassWorm-style loaders use to hide a payload in "empty" lines:
# variation selectors (FE00-FE0F, E0100-E01EF), Unicode tag characters (E0000-E007F) and the
# private-use area. A long unbroken run of these in source code is a hidden byte stream.
INVISIBLE_RUN = re.compile("[\ufe00-\ufe0f\U000e0100-\U000e01ef\U000e0000-\U000e007f]{24,}")
PUA_RUN = re.compile("[\ue000-\uf8ff]{200,}")
EVAL_SINK = re.compile(r"\beval\s*\(|new\s+Function\s*\(|\bFunction\s*\(\s*[\"'`]|vm\.runIn\w*Context\s*\(|\.runInThisContext\s*\(", re.I)
SOLANA_RE = re.compile(r"getSignaturesForAddress|api\.mainnet-beta\.solana\.com|solana-mainnet|\bspl-memo\b|MemoSq4gqABAXKb96qnH8TysNcWxMyWCqXgDLGmfcHr", re.I)
CALENDAR_RE = re.compile(r"calendar\.app\.google/[A-Za-z0-9]+", re.I)
DECODE_RE = re.compile(r"atob\s*\(|Buffer\.from\s*\([^)]{0,200}[\"'](?:base64|hex)[\"']|decodeURIComponent\s*\(\s*escape", re.I)

PATTERNS = {
    "critical": [
        {"id": "download_execute", "name": "Download & Execute",
         "desc": "Fetches remote content and pipes it straight into a shell/interpreter/eval",
         "regexes": [
             r"curl\s+[^\n|;\"'`]*https?://[^\n|;]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|node)\b",
             r"wget\s+[^\n|;\"'`]*https?://[^\n|;]*\|\s*(?:sudo\s+)?(?:sh|bash|zsh|python3?|node)\b",
             r"(?:sh|bash|python3?|node)\s*<\s*\(\s*(?:curl|wget)\s",
             r"eval\s*\(\s*(?:await\s+)?\(?\s*(?:await\s+)?fetch\s*\(",
             r"(?:eval|new\s+Function)\s*\(\s*(?:await\s+)?\(?\s*(?:await\s+)?(?:\(\s*await\s+)?(?:axios\.get|fetch)\s*\([^\n]{0,200}\)\s*\)?\s*\.(?:text|data)",
             r"(?:iex|Invoke-Expression)\s*\(?\s*\(?\s*(?:New-Object\s+Net\.WebClient|iwr|Invoke-WebRequest|irm|Invoke-RestMethod)\b",
             r"powershell(?:\.exe)?[\"',\s][^\n]{0,60}-(?:e|enc|encodedcommand)\s+[A-Za-z0-9+/=]{60,}",
         ]},
        {"id": "env_exfil", "name": "Environment Dump",
         "desc": "Serialises the whole process.env (every token/secret) - exfil when a network sink is present",
         "regexes": [
             r"JSON\.stringify\s*\(\s*process\.env\s*\)",
             r"Buffer\.from\s*\(\s*JSON\.stringify\s*\(\s*process\.env",
             r"querystring\.stringify\s*\(\s*process\.env",
             r"(?:body|data|payload)\s*:\s*JSON\.stringify\s*\(\s*\{[^\n}]{0,120}\benv\s*:\s*process\.env",
         ]},
        {"id": "reverse_shell", "name": "Reverse Shell",
         "desc": "Spawns an interactive shell bound to a network socket",
         "regexes": [
             r"/dev/tcp/(?:\d{1,3}\.){3}\d{1,3}/\d+|/dev/tcp/[a-z0-9.-]+\.[a-z]{2,}/\d+",
             r"bash\s+-i\s*>&\s*/dev/tcp",
             r"\bnc(?:at)?\s+(?:-\w+\s+)*-e\s+/bin/(?:ba)?sh",
             r"spawn\s*\(\s*[\"'](?:/bin/)?(?:ba)?sh[\"'][^\n]{0,200}\.pipe\s*\(\s*(?:client|socket|sock|conn)\b",
             r"\b(?:client|socket|sock|conn)\.pipe\s*\(\s*(?:sh|shell|proc|child)\.stdin\s*\)",
         ]},
        {"id": "destructive", "name": "Destructive Payload",
         "desc": "Wipes the home directory / filesystem (protestware, wiper)",
         "regexes": [
             r"rm\s+-[a-zA-Z]*r[a-zA-Z]*f?\s+(?:--no-preserve-root\s+)?(?:~|\$HOME)/?(?:\s|[\"'`;]|$)",
             r"rm\s+-rf\s+--no-preserve-root\s+/",
             r"(?:rmSync|rmdirSync|rimraf\w*)\s*\(\s*(?:os\.)?homedir\s*\(\s*\)\s*,",
             r"del\s+/[fsq]\s+/[fsq]\s+[\"']?C:\\\\(?:\s|[\"'])",
         ]},
        {"id": "worm_propagation", "name": "Self-Propagation (Worm)",
         "desc": "Uses stolen registry/GitHub tokens to republish extensions or packages",
         "regexes": [
             r"(?:ovsx|vsce)\s+publish[^\n]{0,160}(?:-p\s|--pat\b|OVSX_PAT|VSCE_PAT)",
             r"(?:OVSX_PAT|VSCE_PAT)[^\n]{0,200}(?:ovsx|vsce)\s+publish",
             r"open-vsx\.org/api/-/publish\?token=",
             r"npm\s+publish[^\n]{0,120}(?:NPM_TOKEN|_authToken|npm_token)",
             r"registry\.npmjs\.org/-/v1/search\?text=maintainer:",
         ]},
    ],
    "high": [
        {"id": "exfil_host", "name": "Exfiltration Endpoint",
         "desc": "Hard-codes a webhook / paste / tunnel / OAST collector host",
         "regexes": [EXFIL_HOST]},
        {"id": "wallet_browser_theft", "name": "Wallet / Browser Data Theft",
         "desc": "Targets crypto-wallet extension storage, browser credential stores or Keychain",
         "regexes": [
             r"nkbihfbeogaeaoehlefnkodbefgpgknn|bfnaelmomeimhlpmgjnjophhpkkoljpa|hnfanknocfeofbddgcijnmhnfnkdnaad|ibnejdfjmmkpcnlpebklmnkoeoihofec|egjidjbpglichdcondbcbdnbeeppgdph|aholpfdialjgjfhomihkjbmgjidlcdno|acmacodkjbdgmoleebolmdjonilkdbch",
             r"(?:Chrome|BraveSoftware|Microsoft[/\\\\]Edge|Opera Software)[^\n]{0,80}(?:Login Data|Local Extension Settings)",
             r"(?:Exodus|atomic|Electrum)[/\\\\](?:exodus\.wallet|Local Storage|wallets)",
             r"find-generic-password[^\n]{0,80}(?:Chrome|Chromium|Brave|Microsoft Edge|Opera|Vivaldi|Arc|Yandex) Safe Storage",
             r"\b(?:wallet\.dat|seed\.seco)\b",
         ]},
        {"id": "obfuscation", "name": "Obfuscated Payload",
         "desc": "eval of decoded strings / escape blobs",
         "regexes": [
             r"(?:eval|Function)\s*\(\s*(?:atob|unescape)\s*\(",
             r"(?:eval|new\s+Function)\s*\(\s*Buffer\.from\s*\([^)]{0,4000},\s*[\"'](?:base64|hex)[\"']",
             r"(?:eval|new\s+Function)\s*\(\s*[\"'](?:\\x[0-9a-fA-F]{2}){20,}",
             r"(?:eval|new\s+Function)\s*\(\s*String\.fromCharCode\s*\(",
         ]},
        {"id": "dns_exfil", "name": "DNS Exfiltration",
         "desc": "Encodes host/user data into a DNS lookup (beacon)",
         "regexes": [
             r"dns\.(?:lookup|resolve\w*)\s*\([^\n]{0,160}(?:hostname\s*\(\)|userInfo\s*\(\)|homedir\s*\(\)|toString\s*\(\s*[\"']hex)",
         ]},
    ],
    "medium": [
        {"id": "browser_store_read", "name": "Browser Credential Store Read",
         "desc": "Copies/reads a browser Login Data / Cookies database (HIGH with an exfil endpoint nearby)",
         "regexes": [r"[\"'](?:Login Data|Web Data|Cookies)[\"'][^\n]{0,160}(?:readFile|copyFile|createReadStream)"]},
        {"id": "auth_bypass", "name": "TLS Verification Disabled Globally",
         "desc": "Turns off certificate checking for the whole extension host (weakness, not malice)",
         "regexes": [r"process\.env\.NODE_TLS_REJECT_UNAUTHORIZED\s*=\s*[\"']?0"]},
        {"id": "raw_ip_url", "name": "Raw-IP URL",
         "desc": "Contacts a public IP address directly instead of a hostname",
         "regexes": [RAW_IP_URL]},
        {"id": "calendar_c2", "name": "Calendar-Hosted Pointer",
         "desc": "Google Calendar short link in code (GlassWorm backup C2 channel)",
         "regexes": [r"calendar\.app\.google/[A-Za-z0-9]+"]},
    ],
    "low": [],
    # Context: reported, never scored. Capabilities popular extensions use daily.
    "info": [
        {"id": "credential_read", "name": "Credential Store Reference",
         "desc": "References ~/.ssh, ~/.aws, ~/.npmrc, git credentials, kube/docker config",
         "regexes": [r"\.npmrc\b", r"\.ssh[/\\\\]id_\w+", r"\.aws[/\\\\]credentials", r"\.git-credentials",
                     r"\.docker[/\\\\]config\.json", r"\.kube[/\\\\]config"]},
        {"id": "secret_storage", "name": "Editor Secret / Session Access",
         "desc": "Reads SecretStorage or an auth session (normal for sign-in features)",
         "regexes": [r"\.secrets\.get\s*\(", r"authentication\.getSession\s*\("]},
        {"id": "child_process", "name": "Process Spawning",
         "desc": "Uses child_process (language servers, linters, CLIs all do)",
         "regexes": [r"child_process", r"\bexecSync\s*\(", r"\bspawnSync\s*\("]},
        {"id": "network", "name": "Network Access",
         "desc": "Makes outbound HTTP/DNS/socket calls",
         "regexes": [NET_SEND]},
        {"id": "env_read", "name": "Environment Access",
         "desc": "Reads environment variables",
         "regexes": [r"process\.env\b"]},
        {"id": "keychain_read", "name": "Keychain Read",
         "desc": "Reads a macOS Keychain item (CLIs and SDKs read their own stored credentials)",
         "regexes": [r"security\s+find-generic-password\b"]},
        {"id": "secret_scanner_fetch", "name": "Secret-Scanner Download",
         "desc": "Downloads TruffleHog (secret-scanning features do; Shai-Hulud did too)",
         "regexes": [r"github\.com/trufflesecurity/trufflehog/releases"]},
        {"id": "solana_rpc", "name": "Blockchain RPC",
         "desc": "Solana RPC / memo access (wallet tooling does this; GlassWorm used it as C2)",
         "regexes": [SOLANA_RE.pattern]},
    ],
}
CONTEXT_ONCE = {"keychain_read", "secret_scanner_fetch", "network", "env_read", "child_process", "secret_storage", "credential_read", "solana_rpc"}

# ---- literal prefilter ----------------------------------------------------------------
# Python's re is slow on IGNORECASE alternations over 15 MB webpack bundles. Each regex gets
# an any-of set of lowercase literals derived from its parse tree; at least one must occur in
# the lowercased text for a match to be possible, so most regexes are skipped by a C-speed
# substring test.
def _lits(parsed):
    """Return a set of literals at least one of which every match must contain, or None."""
    best, run = None, ""

    def consider(cand):
        nonlocal best
        if cand and all(len(c) >= 3 for c in cand):
            if best is None or min(map(len, cand)) > min(map(len, best)):
                best = cand
    for op, av in list(parsed):
        name = str(op)
        if name == "LITERAL":
            run += chr(av).lower()
            continue
        consider({run} if run else None)
        run = ""
        if name == "SUBPATTERN":
            consider(_lits(av[-1]))
        elif name == "BRANCH":
            subs = [_lits(b) for b in av[1]]
            if all(x is not None for x in subs):
                consider(set().union(*subs))
        elif name in ("MAX_REPEAT", "MIN_REPEAT") and av[0] >= 1:
            consider(_lits(av[2]))
    consider({run} if run else None)
    return best


def _prefilter(pattern):
    try:
        return _lits(_sre_parse.parse(pattern))
    except Exception:
        return None


_ASCII_LOWER = {c: c + 32 for c in range(65, 91)}


def _lower(text):
    """ASCII-only lowercase: keeps offsets aligned with the original text (str.lower() can
    change the length of non-ASCII text, which would misplace every literal hit)."""
    return text.lower() if text.isascii() else text.translate(_ASCII_LOWER)


def _possible(lits, lowered):
    return lits is None or any(l in lowered for l in lits)


def _finditer(rx, lits, text, low, before=400, after=800, cap=4000):
    """rx.finditer(text), but only search windows around the regex's required literals."""
    if lits is None or len(low) != len(text):
        yield from rx.finditer(text)
        return
    pos = []
    for lit in lits:
        i = low.find(lit)
        while i != -1:
            pos.append(i)
            if len(pos) > cap:  # literal is everywhere: a full scan is cheaper
                yield from rx.finditer(text)
                return
            i = low.find(lit, i + 1)
    end = -1
    for p in sorted(pos):
        if p < end:
            continue
        m = rx.search(text, max(0, p - before, end), p + after)
        if m:
            end = m.end()
            yield m


def _search(rx, lits, text, low, lo=0, hi=None):
    hi = len(text) if hi is None else hi
    if lits is not None and len(low) == len(text) and not any(l in low[lo:hi] for l in lits):
        return None
    for m in _finditer(rx, lits, text[lo:hi], low[lo:hi]):
        return m
    return None


SEVERITY_SCORE = {"critical": 25, "high": 15, "medium": 8, "low": 3, "info": 0}
SEV_ORDER = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0, "SAFE": 0}
_COMPILED = [(sev, pg, re.compile(rx, re.IGNORECASE), _prefilter(rx))
             for sev, groups in PATTERNS.items() for pg in groups for rx in pg["regexes"]]
OBF_IDENT = re.compile(r"\b_0x[0-9a-f]{4,6}\b")
NET_RE = re.compile(NET_SEND, re.IGNORECASE)
EXFIL_RE = re.compile(EXFIL_HOST, re.IGNORECASE)
RAWIP_RE = re.compile(RAW_IP_URL)
CRED_RE = re.compile(r"\.ssh[/\\\\]id_\w+|\.aws[/\\\\]credentials|\.git-credentials|\.npmrc\b|\.secrets\.get\s*\(|authentication\.getSession\s*\(", re.I)
STARTUP_EVENTS = ("*", "onStartupFinished")
_COMBO_LITS = {"net": _prefilter(NET_SEND), "eval": _prefilter(EVAL_SINK.pattern),
               "decode": _prefilter(DECODE_RE.pattern), "exfil": _prefilter(EXFIL_HOST),
               "cred": _prefilter(CRED_RE.pattern), "solana": _prefilter(SOLANA_RE.pattern)}
# Official vendor installers that extensions legitimately run (uv, rustup, deno, bun, ...).
KNOWN_INSTALLER = re.compile(
    r"https://(?:astral\.sh/(?:uv|ruff)/|sh\.rustup\.rs|static\.rust-lang\.org/rustup|deno\.land/install|"
    r"bun\.sh/install|get\.pnpm\.io/install|install\.python-poetry\.org|pyenv\.run|get\.docker\.com|"
    r"raw\.githubusercontent\.com/nvm-sh/nvm/|foundry\.paradigm\.xyz|get\.volta\.sh|fnm\.vercel\.app/install|"
    r"pixi\.sh/install|claude\.ai/install\.sh|opencode\.ai/install|ollama\.com/install\.sh|sdk\.cloud\.google\.com|"
    r"cli\.github\.com|get\.jetpack\.io|mise\.run|get\.haskell\.org|get-ghcup\.haskell\.org|nixos\.org/nix/install|"
    r"install\.determinate\.systems|dot\.net/v1/dotnet-install|aka\.ms/install|sh\.brew\.sh|"
    r"x\.ai/cli/install|cursor\.com/install|antigravity\.google/cli|dev\.meta\.ai/install|pi\.dev/install|"
    r"ampcode\.com/install|app\.factory\.ai/cli|cli\.coderabbit\.ai|kiro\.dev/install|warp\.dev/install|"
    r"github\.com/block/goose/releases|qwenlm\.github\.io|cli\.kimi\.com|droid\.factory\.ai|"
    r"raw\.githubusercontent\.com/Homebrew/install/)", re.I)
DOMAIN_STR = re.compile(r"[\"'][*.]?[a-z0-9-]+(?:\.[a-z0-9-]+)+[\"']", re.I)
NEAR = 1500  # chars: in a bundle "same file" is meaningless, so sinks must be nearby


COMMENT_LINE = re.compile(r"^\s*(?://|/\*|\*|#|<!--|REM\s)")
NO_STARTUP_ESCALATION = {"auth_bypass", "remote_installer", "obfuscation_heavy", "browser_store_read"}
# A command rendered for the user to copy (HTML/markdown/“run:” prose), not executed.
DISPLAY_CTX = re.compile(r"(?:<(?:code|pre|div|span|p|kbd|li|td)\b[^>]*>|\\?`|\b(?:run|paste|execute|terminal|install(?:\s+it)?)\s*(?:this|the following|:|,)?\s*[\"'`]?)\s*$", re.I)
SHELL_FILE = (".sh", ".ps1", ".bat", ".cmd")
LIST_ELEMENT = re.compile(r"[\[,]\s*[\"'`]$")
LIST_LINE = re.compile(r"^\s*[\"'`][^\"'`]{0,200}[\"'`]\s*[,\]]?\s*$")
HTTPS_NAMED = re.compile(r"https://[a-z0-9-]+(?:\.[a-z0-9-]+)*\.[a-z]{2,}/", re.I)
SKETCHY_HOST = re.compile(r"raw\.githubusercontent\.com|gist\.githubusercontent|pastebin|paste\.|transfer\.sh|file\.io|"
                          r"ngrok|trycloudflare|serveo|localtunnel|\.onion|bit\.ly|tinyurl|is\.gd|t\.co/", re.I)
COMMENT_DEMOTE = {"auth_bypass", "download_execute", "reverse_shell", "destructive", "worm_propagation", "exfil_host", "raw_ip_url"}


def _item(sev, pid, name, desc, path, line, matched, context):
    return {"severity": sev, "id": pid, "name": name, "description": desc, "file": path,
            "line": line, "matched": matched[:120], "context": context[:200]}


GENERIC_TOKENS = {"vscode", "code", "extension", "extensions", "tools", "tool", "the", "and", "for", "com",
                  "github", "www", "http", "https", "lang", "language", "support", "dev", "app", "pack",
                  "plugin", "theme", "server", "client", "inc", "llc", "ltd", "official", "team", "labs",
                  "org", "net", "git", "ide", "studio", "visual"}


def _vendor_tokens(pkg):
    """Identity tokens of an extension: publisher, name, display name, repo/homepage hosts."""
    raw = [pkg.get("publisher"), pkg.get("name"), pkg.get("displayName"), pkg.get("homepage")]
    repo = pkg.get("repository")
    raw.append(repo.get("url") if isinstance(repo, dict) else repo)
    author = pkg.get("author")
    raw.append(author.get("name") if isinstance(author, dict) else author)
    toks = set()
    for r in raw:
        if isinstance(r, str):
            toks.update(t for t in re.split(r"[^a-z0-9]+", r.lower()) if len(t) >= 3)
    return frozenset(toks - GENERIC_TOKENS)


def _vendor_host(matched, vendor):
    m = re.search(r"https://([a-z0-9.-]+)", matched, re.I)
    if not m:
        return False
    labels = {t for t in re.split(r"[^a-z0-9]+", m.group(1).lower()) if len(t) >= 3}
    return any(l in vendor or any(v in l for v in vendor) for l in labels - GENERIC_TOKENS)


def _scan_text(text, path, findings, info, startup, vendor=frozenset()):
    """Line-oriented pattern pass plus file-level combination rules."""
    lines = text.split("\n")
    starts, acc = [], 0
    for ln in lines:
        starts.append(acc)
        acc += len(ln) + 1
    seen = set()
    local = []
    low = _lower(text)
    for sev, pg, rx, lits in _COMPILED:
        pid = pg["id"]
        once = pid in CONTEXT_ONCE
        if (once and pid in seen) or not _possible(lits, low):
            continue
        for m in _finditer(rx, lits, text, low):
            n = bisect.bisect_right(starts, m.start())  # 1-based line number
            if (pid, n) in seen:
                continue
            seen.add((pid, n))
            line = lines[n - 1]
            s = m.start() - starts[n - 1]
            it = _item(sev.upper(), pid, pg["name"], pg["desc"], path, n, m.group(0),
                       line[max(0, s - 60):s + 140].strip())
            it["_pos"] = m.start()
            local.append(it)
            if once:
                seen.add(pid)
                break
    ids = {f["id"] for f in local}
    may = {k: _possible(v, low) for k, v in _COMBO_LITS.items()}
    L = _COMBO_LITS
    has_net = may["net"] and bool(_search(NET_RE, L["net"], text, low))
    has_eval = may["eval"] and bool(_search(EVAL_SINK, L["eval"], text, low))
    has_decode = may["decode"] and bool(_search(DECODE_RE, L["decode"], text, low))
    has_exfil = may["exfil"] and bool(_search(EXFIL_RE, L["exfil"], text, low))

    def near(key, rx, pos, span=NEAR):
        return may[key] and bool(_search(rx, L[key], text, low, max(0, pos - span), pos + span))

    def demote(pid):
        for f in local:
            if f["id"] == pid:
                f["severity"] = "INFO"

    # ---- combination rules --------------------------------------------------------------
    # A shell one-liner inside a comment is install documentation, not code that runs.
    for f in local:
        if f["id"] in COMMENT_DEMOTE and f["line"] and COMMENT_LINE.match(lines[f["line"] - 1]):
            f["severity"] = "INFO"
            f["description"] += " [in a comment]"
    for f in local:
        if f["severity"] == "INFO" or not f["line"]:
            continue
        pos = f.get("_pos", 0)
        # A dangerous command as an element of a string list is a blocklist / deny-rule table
        # (auto-approve and terminal-safety extensions ship these), not code that runs.
        if f["id"] in ("destructive", "download_execute", "reverse_shell") and (
                LIST_ELEMENT.search(text[max(0, pos - 12):pos]) or LIST_LINE.match(lines[f["line"] - 1])):
            f["severity"] = "INFO"
            f["description"] += " [string in a command list]"
            continue
        # env dump with no network sink nearby is a debug print / a shell-command string.
        if f["id"] == "env_exfil" and not near("net", NET_RE, pos):
            f["severity"] = "INFO"
        # an exfil host with no send nearby is a string in docs / config UI;
        # one inside a long list of domains is a public-suffix / blocklist table.
        elif f["id"] == "exfil_host" and (not near("net", NET_RE, pos) or
                                          len(DOMAIN_STR.findall(text, max(0, pos - 300), pos + 300)) >= 8):
            f["severity"] = "INFO"
            f["description"] += " [no nearby send / domain list]"
        # an install command rendered for the user to copy is documentation, not execution.
        if f["id"] == "download_execute" and DISPLAY_CTX.search(text[max(0, pos - 60):pos]):
            f["severity"] = "INFO"
            f["description"] += " [shown to the user]"
            continue
        # a publisher's own release script shipped in the package (`ovsx publish -p $PAT` in a
        # .sh file) is CI leakage; a worm runs publish from the extension's JS.
        if f["id"] == "worm_propagation" and path.lower().endswith(SHELL_FILE):
            f["severity"] = "INFO"
            f["description"] += " [release script shipped in the package]"
            continue
        # running an official vendor installer (uv, rustup, ...) is setup, not an attack.
        if f["id"] == "download_execute" and KNOWN_INSTALLER.search(f["matched"] + f["context"]):
            f["severity"] = "INFO"
            f["description"] += " [official vendor installer]"
        # curl|sh of an HTTPS installer hosted on the extension's OWN vendor domain is how vendors
        # ship their CLIs (firebase -> firebase.tools, snowflake -> ai.snowflake.com): a trust
        # decision worth showing, not an attack. Any other host, plain http, raw IPs and
        # paste/gist/tunnel/shortener hosts stay CRITICAL.
        elif (f["id"] == "download_execute" and vendor and _vendor_host(f["matched"], vendor)
              and not SKETCHY_HOST.search(f["matched"]) and not RAWIP_RE.search(f["matched"])
              and not EXFIL_RE.search(f["matched"])):
            f["severity"], f["id"], f["name"] = "MEDIUM", "remote_installer", "Remote Installer Piped to Shell"
            f["description"] = ("Pipes an HTTPS install script from the extension's own vendor domain into a "
                                "shell (a trust decision; review the host)")
        # raw-IP URLs only matter next to a credential/env read or an eval sink.
        elif f["id"] == "raw_ip_url" and not (near("cred", CRED_RE, pos) or near("eval", EVAL_SINK, pos)
                                              or "process.env" in low[max(0, pos - NEAR):pos + NEAR]):
            f["severity"] = "INFO"
        # browser cookie / Login Data copy: browser-automation extensions import cookies;
        # it is theft when an exfil endpoint or raw IP sits next to it.
        elif f["id"] == "browser_store_read" and (near("exfil", EXFIL_RE, pos, 3000) or
                                                  RAWIP_RE.search(text, max(0, pos - 3000), pos + 3000)):
            f["severity"] = "HIGH"
    # a calendar short link is only a C2 pointer if something decodes and runs code.
    if "calendar_c2" in ids and has_eval and has_decode:
        for f in local:
            if f["id"] == "calendar_c2":
                f["severity"] = "HIGH"
    elif "calendar_c2" in ids:
        demote("calendar_c2")
    # credential store / editor secret read + exfil endpoint in the same file -> theft
    if has_exfil and has_net and may["cred"] and any(
            near("exfil", EXFIL_RE, m.start(), 3000) and near("net", NET_RE, m.start(), 3000)
            for m in _finditer(CRED_RE, L["cred"], text, low)):
        local.append(_item("CRITICAL", "credential_exfil", "Credential Exfiltration",
                           "Reads credentials / editor secrets and sends to an exfil endpoint in the same file",
                           path, 0, "", "file-level combination"))
    # blockchain-memo C2: reads transaction memos AND evals decoded content (GlassWorm)
    if has_eval and has_decode and may["solana"] and "memo" in low and _search(SOLANA_RE, L["solana"], text, low):
        local.append(_item("CRITICAL", "blockchain_c2", "Blockchain-Hosted C2",
                           "Reads Solana transaction memos and evals decoded content (GlassWorm C2 pattern)",
                           path, 0, "", "file-level combination"))
    # invisible-Unicode payload (GlassWorm): a long run of variation selectors / tag chars
    for rx, label in ((INVISIBLE_RUN, "variation-selector / tag-character"), (PUA_RUN, "private-use")):
        m = rx.search(text) if not text.isascii() else None
        if m:
            n = text.count("\n", 0, m.start()) + 1
            sev = "CRITICAL" if has_eval or has_decode else "HIGH"
            local.append(_item(sev, "invisible_unicode", "Invisible-Unicode Payload",
                               "%d consecutive invisible %s code points (hidden byte stream)" % (len(m.group(0)), label),
                               path, n, "", "U+%04X x%d" % (ord(m.group(0)[0]), len(m.group(0)))))
            break
    # javascript-obfuscator output: dozens of _0x identifiers.
    obf = len(OBF_IDENT.findall(text[:6000000])) if "_0x" in low else 0
    if obf >= 25:
        # commercial extensions obfuscate to protect their code; it is a payload shape when
        # the obfuscated file also carries an exfil endpoint or a raw public IP.
        if has_exfil or RAWIP_RE.search(text):
            sev = "HIGH"
        else:
            sev = "MEDIUM" if (has_eval and has_net) else "INFO"
        local.append(_item(sev, "obfuscation_heavy", "Heavily Obfuscated Code",
                           "javascript-obfuscator style code (%d _0x identifiers)" % obf,
                           path, 0, "", "file-level"))
    # Startup escalation: an extension that activates on every window ("*"/onStartupFinished)
    # runs this code with no user action - HIGH there is CRITICAL.
    if startup:
        for f in local:
            if f["severity"] in ("HIGH", "MEDIUM") and f["id"] not in NO_STARTUP_ESCALATION:
                f["severity"] = "CRITICAL"
                f["description"] += " [runs on editor startup]"
    for f in local:
        f.pop("_pos", None)
        (info if f["severity"] == "INFO" else findings).append(f)


def _manifest(pkg, findings, info):
    """Extension manifest context. VS Code never runs npm lifecycle scripts on install."""
    events = pkg.get("activationEvents") or []
    startup = any(e in STARTUP_EVENTS for e in events if isinstance(e, str))
    if startup:
        info.append(_item("INFO", "eager_activation", "Startup Activation",
                          "Activates on every editor start (%s)" % ", ".join(e for e in events if e in STARTUP_EVENTS),
                          "package.json", 0, "", "activationEvents"))
    for k in ("extensionDependencies", "extensionPack"):
        deps = pkg.get(k) or []
        if deps:
            info.append(_item("INFO", "extension_pull", "Pulls Other Extensions",
                              "%s installs %d other extension(s)" % (k, len(deps)), "package.json", 0, "",
                              ", ".join(map(str, deps))[:200]))
    scripts = pkg.get("scripts") or {}
    for hook in ("preinstall", "install", "postinstall"):
        cmd = scripts.get(hook)
        if isinstance(cmd, str) and cmd.strip():
            info.append(_item("INFO", "lifecycle_script", "npm Lifecycle Script",
                              "Not run by VS Code on install; runs if someone `npm install`s the source",
                              "package.json", 0, hook, "%s: %s" % (hook, cmd)))
            tmp = []
            _scan_text(cmd, "package.json#scripts.%s" % hook, tmp, info, False)
            findings.extend(tmp)
    return startup


def _entry_files(pkg):
    out = set()
    for k in ("main", "browser"):
        v = pkg.get(k)
        if isinstance(v, str) and v:
            p = os.path.normpath(v.replace("\\", "/")).lstrip("./")
            out.update({p, p + ".js"})
    return out


def scan_extension(files, label="", binaries=()):
    """files: {path relative to the extension root: text}. Returns an audit result dict."""
    findings, info = [], []
    pkg = {}
    if "package.json" in files:
        try:
            pkg = json.loads(files["package.json"])
        except ValueError:
            pkg = {}
    startup = _manifest(pkg, findings, info)
    entries = _entry_files(pkg)
    vendor = _vendor_tokens(pkg)
    for b in sorted(binaries)[:20]:
        info.append(_item("INFO", "native_binary", "Bundled Native Binary",
                          "Ships compiled code that cannot be text-scanned", b, 0, "", ""))
    total = 0
    for path, text in sorted(files.items()):
        if path.endswith((".json", ".d.ts", ".map")):
            continue
        total += len(text)
        if total > MAX_TOTAL:
            info.append(_item("INFO", "truncated", "Scan Truncated",
                              "Extension exceeds %d bytes of text" % MAX_TOTAL, path, 0, "", ""))
            break
        _scan_text(text, path, findings, info, startup and path in entries, vendor)
    return _summarise(findings, info, label, pkg)


def _summarise(findings, info, label, pkg=None):
    counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    score = 0
    for f in findings:
        counts[f["severity"]] += 1
        score += SEVERITY_SCORE[f["severity"].lower()]
    level = next((s for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]), "SAFE")
    findings.sort(key=lambda f: (-SEV_ORDER[f["severity"]], f["file"], f["line"]))
    parts = ["%d %s" % (counts[s], s) for s in ("CRITICAL", "HIGH", "MEDIUM", "LOW") if counts[s]]
    pkg = pkg or {}
    return {"target": label, "risk_score": min(score, 100), "risk_level": level,
            "summary": ", ".join(parts) or "No issues found",
            "version": pkg.get("version"),
            "activation": pkg.get("activationEvents") or [],
            "findings": findings, "info": info,
            "total_findings": len(findings), "info_count": len(info)}


def scan(content, label="<text>"):
    """Scan a bare string."""
    findings, info = [], []
    _scan_text(content, label, findings, info, False)
    return _summarise(findings, info, label)


# ---------------------------------------------------------------------------
# Loading targets (never executes extension code)
# ---------------------------------------------------------------------------
UA = {"User-Agent": "vsix-audit/%s (+https://github.com/eltociear/vsix-audit)" % __version__}


def _get(url, timeout=120, tries=4):
    for i in range(tries):
        try:
            data = urllib.request.urlopen(urllib.request.Request(url, headers=UA), timeout=timeout).read()
            if data[:2] == b"\x1f\x8b":  # the Marketplace serves gzip'd vsix
                data = gzip.decompress(data)
            return data
        except urllib.error.HTTPError as e:
            if e.code < 500 or i == tries - 1:
                raise
        except Exception:
            if i == tries - 1:
                raise
        time.sleep(2 * (i + 1))


def _add(out, bins, rel, raw_size, read):
    low = rel.lower()
    if low.endswith(BINARY_EXT):
        bins.append(rel)
        return
    if not (low.endswith(SCAN_EXT) or rel == "package.json") or raw_size > MAX_FILE:
        return
    out[rel] = read().decode("utf-8", "replace")


def files_from_vsix(data):
    """Read a .vsix (zip). Extension files live under extension/."""
    out, bins = {}, []
    with zipfile.ZipFile(io.BytesIO(data)) as z:
        for zi in z.infolist():
            if zi.is_dir() or not zi.filename.startswith("extension/"):
                continue
            rel = zi.filename[len("extension/"):]
            _add(out, bins, rel, zi.file_size, lambda zi=zi: z.read(zi))
    return out, bins


def files_from_dir(root):
    out, bins = {}, []
    for dp, dns, fns in os.walk(root):
        dns[:] = [d for d in dns if d != ".git"]
        for fn in fns:
            p = os.path.join(dp, fn)
            rel = os.path.relpath(p, root).replace(os.sep, "/")
            try:
                size = os.path.getsize(p)
                _add(out, bins, rel, size, lambda p=p: open(p, "rb").read())
            except OSError:
                pass
    return out, bins


def split_id(spec):
    ident, _, ver = spec.partition("@")
    if "." not in ident:
        raise ValueError("expected publisher.name, got %r" % spec)
    pub, name = ident.split(".", 1)
    return pub, name, ver or "latest"


def openvsx_url(spec):
    pub, name, ver = split_id(spec)
    base = "https://open-vsx.org/api/%s/%s" % (urllib.parse.quote(pub), urllib.parse.quote(name))
    meta = json.loads(_get(base if ver == "latest" else base + "/" + urllib.parse.quote(ver), timeout=60))
    return meta["files"]["download"], "%s.%s@%s" % (pub, name, meta.get("version", ver))


def marketplace_url(spec):
    pub, name, ver = split_id(spec)
    return ("https://marketplace.visualstudio.com/_apis/public/gallery/publishers/%s/vsextensions/%s/%s/vspackage"
            % (pub, name, ver)), "%s.%s@%s" % (pub, name, ver)


def audit_url(url, label):
    files, bins = files_from_vsix(_get(url, timeout=300))
    r = scan_extension(files, label, bins)
    if label.endswith("@latest") and r.get("version"):
        r["target"] = label[:-len("latest")] + r["version"]
    return r


def audit_dir(root, label):
    files, bins = files_from_dir(root)
    return scan_extension(files, label, bins)


def audit_vsix_file(path):
    with open(path, "rb") as fh:
        files, bins = files_from_vsix(fh.read())
    return scan_extension(files, path, bins)


def installed_dirs():
    home = os.path.expanduser("~")
    roots = [".vscode", ".vscode-insiders", ".vscode-oss", ".cursor", ".windsurf", ".vscodium",
             ".positron", ".kiro", ".trae", ".void"]
    out = []
    for r in roots:
        d = os.path.join(home, r, "extensions")
        if os.path.isdir(d):
            for e in sorted(os.listdir(d)):
                p = os.path.join(d, e)
                if os.path.isfile(os.path.join(p, "package.json")):
                    out.append((r.lstrip(".") + "/" + e, p))
    return out


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
_ICON = {"CRITICAL": "\U0001F534", "HIGH": "\U0001F7E0", "MEDIUM": "\U0001F7E1",
         "LOW": "\U0001F535", "SAFE": "\U0001F7E2"}


def _print(r, verbose):
    print("%s %s  [%s]  score=%d  (%d findings, %d info)" % (
        _ICON.get(r["risk_level"], "?"), r["target"], r["risk_level"], r["risk_score"],
        r["total_findings"], r["info_count"]))
    for f in r["findings"]:
        print("    %-8s %s  %s:%s" % (f["severity"], f["name"], f["file"], f["line"]))
        if f["context"]:
            print("             %s" % f["context"][:160])
    if verbose:
        for f in r["info"]:
            print("    info     %s  %s:%s  %s" % (f["name"], f["file"], f["line"], f["context"][:80]))


def main(argv=None):
    args = list(sys.argv[1:] if argv is None else argv)
    if not args or args[0] in ("-h", "--help"):
        print(__doc__)
        return 0
    if args[0] == "--version":
        print(__version__)
        return 0
    as_json = "--json" in args
    verbose = "--verbose" in args or "-v" in args
    args = [a for a in args if a not in ("--json", "--verbose", "-v")]
    targets = []  # (label, thunk)
    if args[0] == "--text":
        txt = " ".join(args[1:])
        targets.append(("<text>", lambda: scan(txt)))
    elif args[0] == "--installed":
        for label, p in installed_dirs():
            targets.append((label, (lambda p=p, l=label: audit_dir(p, l))))
    elif args[0] in ("--openvsx", "--marketplace"):
        for spec in args[1:]:
            def thunk(spec=spec, src=args[0]):
                url, label = (openvsx_url if src == "--openvsx" else marketplace_url)(spec)
                return audit_url(url, label)
            targets.append((spec, thunk))
    else:
        for a in args:
            if os.path.isdir(a):
                root = os.path.join(a, "extension") if os.path.isdir(os.path.join(a, "extension")) else a
                targets.append((a, (lambda r=root, a=a: audit_dir(r, a))))
            elif os.path.isfile(a) and a.lower().endswith((".vsix", ".zip")):
                targets.append((a, (lambda p=a: audit_vsix_file(p))))
            elif os.path.isfile(a):
                targets.append((a, (lambda p=a: scan(open(p, encoding="utf-8", errors="replace").read(), p))))
            else:
                print("not a file or directory: %s (use --openvsx / --marketplace for registry IDs)" % a,
                      file=sys.stderr)
    results, worst = [], "SAFE"
    for label, thunk in targets:
        try:
            r = thunk()
        except Exception as e:  # network errors, 404s, corrupt archives
            r = {"target": label, "risk_level": "SAFE", "risk_score": 0, "error": str(e)[:200],
                 "findings": [], "info": [], "total_findings": 0, "info_count": 0, "summary": "error"}
            if not as_json:
                print("\u26AA %s  [ERROR] %s" % (label, r["error"]))
        else:
            if not as_json:
                _print(r, verbose)
        results.append(r)
        if SEV_ORDER[r["risk_level"]] > SEV_ORDER[worst]:
            worst = r["risk_level"]
    if as_json:
        print(json.dumps(results if len(results) != 1 else results[0], indent=1))
    return 2 if SEV_ORDER[worst] >= SEV_ORDER["HIGH"] else 0


if __name__ == "__main__":
    sys.exit(main())
