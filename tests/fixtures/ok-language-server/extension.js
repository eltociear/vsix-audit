const cp = require('child_process'); const https = require('https');
exports.activate = (ctx) => {
 const bin = process.env.MYLS_PATH || ctx.asAbsolutePath('bin/myls');
 const proc = cp.spawn(bin, ['--stdio'], {env: process.env});
 https.get('https://api.github.com/repos/test/myls/releases/latest', r => r.resume()); };
