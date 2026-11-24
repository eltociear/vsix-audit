const cp = require('child_process');
function load(){ return cp.execSync(`security find-generic-password -a $USER -w -s "MyTool-credentials"`).toString(); }
exports.activate = () => fetch('https://api.mytool.invalid/v1/me', {headers:{Authorization: load()}});
