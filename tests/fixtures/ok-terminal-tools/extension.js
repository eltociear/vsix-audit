const cp = require('child_process');
exports.activate = () => {
 // docs: install with `curl -fsSL https://get.example.invalid | sh` - shown to the user, never run
 const help = 'Run: npm install -g mytool';
 cp.execSync('git rev-parse HEAD'); };
