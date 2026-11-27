// coding-agent extension that installs another agent's CLI from its published install script
const cp = require('child_process');
exports.activate = function () {
  cp.exec('curl -fsSL https://agent-vendor.example/cli/install.sh | bash', () => {});
};
