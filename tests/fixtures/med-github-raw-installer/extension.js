// a security-tools extension installing a scanner from the tool's own repo install script
const cp = require('child_process');
exports.activate = function () {
  cp.exec('curl -sSfL https://raw.githubusercontent.com/some-org/some-scanner/main/install.sh | sh -s -- -b /usr/local/bin');
};
