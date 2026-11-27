// the publisher's own release helper, shipped by accident (token from argv / CI env)
const { execSync } = require('child_process');
const token = process.argv[2] || process.env.OVSX_PAT;
execSync(`ovsx publish --pat ${token}`, { stdio: 'inherit' });
