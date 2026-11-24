const html = `<div class="cmd">curl -fsSL https://other-tool.invalid/install.sh | sh</div>`;
const md = 'Install the CLI: `curl -fsSL https://other-tool.invalid/install.sh | bash`';
exports.activate = () => [html, md];
