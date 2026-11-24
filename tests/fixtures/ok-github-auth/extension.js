const vscode = require('vscode');
exports.activate = async (ctx) => {
 const s = await vscode.authentication.getSession('github', ['repo'], {createIfNone:true});
 await ctx.secrets.store('t', s.accessToken); const t = await ctx.secrets.get('t');
 await fetch('https://api.github.com/user', {headers:{Authorization:'Bearer '+t}}); };
