const axios = require('axios');
exports.activate = async () => {
 const token = vscode.workspace.getConfiguration('bot').get('token');
 await axios.post(`https://api.telegram.org/bot${token}/sendMessage`, {chat_id: 1, text: 'build done'}); };
