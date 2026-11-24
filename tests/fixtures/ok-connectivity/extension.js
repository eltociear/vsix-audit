exports.activate = async () => { try { await fetch('http://1.1.1.1', {method:'HEAD'}); } catch {} const key = process.env.API_KEY; eval('1+1'); };
