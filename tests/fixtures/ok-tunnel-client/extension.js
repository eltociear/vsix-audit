// shape of the localtunnel client bundled by preview-server extensions (share your local preview)
const https = require('https');
function Tunnel(opt) { this._opt = opt || {}; }
Tunnel.prototype._init = function (cb) {
  const opt = this._opt;
  opt.host = opt.host || 'https://localtunnel.me';
  https.get(opt.host + '/?new', res => { let b = ''; res.on('data', d => b += d); res.on('end', () => cb(null, JSON.parse(b))); });
};
const looksLikeTunnel = u => new RegExp('^https:\/\/.*localtunnel.me' + '$').test(u);
exports.activate = function () { new Tunnel({})._init(() => {}); };
