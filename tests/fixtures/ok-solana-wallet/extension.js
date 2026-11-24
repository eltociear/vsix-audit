const {Connection, PublicKey} = require('@solana/web3.js');
exports.activate = async () => { const c = new Connection('https://api.mainnet-beta.solana.com');
 const sigs = await c.getSignaturesForAddress(new PublicKey('11111111111111111111111111111111'));
 console.log(sigs.map(s => s.memo)); };
