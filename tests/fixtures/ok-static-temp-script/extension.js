// a fixed helper script written to the temp dir and run (process detection); the network call
// nearby is the extension's own API, and nothing downloaded is written or executed.
const fs = require('fs'), os = require('os'), path = require('path'), cp = require('child_process'), https = require('https');
function detect(cb) {
  const tmpScript = path.join(os.tmpdir(), '_ls_detect.ps1');
  fs.writeFileSync(tmpScript, "Get-CimInstance Win32_Process | Select-Object ProcessId,CommandLine | ConvertTo-Json");
  cp.exec('powershell -NoProfile -ExecutionPolicy Bypass -File "' + tmpScript + '"', cb);
}
function report(x) { https.request({ host: 'api.example.com', method: 'POST' }).end(JSON.stringify(x)); }
exports.activate = function () { detect((e, out) => report({ n: (out || '').length })); };
