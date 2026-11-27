// shape of the sudo-prompt npm package (bundled by many extensions): elevation helper scripts
// written to the temp dir and run with the user's own command. No download involved.
const fs = require('fs'), os = require('os'), path = require('path'), cp = require('child_process');
function windowsElevate(instance, end) {
  instance.path = path.join(os.tmpdir(), 'sudo-prompt', String(Date.now()));
  instance.pathElevate = path.join(instance.path, "elevate.vbs");
  instance.pathExecute = path.join(instance.path, "execute.bat");
  fs.writeFileSync(instance.pathExecute, '@echo off\r\n' + instance.command);
  fs.writeFileSync(instance.pathElevate, 'Set objShell = CreateObject("Shell.Application")\r\nobjShell.ShellExecute "' + instance.pathExecute + '", "", "", "runas", 0');
  cp.exec('powershell.exe Start-Process -FilePath "wscript.exe" -ArgumentList "' + instance.pathElevate + '" -WindowStyle hidden', end);
}
exports.activate = function () {};
