// shape of the monaco / AMD loader bundled in webviews: fetch a module of the package itself and evaluate it
function load(o, n, s) {
  fetch(o, { credentials: "same-origin" }).then(e => { if (!e.ok) throw new Error(e.statusText); return e.text(); })
    .then(t => { t = `${t}\n//# sourceURL=${o}`; (new Function(t)).call(self); n(); }).then(void 0, s);
}
exports.activate = function () { load('./vs/editor/editor.main.js', () => {}, () => {}); };
