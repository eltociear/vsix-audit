const addon = require('./build/addon.node');
exports.activate = () => addon.init();
