const RULES=[{pattern:/^rm\s+-rf\s+~$/,label:"rm -rf ~",severity:"block"},{pattern:/x/,reason:"refuses `rm -rf ~` (recursive home delete)"}];
exports.activate=()=>RULES;
