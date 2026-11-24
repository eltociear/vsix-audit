var pkg={scripts:{"publish:ovsx":"bun run bundle && bunx ovsx publish -p $OVSX_TOKEN",release:"semantic-release"}};
exports.activate=()=>pkg.scripts;
