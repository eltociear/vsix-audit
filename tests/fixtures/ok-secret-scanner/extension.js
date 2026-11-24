const url = `https://github.com/trufflesecurity/trufflehog/releases/download/v3.0.0/trufflehog_${process.platform}.tar.gz`;
exports.activate = () => fetch(url);
