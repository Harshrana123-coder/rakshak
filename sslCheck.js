module.exports.checkSSL = (url) => new Promise((resolve) => {
  const hostname = new URL(url).hostname;
  
  // Fast TLS version check only
  exec(`openssl s_client -connect ${hostname}:443 -tls1_2 2>&1 | grep 'Protocol'`, (error, stdout) => {
    if (error || !stdout.includes('TLSv1.2')) {
      resolve([{
        name: 'Insecure TLS Version',
        description: 'Server does not support modern TLS 1.2 protocol',
        severity: 'High',
        prevention: [
          "Upgrade to TLS 1.2 or higher",
          "Disable support for TLS 1.0 and 1.1",
          "Use tools like SSL Labs to test your configuration"
        ]
      }]);
    } else {
      resolve([]);
    }
  });
});