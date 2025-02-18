const axios = require('axios');

module.exports.checkXSS = async (url) => {
  try {
    const testPayload = '<script>alert("XSS")</script>';
    const response = await axios.get(`${url}?q=${encodeURIComponent(testPayload)}`);
    
    const vulnerabilities = [];
    if (response.data.includes(testPayload)) {
      vulnerabilities.push({
        name: 'Potential XSS Vulnerability',
        description: 'Unsanitized user input detected in response',
        severity: 'High',
        prevention: [
          "Sanitize all user inputs using libraries like DOMPurify",
          "Use Content Security Policy (CSP) headers",
          "Escape special characters in HTML, JavaScript, and CSS contexts"
        ]
      });
    }
    
    return vulnerabilities;
  } catch (error) {
    return [];
  }
};
