const axios = require('axios');

module.exports.checkSQLi = async (url) => {
  try {
    const testPayload = "' OR '1'='1";
    const response = await axios.get(`${url}?id=${encodeURIComponent(testPayload)}`);
    
    const vulnerabilities = [];
    if (response.data.toLowerCase().includes('sql syntax')) {
      vulnerabilities.push({
        name: 'Potential SQL Injection',
        description: 'Possible SQL injection vulnerability detected',
        severity: 'Critical',
        prevention: [
          "Use parameterized queries or prepared statements",
          "Implement proper input validation and sanitization",
          "Utilize ORM frameworks for database interactions",
          "Avoid constructing SQL queries with string concatenation"
        ]
      });
    }
    
    return vulnerabilities;
  } catch (error) {
    return [];
  }
};