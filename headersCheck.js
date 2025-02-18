const axios = require('axios');

const requiredHeaders = [
  'Content-Security-Policy',
  'X-Content-Type-Options',
  'X-Frame-Options',
  'Strict-Transport-Security'
];

const headerPreventions = {
  'Content-Security-Policy': [
    "Set Content-Security-Policy header with a strict policy",
    "Restrict unsafe inline scripts and eval",
    "Specify trusted sources for all content types"
  ],
  'X-Content-Type-Options': [
    "Set X-Content-Type-Options header to 'nosniff'",
    "Ensure MIME types are correctly specified"
  ],
  'X-Frame-Options': [
    "Set X-Frame-Options header to 'DENY' or 'SAMEORIGIN'",
    "Prevent page from being embedded in frames"
  ],
  'Strict-Transport-Security': [
    "Enable Strict-Transport-Security with max-age of at least 31536000",
    "Include includeSubDomains and preload directives"
  ]
};

module.exports.checkSecurityHeaders = async (url) => {
  try {
    const response = await axios.head(url);
    const missingHeaders = requiredHeaders.filter(
      header => !response.headers[header.toLowerCase()]
    );

    return missingHeaders.map(header => ({
      name: `Missing Security Header: ${header}`,
      description: `The ${header} security header is missing`,
      severity: header === 'Strict-Transport-Security' ? 'High' : 'Medium',
      prevention: headerPreventions[header] || []
    }));
  } catch (error) {
    return [];
  }
};
