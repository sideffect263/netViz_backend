/**
 * Utility functions for input validation
 */

/**
 * Check if a string is a valid domain name
 * @param {string} domain - Domain to validate
 * @returns {boolean} - True if valid domain
 */
exports.isValidDomain = (domain) => {
  if (!domain) return false;
  
  // Basic domain validation regex
  // Matches domain names like example.com, sub.example.co.uk, etc.
  const domainRegex = /^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]$/i;
  return domainRegex.test(domain);
};

/**
 * Check if a string is a valid IPv4 address
 * @param {string} ip - IP address to validate
 * @returns {boolean} - True if valid IPv4
 */
exports.isValidIPv4 = (ip) => {
  if (!ip) return false;
  
  // IPv4 validation regex
  // Matches IP addresses like 192.168.1.1
  const ipv4Regex = /^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(ip);
};

/**
 * Check if a string is a valid IPv6 address
 * @param {string} ip - IP address to validate
 * @returns {boolean} - True if valid IPv6
 */
exports.isValidIPv6 = (ip) => {
  if (!ip) return false;
  
  // IPv6 validation regex
  // This is a simplified version, full IPv6 validation is complex
  const ipv6Regex = /^(([0-9a-fA-F]{1,4}:){7}[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,7}:|([0-9a-fA-F]{1,4}:){1,6}:[0-9a-fA-F]{1,4}|([0-9a-fA-F]{1,4}:){1,5}(:[0-9a-fA-F]{1,4}){1,2}|([0-9a-fA-F]{1,4}:){1,4}(:[0-9a-fA-F]{1,4}){1,3}|([0-9a-fA-F]{1,4}:){1,3}(:[0-9a-fA-F]{1,4}){1,4}|([0-9a-fA-F]{1,4}:){1,2}(:[0-9a-fA-F]{1,4}){1,5}|[0-9a-fA-F]{1,4}:((:[0-9a-fA-F]{1,4}){1,6})|:((:[0-9a-fA-F]{1,4}){1,7}|:)|fe80:(:[0-9a-fA-F]{0,4}){0,4}%[0-9a-zA-Z]+|::(ffff(:0{1,4})?:)?((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9])|([0-9a-fA-F]{1,4}:){1,4}:((25[0-5]|(2[0-4]|1?[0-9])?[0-9])\.){3}(25[0-5]|(2[0-4]|1?[0-9])?[0-9]))$/;
  return ipv6Regex.test(ip);
};

/**
 * Check if a target is either a valid domain or IP address
 * @param {string} target - Target to validate
 * @returns {boolean} - True if valid target
 */
exports.isValidTarget = (target) => {
  return (
    exports.isValidDomain(target) || 
    exports.isValidIPv4(target) || 
    exports.isValidIPv6(target)
  );
};

/**
 * Sanitize user input to prevent command injection
 * @param {string} input - User input to sanitize
 * @returns {string} - Sanitized input
 */
exports.sanitizeInput = (input) => {
  if (!input) return '';
  
  // Remove any characters that could be used for command injection
  return input.replace(/[;&|`\'"\\]/g, '');
}; 