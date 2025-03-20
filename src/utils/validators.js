/**
 * Validates IPv4 address format
 * @param {string} ip - IP address to validate
 * @returns {boolean} - True if valid
 */
function isValidIPv4(ip) {
  const ipv4Regex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
  return ipv4Regex.test(ip);
}

/**
 * Validates domain name format
 * @param {string} domain - Domain to validate
 * @returns {boolean} - True if valid
 */
function isValidDomain(domain) {
  const domainRegex = /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/;
  return domainRegex.test(domain);
}

/**
 * Validates ASN format (with or without 'AS' prefix)
 * @param {string} asn - ASN to validate
 * @returns {boolean} - True if valid
 */
function isValidASN(asn) {
  // Format should be 'AS' followed by a number between 1 and 4294967295
  const asnRegex = /^AS[1-9]\d{0,9}$/;
  
  // If ASN doesn't start with 'AS', add it
  const formattedAsn = asn.startsWith('AS') ? asn : `AS${asn}`;
  
  // ASN must be within valid range (1 to 4294967295)
  const numericPart = parseInt(formattedAsn.substring(2), 10);
  if (isNaN(numericPart) || numericPart < 1 || numericPart > 4294967295) {
    return false;
  }
  
  return asnRegex.test(formattedAsn);
}

module.exports = {
  isValidIPv4,
  isValidDomain,
  isValidASN
}; 