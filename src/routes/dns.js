const express = require('express');
const router = express.Router();
const dns = require('dns').promises;
const whois = require('whois-json');

// Get DNS information for a domain
router.get('/:domain', async (req, res) => {
  try {
    const { domain } = req.params;
    
    // Validate domain
    if (!domain || !domain.match(/^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/)) {
      return res.status(400).json({ error: 'Invalid domain format' });
    }

    // Get A records (IPv4 addresses)
    const ipAddresses = await dns.resolve4(domain);
    
    // Get MX records
    const mxRecords = await dns.resolveMx(domain).catch(() => []);
    
    // Get NS records
    const nsRecords = await dns.resolveNs(domain).catch(() => []);
    
    // Get TXT records
    const txtRecords = await dns.resolveTxt(domain).catch(() => []);
    
    // Get CNAME records
    const cnameRecords = await dns.resolveCname(domain).catch(() => []);
    
    // WHOIS information
    let whoisData = {};
    try {
      whoisData = await whois(domain);
    } catch (error) {
      console.error('WHOIS error:', error);
      whoisData = { error: 'Failed to retrieve WHOIS data' };
    }

    res.json({
      domain,
      ipAddresses,
      mxRecords,
      nsRecords,
      txtRecords: txtRecords.map(txt => txt.join(' ')),
      cnameRecords,
      whois: whoisData
    });
  } catch (error) {
    console.error('DNS lookup error:', error);
    res.status(500).json({ 
      error: 'Failed to retrieve DNS information',
      message: error.message
    });
  }
});

// Get reverse DNS (PTR) for an IP address
router.get('/ptr/:ip', async (req, res) => {
  try {
    const { ip } = req.params;
    
    // Simple IP validation
    if (!ip.match(/^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/)) {
      return res.status(400).json({ error: 'Invalid IP address format' });
    }
    
    const hostnames = await dns.reverse(ip);
    
    res.json({
      ip,
      hostnames
    });
  } catch (error) {
    console.error('Reverse DNS lookup error:', error);
    res.status(500).json({ 
      error: 'Failed to retrieve reverse DNS information',
      message: error.message
    });
  }
});

module.exports = router; 