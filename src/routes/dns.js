const express = require('express');
const router = express.Router();
const dns = require('dns').promises;
const whois = require('whois-json');
const cache = require('../utils/cache');
const axios = require('axios');

// Function to determine network CIDR from IP
const getNetworkInfo = (ip) => {
  try {
    // Only process IPv4 addresses for now
    if (!ip.includes(':')) {
      const parts = ip.split('.');
      // Simple Class A, B, C determination
      if (parts[0] < 128) {
        return { cidr: `${parts[0]}.0.0.0/8`, class: 'A' };
      } else if (parts[0] < 192) {
        return { cidr: `${parts[0]}.${parts[1]}.0.0/16`, class: 'B' };
      } else {
        return { cidr: `${parts[0]}.${parts[1]}.${parts[2]}.0/24`, class: 'C' };
      }
    } else {
      // Return a placeholder for IPv6
      return { cidr: `${ip}/128`, class: 'IPv6' };
    }
  } catch (e) {
    console.error('Error determining network info:', e);
    return { cidr: 'Unknown', class: 'Unknown' };
  }
};

// Get DNS information for a domain
router.get('/:domain', async (req, res) => {
  try {
    const { domain } = req.params;
    
    // Validate domain
    if (!domain || !domain.match(/^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+$/)) {
      return res.status(400).json({ error: 'Invalid domain format' });
    }

    // Check cache first
    const cacheKey = `dns:${domain}`;
    const cachedData = cache.get(cacheKey);
    
    if (cachedData) {
      // Add cache indicator to response headers
      res.setHeader('X-Cache', 'HIT');
      return res.json(cachedData);
    }
    
    // Set cache miss header
    res.setHeader('X-Cache', 'MISS');

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

    // Process IP addresses to add network info
    const ipAddressesWithNetInfo = ipAddresses.map(ip => {
      const netInfo = getNetworkInfo(ip);
      return {
        ip,
        network: netInfo.cidr,
        class: netInfo.class
      };
    });

    const result = {
      domain,
      ipAddresses,
      ipDetails: ipAddressesWithNetInfo,
      mxRecords,
      nsRecords,
      txtRecords: txtRecords.map(txt => txt.join(' ')),
      cnameRecords,
      whois: whoisData,
      timestamp: new Date().toISOString()
    };
    
    // Store result in cache
    cache.set(cacheKey, result);

    res.json(result);
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
    
    // Check cache first
    const cacheKey = `ptr:${ip}`;
    const cachedData = cache.get(cacheKey);
    
    if (cachedData) {
      res.setHeader('X-Cache', 'HIT');
      return res.json(cachedData);
    }
    
    res.setHeader('X-Cache', 'MISS');
    
    const hostnames = await dns.reverse(ip);
    
    const result = {
      ip,
      hostnames,
      timestamp: new Date().toISOString()
    };
    
    // Store in cache
    cache.set(cacheKey, result);
    
    res.json(result);
  } catch (error) {
    console.error('Reverse DNS lookup error:', error);
    res.status(500).json({ 
      error: 'Failed to retrieve reverse DNS information',
      message: error.message
    });
  }
});

// Add a new endpoint to get cache statistics
router.get('/cache/stats', (req, res) => {
  res.json(cache.getStats());
});

// Add an endpoint to clear the cache
router.post('/cache/clear', (req, res) => {
  cache.clear();
  res.json({ success: true, message: 'Cache cleared successfully' });
});

module.exports = router; 