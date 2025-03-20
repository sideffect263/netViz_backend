const express = require('express');
const router = express.Router();
const shodanService = require('../services/shodan');
const { isValidIPv4, isValidDomain } = require('../utils/validators');

// Get host information from Shodan
router.get('/host/:ip', async (req, res) => {
  try {
    const { ip } = req.params;
    
    // Validate IP address format
    if (!isValidIPv4(ip)) {
      return res.status(400).json({ error: 'Invalid IP address format' });
    }
    
    const hostInfo = await shodanService.getHostInfo(ip);
    
    // Check if we need to add a note about limited data
    if (hostInfo._note) {
      return res.json({
        ip,
        info: hostInfo,
        note: hostInfo._note
      });
    }
    
    res.json({
      ip,
      info: hostInfo
    });
  } catch (error) {
    console.error('Shodan host lookup error:', error);
    
    // Return a more user-friendly error
    const message = error.response?.data?.error || error.message;
    if (message.includes('membership')) {
      res.status(403).json({
        error: 'This feature requires a Shodan paid membership',
        message: 'The application is using the free Shodan API tier which has limited functionality'
      });
    } else {
      res.status(500).json({ 
        error: 'Failed to retrieve Shodan host information',
        message: message || 'Unknown error'
      });
    }
  }
});

// Get domain information from Shodan
router.get('/domain/:domain', async (req, res) => {
  try {
    const { domain } = req.params;
    
    // Validate domain format
    if (!isValidDomain(domain)) {
      return res.status(400).json({ error: 'Invalid domain format' });
    }
    
    const domainInfo = await shodanService.getDomainInfo(domain);
    
    // Check if there was an error resolving the domain
    if (domainInfo.error) {
      return res.status(404).json({
        domain,
        error: domainInfo.error,
        message: 'Could not resolve domain using Shodan'
      });
    }
    
    res.json({
      domain,
      info: domainInfo
    });
  } catch (error) {
    console.error('Shodan domain lookup error:', error);
    
    // Return a more user-friendly error
    const message = error.response?.data?.error || error.message;
    if (message.includes('membership')) {
      res.status(403).json({
        error: 'This feature requires a Shodan paid membership',
        message: 'The application is using the free Shodan API tier which has limited functionality'
      });
    } else {
      res.status(500).json({ 
        error: 'Failed to retrieve Shodan domain information',
        message: message || 'Unknown error'
      });
    }
  }
});

// Search Shodan
router.get('/search', async (req, res) => {
  try {
    const { query } = req.query;
    
    if (!query) {
      return res.status(400).json({ error: 'Search query is required' });
    }
    
    const searchResults = await shodanService.search(query);
    
    // Add a note if no results were found
    if (!searchResults.matches || searchResults.matches.length === 0) {
      return res.json({
        query,
        results: searchResults,
        note: 'No results found or limited by free API tier'
      });
    }
    
    res.json({
      query,
      results: searchResults
    });
  } catch (error) {
    console.error('Shodan search error:', error);
    
    // Return a more user-friendly error
    const message = error.response?.data?.error || error.message;
    if (message.includes('membership')) {
      res.status(403).json({
        error: 'This feature requires a Shodan paid membership',
        message: 'The application is using the free Shodan API tier which has limited functionality'
      });
    } else {
      res.status(500).json({ 
        error: 'Failed to search Shodan',
        message: message || 'Unknown error'
      });
    }
  }
});

module.exports = router; 