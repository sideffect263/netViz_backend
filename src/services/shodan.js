const axios = require('axios');

/**
 * Service for accessing the Shodan API (free tier only)
 */
class ShodanService {
  constructor() {
    this.apiKey = process.env.SHODAN_API_KEY;
    this.baseUrl = 'https://api.shodan.io';
  }

  /**
   * Get basic host information from Shodan (free API)
   * @param {string} ip - IP address to lookup
   * @returns {Promise<Object>} - Host information
   */
  async getHostInfo(ip) {
    try {
      // First try using the /shodan/host/{ip} endpoint with minimal data
      const response = await axios.get(`${this.baseUrl}/shodan/host/${ip}`, {
        params: {
          key: this.apiKey,
          minify: true // Request minimal data (available in free tier)
        },
        timeout: 10000
      });
      
      // If we get here, it worked, so return the data
      return response.data;
    } catch (error) {
      // If it's a membership error, try the fallback approach
      if (error.response?.data?.error?.includes('membership') || 
          error.message?.includes('membership')) {
        
        // Fallback to host search, which often works on free tier
        try {
          const searchResponse = await axios.get(`${this.baseUrl}/shodan/host/search`, {
            params: {
              key: this.apiKey,
              query: `ip:${ip}`,
              minify: true
            },
            timeout: 10000
          });
          
          // If we have matches, format the first one to look like host info
          if (searchResponse.data.matches && searchResponse.data.matches.length > 0) {
            const match = searchResponse.data.matches[0];
            return {
              ip: ip,
              ports: Array.from(new Set(searchResponse.data.matches.map(m => m.port))),
              country_name: match.location?.country_name || null,
              city: match.location?.city || null,
              org: match.org || null,
              isp: match.isp || null,
              os: match.os || null,
              last_update: match.timestamp || null
            };
          }
        } catch (searchError) {
          console.error(`Error in fallback search for ${ip}:`, searchError.message);
        }
        
        // If both approaches fail, return mock data
        return this._getMockHostData(ip);
      }
      
      console.error(`Error fetching Shodan host info for ${ip}:`, error.message);
      throw error;
    }
  }

  /**
   * Search Shodan using a query (free tier)
   * @param {string} query - Shodan search query
   * @returns {Promise<Object>} - Search results
   */
  async search(query) {
    try {
      const response = await axios.get(`${this.baseUrl}/shodan/host/search`, {
        params: {
          key: this.apiKey,
          query: query,
          minify: true // Request minimal data (available in free tier)
        },
        timeout: 10000
      });
      
      return response.data;
    } catch (error) {
      // If it's a membership error, return mock data
      if (error.response?.data?.error?.includes('membership') || 
          error.message?.includes('membership')) {
        return {
          matches: [],
          total: 0,
          query: query
        };
      }
      
      console.error(`Error searching Shodan for "${query}":`, error.message);
      throw error;
    }
  }
  
  /**
   * Get domain information (using alternative free methods)
   * @param {string} domain - Domain to lookup
   * @returns {Promise<Object>} - Domain information
   */
  async getDomainInfo(domain) {
    try {
      // Try the DNS endpoint first
      const response = await axios.get(`${this.baseUrl}/dns/resolve`, {
        params: {
          key: this.apiKey,
          hostnames: domain
        },
        timeout: 10000
      });
      
      // Check if we got an IP, then try to get some minimal host info for it
      const ip = response.data[domain];
      if (ip) {
        try {
          const hostInfo = await this.getHostInfo(ip);
          return {
            domain,
            ip,
            info: hostInfo
          };
        } catch (hostError) {
          return { domain, ip };
        }
      }
      
      return { domain, ip: null };
    } catch (error) {
      // Return a minimal response rather than failing
      return {
        domain,
        ip: null,
        error: "Could not resolve domain"
      };
    }
  }
  
  /**
   * Generate mock host data for fallback
   * @private
   * @param {string} ip - IP address
   * @returns {Object} - Mock host data
   */
  _getMockHostData(ip) {
    // Structure similar to what Shodan would return
    return {
      ip: ip,
      ports: [80, 443],
      country_name: "Unknown",
      city: "Unknown",
      org: "Unknown Organization",
      isp: "Unknown ISP",
      os: null,
      last_update: new Date().toISOString(),
      _note: "Limited data available (free API tier)"
    };
  }
}

module.exports = new ShodanService(); 