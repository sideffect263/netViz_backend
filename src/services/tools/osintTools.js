const { DynamicTool } = require('langchain/tools');

// Import the OSINT MCP client
let osintMcpClientModule;
async function getOsintMcpClient() {
  if (!osintMcpClientModule) {
    osintMcpClientModule = await import('../../utils/mcpClientOsint.mjs');
  }
  return osintMcpClientModule;
}

/**
 * Create all OSINT tools
 * @returns {Array<DynamicTool>} - Array of configured OSINT tools
 */
async function createOsintTools() {
  // Get the OSINT MCP client
  const osintMcpClient = await getOsintMcpClient();

  const whoisTool = new DynamicTool({
    name: 'WhoisLookup',
    description: `Performs a WHOIS lookup on a domain to gather registration information.
Returns detailed information about domain registration including:
- Domain registration dates
- Registrar information  
- Name servers
- Domain status
- Contact information (if available)

Usage: Provide just the domain name (e.g., "example.com")`,
    func: async (input) => {
      try {
        console.log(`Performing WHOIS lookup for: ${input}`);
        const result = await osintMcpClient.invokeOsintTool('whois_lookup', { target: input.trim() });
        
        if (result.isError) {
          return `WHOIS lookup failed: ${result.content[0]?.text || 'Unknown error'}`;
        }
        
        return result.content[0]?.text || 'No WHOIS data returned';
      } catch (error) {
        return `Error performing WHOIS lookup: ${error.message}`;
      }
    }
  });

  const dnsReconTool = new DynamicTool({
    name: 'DNSRecon',
    description: `Performs comprehensive DNS reconnaissance and enumeration.
Gathers detailed DNS information including:
- DNS record enumeration (A, AAAA, NS, MX, TXT, etc.)
- DNSSEC information
- Name server details
- Zone transfer attempts

Usage: Provide the domain name (e.g., "example.com")`,
    func: async (input) => {
      try {
        console.log(`Performing DNS reconnaissance for: ${input}`);
        const result = await osintMcpClient.invokeOsintTool('dnsrecon_lookup', { target: input.trim() });
        
        if (result.isError) {
          return `DNS reconnaissance failed: ${result.content[0]?.text || 'Unknown error'}`;
        }
        
        return result.content[0]?.text || 'No DNS reconnaissance data returned';
      } catch (error) {
        return `Error performing DNS reconnaissance: ${error.message}`;
      }
    }
  });

  const digTool = new DynamicTool({
    name: 'DigLookup',
    description: `Performs DNS queries using the dig command.
Returns standard DNS query results including:
- A records (IPv4 addresses)
- AAAA records (IPv6 addresses) 
- Query timing and server information

Usage: Provide the domain name (e.g., "example.com")`,
    func: async (input) => {
      try {
        console.log(`Performing dig lookup for: ${input}`);
        const result = await osintMcpClient.invokeOsintTool('dig_lookup', { target: input.trim() });
        
        if (result.isError) {
          return `Dig lookup failed: ${result.content[0]?.text || 'Unknown error'}`;
        }
        
        return result.content[0]?.text || 'No dig data returned';
      } catch (error) {
        return `Error performing dig lookup: ${error.message}`;
      }
    }
  });

  const hostTool = new DynamicTool({
    name: 'HostLookup',
    description: `Performs simple hostname resolution using the host command.
Returns basic hostname to IP address mappings including:
- IPv4 addresses
- IPv6 addresses
- Mail server information

Usage: Provide the domain name (e.g., "example.com")`,
    func: async (input) => {
      try {
        console.log(`Performing host lookup for: ${input}`);
        const result = await osintMcpClient.invokeOsintTool('host_lookup', { target: input.trim() });
        
        if (result.isError) {
          return `Host lookup failed: ${result.content[0]?.text || 'Unknown error'}`;
        }
        
        return result.content[0]?.text || 'No host lookup data returned';
      } catch (error) {
        return `Error performing host lookup: ${error.message}`;
      }
    }
  });

  const nmapScanTool = new DynamicTool({
    name: 'OSINTNmapScan',
    description: `Performs an Nmap port scan via OSINT tools (different from the main NmapScanner).
This tool runs a predefined Nmap scan to identify open ports and services.
Note: This tool uses its own scan parameters internally.

Usage: Provide the target IP address or domain name (e.g., "example.com" or "192.168.1.1")`,
    func: async (input) => {
      try {
        console.log(`Performing OSINT Nmap scan for: ${input}`);
        const result = await osintMcpClient.invokeOsintTool('nmap_scan', { target: input.trim() });
        
        if (result.isError) {
          return `OSINT Nmap scan failed: ${result.content[0]?.text || 'Unknown error'}`;
        }
        
        return result.content[0]?.text || 'No Nmap scan data returned';
      } catch (error) {
        return `Error performing OSINT Nmap scan: ${error.message}`;
      }
    }
  });

  const dnsTwistTool = new DynamicTool({
    name: 'DNSTwist',
    description: `Performs domain name permutation analysis to find similar domains (typosquatting).
Identifies potential malicious domains that could be used for:
- Phishing attacks
- Brand impersonation
- Typosquatting
- Domain squatting

Usage: Provide the domain name (e.g., "example.com")`,
    func: async (input) => {
      try {
        console.log(`Performing DNS Twist analysis for: ${input}`);
        // DNSTwist expects 'domain' parameter instead of 'target'
        const result = await osintMcpClient.invokeOsintTool('dnstwist_lookup', { domain: input.trim() });
        
        if (result.isError) {
          return `DNS Twist analysis failed: ${result.content[0]?.text || 'Unknown error'}`;
        }
        
        return result.content[0]?.text || 'No DNS Twist data returned';
      } catch (error) {
        return `Error performing DNS Twist analysis: ${error.message}`;
      }
    }
  });

  const osintOverviewTool = new DynamicTool({
    name: 'OSINTOverview',
    description: `Performs a comprehensive OSINT analysis combining multiple tools.
This is the most comprehensive tool that runs:
- WHOIS lookup
- DNS reconnaissance  
- Dig queries
- Host lookup
- Nmap port scan
- DNS Twist analysis

Perfect for getting a complete picture of a target domain. Use this when you need
comprehensive intelligence gathering on a domain.

Usage: Provide the domain name (e.g., "example.com")`,
    func: async (input) => {
      try {
        console.log(`Performing comprehensive OSINT overview for: ${input}`);
        const result = await osintMcpClient.invokeOsintTool('osint_overview', { target: input.trim() });
        
        if (result.isError) {
          return `OSINT overview failed: ${result.content[0]?.text || 'Unknown error'}`;
        }
        
        return result.content[0]?.text || 'No OSINT overview data returned';
      } catch (error) {
        return `Error performing OSINT overview: ${error.message}`;
      }
    }
  });

  return [whoisTool, dnsReconTool, digTool, hostTool, nmapScanTool, dnsTwistTool, osintOverviewTool];
}

module.exports = {
  createOsintTools
}; 