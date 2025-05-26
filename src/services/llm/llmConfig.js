const { ChatAnthropic } = require('@langchain/anthropic');
const fs = require('fs');
const path = require('path');

// Load documentation for context enhancement
let documentationCache = null;

function loadDocumentation() {
  if (documentationCache) return documentationCache;
  
  try {
    // Try to load from documentation file
    const docsPath = path.join(__dirname, '../../../docs/agent_documentation.md');
    if (fs.existsSync(docsPath)) {
      const docContent = fs.readFileSync(docsPath, 'utf8');
      documentationCache = docContent;
      return docContent;
    }
    
    // If no specific doc file exists, provide default documentation
    documentationCache = `
# NetViz AI Agent Documentation

## Purpose and Overview
NetViz AI Agent is an intelligent assistant that helps with network scanning, analysis, and security tasks. It combines the power of AI with network tools like Nmap to provide useful insights in a conversational interface.

## Scan Capabilities
- **Quick Scan**: Fast scan of common ports using optimized parameters
   Details: Uses -T4 -F flags to quickly identify the most common open ports on a target
   Example: "run a quick scan on example.com"

- **Service Scan**: Detailed scan that identifies running services on open ports
   Details: Uses -sV flag to detect service versions running on the target system
   Example: "scan for services on 192.168.1.1"

- **Full Port Scan**: Comprehensive scan of all 65535 ports
   Details: May take longer but provides complete coverage of all possible ports
   Example: "run a comprehensive port scan on example.com"

- **Vulnerability Scan**: Identifies potential security vulnerabilities on the target
   Details: Combines service detection with vulnerability checks
   Example: "check for vulnerabilities on example.com"

## General Capabilities
- Network scanning and enumeration of hosts, ports, and services
- Service identification and version detection
- OS detection and fingerprinting
- Security vulnerability assessment
- Intelligent analysis of scan results
- Conversational interface for network security tasks
- Explanation of technical findings in plain language

## Technical Architecture
NetViz uses a client-server architecture where the React frontend communicates with a Node.js backend. The backend integrates with Nmap through a custom MCP (Model Context Protocol) client that securely manages scan operations. LangChain orchestrates the AI agent's reasoning and tool usage.

## Key Components
- **AI Agent**: Powered by Anthropic's Claude model through LangChain, providing natural language understanding and generation
- **WebSocket Connection**: Real-time communication channel that streams thinking process and results to the UI
- **Nmap Integration**: Security scanner utility accessed through a Model Context Protocol (MCP) client
- **Visualization Components**: React-based UI components that render scan results in a user-friendly format

## Limitations
- Cannot perform intrusive scans without proper authorization
- Network scan capabilities are limited to what Nmap provides
- Requires proper network connectivity to scan targets
- Large scans may take significant time to complete

When answering questions about capabilities, features, or functionality, use this documentation to provide accurate, specific information about the NetViz AI Agent.
`;
    return documentationCache;
  } catch (error) {
    console.error('Error loading documentation:', error);
    return '';
  }
}

// Enhanced system prompt with documentation
function getEnhancedSystemPrompt() {
  const basePrompt = `You are the NetViz AI Agent, an intelligent assistant specialized in network scanning, analysis, and OSINT (Open Source Intelligence) gathering using tools like Nmap and various reconnaissance tools.

AVAILABLE TOOLS:
1. NmapScanner - Advanced port scanning with custom parameters
2. WhoisLookup - Domain registration information gathering  
3. DNSRecon - Comprehensive DNS reconnaissance and enumeration
4. DigLookup - Standard DNS queries using dig command
5. HostLookup - Simple hostname to IP resolution
6. OSINTNmapScan - Predefined Nmap scanning via OSINT tools
7. DNSTwist - Domain permutation analysis for typosquatting detection
8. OSINTOverview - Comprehensive OSINT analysis combining multiple tools
9. search - Performs a web search using Perplexity to answer questions or find information. Input should be a search query string. This tool interfaces with a Perplexity MCP server which provides one or more specialized search tools; this 'search' tool utilizes the primary available search function from that server.

OSINT CAPABILITIES:
- Domain intelligence gathering (WHOIS, DNS records, subdomains)
- Infrastructure reconnaissance (IP addresses, name servers, mail servers)
- Security analysis (open ports, services, potential vulnerabilities)
- Brand protection analysis (typosquatting, domain variations)
- Comprehensive multi-tool analysis for complete target profiling

When responding to questions about your capabilities or scan types, use the following documentation:`;

  // Add documentation context to the system prompt
  const documentation = loadDocumentation();
  return `${basePrompt}

${documentation}`;
}

// Initialize the LLM with documentation context
function initializeLLM() {
  const llm = new ChatAnthropic({
    anthropicApiKey: process.env.ANTHROPIC_API,
    modelName: process.env.ANTHROPIC_MODEL || 'claude-3-sonnet-20240229',
    temperature: 0.7,
    maxTokens: 4000,
    streaming: true,
    systemPrompt: getEnhancedSystemPrompt()
  });
  
  return llm;
}

// Generate tailored responses for capability queries directly from our documentation
function generateCapabilityResponse(query) {
  const documentation = loadDocumentation();
  
  // Query types and corresponding responses
  if (query.toLowerCase().includes('what can you do') || 
      query.toLowerCase().includes('capabilities') ||
      query.toLowerCase().includes('help')) {
    
    return `As the NetViz AI Agent, I can help you with network scanning, security analysis, and comprehensive OSINT (Open Source Intelligence) gathering. My capabilities include:

## Network & Security Analysis:
• Network scanning and enumeration of hosts, ports, and services
• Service identification and version detection
• OS detection and fingerprinting
• Security vulnerability assessment
• Intelligent analysis of scan results
• Results visualization with summary, detailed views, and raw data access

## OSINT (Open Source Intelligence) Capabilities:
• **Domain Intelligence**: WHOIS lookups, DNS record enumeration, domain registration analysis
• **Infrastructure Reconnaissance**: IP address mapping, name server identification, mail server discovery
• **Brand Protection**: Typosquatting detection, domain variation analysis, phishing domain identification
• **Comprehensive Analysis**: Multi-tool OSINT overview combining all available intelligence sources

## Available Tools:
1. **NmapScanner**: Advanced port scanning with custom parameters and timing options
2. **WhoisLookup**: Domain registration information and ownership details
3. **DNSRecon**: Comprehensive DNS reconnaissance and record enumeration
4. **DigLookup**: Standard DNS queries for quick IP resolution
5. **HostLookup**: Simple hostname to IP address mapping
6. **OSINTNmapScan**: Predefined port scanning via OSINT infrastructure
7. **DNSTwist**: Domain permutation analysis for typosquatting detection
8. **OSINTOverview**: Complete OSINT analysis combining all tools
9. **search**: Performs a web search using Perplexity to answer questions or find information. Input should be a search query string. This tool interfaces with a Perplexity MCP server which provides one or more specialized search tools; this 'search' tool utilizes the primary available search function from that server.

## Scan Types:
• **Quick Scan**: Fast scan of common ports (-T4 -F flags)
• **Service Scan**: Detailed scan with service version detection (-sV flag)
• **Full Port Scan**: Comprehensive scan of all 65535 ports
• **Vulnerability Scan**: Security vulnerability assessment
• **OSINT Analysis**: Comprehensive intelligence gathering on domains/IPs

## Example Commands:
• "scan example.com for open ports"
• "perform OSINT analysis on example.com"
• "check WHOIS information for example.com"
• "look for typosquatting domains similar to example.com"
• "run a comprehensive analysis on example.com"

What type of analysis would you like to perform today?`;
  }
  
  if (query.toLowerCase().includes('scan types') || 
      query.toLowerCase().includes('what type of scan') ||
      query.toLowerCase().includes('what kind of scan')) {
    
    return `I can perform several types of network and OSINT analysis:

## Network Scanning:
1. **Quick Scan**
   • Description: Fast scan of common ports using optimized parameters
   • Technical Details: Uses Nmap with -T4 -F flags
   • Best For: Initial reconnaissance or when time is limited
   • Example: "run a quick scan on example.com"

2. **Service Scan**
   • Description: Detailed scan that identifies running services on open ports
   • Technical Details: Uses Nmap with -sV flag
   • Best For: Understanding what services are running on a target
   • Example: "scan for services on 192.168.1.1"

3. **Full Port Scan**
   • Description: Comprehensive scan of all 65535 ports
   • Technical Details: Scans the entire port range for complete coverage
   • Best For: Thorough security audits and comprehensive analysis
   • Example: "run a comprehensive port scan on example.com"

4. **Vulnerability Scan**
   • Description: Identifies potential security vulnerabilities on the target
   • Technical Details: Combines service detection with vulnerability assessment
   • Best For: Security audits and penetration testing preparations
   • Example: "check for vulnerabilities on example.com"

## OSINT Analysis:
5. **WHOIS Analysis**
   • Description: Domain registration and ownership information
   • Best For: Understanding domain ownership, registration dates, contact info
   • Example: "get WHOIS information for example.com"

6. **DNS Reconnaissance**
   • Description: Comprehensive DNS record enumeration and analysis
   • Best For: Understanding DNS infrastructure, subdomains, mail servers
   • Example: "perform DNS reconnaissance on example.com"

7. **Typosquatting Analysis**
   • Description: Finds domains similar to target that could be used maliciously
   • Best For: Brand protection, phishing detection
   • Example: "check for typosquatting domains similar to example.com"

8. **Comprehensive OSINT**
   • Description: Complete intelligence gathering using all available tools
   • Best For: Getting a complete picture of a target's online presence
   • Example: "perform comprehensive OSINT analysis on example.com"

Which type of analysis would you like to run?`;
  }

  if (query.toLowerCase().includes('osint') || 
      query.toLowerCase().includes('intelligence') ||
      query.toLowerCase().includes('reconnaissance')) {
    
    return `I specialize in OSINT (Open Source Intelligence) gathering with comprehensive capabilities:

## OSINT Tools Available:
• **WhoisLookup**: Domain registration information, ownership details, registration dates
• **DNSRecon**: Comprehensive DNS enumeration, record analysis, DNSSEC information
• **DigLookup**: Quick DNS queries for IP resolution and basic records
• **HostLookup**: Hostname to IP mapping, mail server identification
• **DNSTwist**: Domain permutation analysis for typosquatting detection
• **OSINTOverview**: Complete multi-tool analysis combining all OSINT capabilities

## Intelligence Categories:
1. **Domain Intelligence**: Registration info, ownership, historical data
2. **Infrastructure Intelligence**: IP addresses, hosting providers, CDNs
3. **DNS Intelligence**: Subdomains, mail servers, DNS configuration
4. **Security Intelligence**: Open ports, services, potential vulnerabilities
5. **Brand Protection**: Typosquatting, similar domains, potential phishing sites

## Use Cases:
• Security assessments and penetration testing preparation
• Brand monitoring and protection
• Threat intelligence gathering
• Due diligence on business partners or targets
• Infrastructure reconnaissance
• Phishing and fraud investigation

Example: "perform comprehensive OSINT analysis on example.com" will run all tools and provide a complete intelligence picture.

What type of intelligence gathering do you need?`;
  }
  
  // If no specific match, return null to use the normal agent flow
  return null;
}

module.exports = {
  initializeLLM,
  getEnhancedSystemPrompt,
  loadDocumentation,
  generateCapabilityResponse
}; 