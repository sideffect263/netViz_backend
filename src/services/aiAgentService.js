const { ChatAnthropic } = require('@langchain/anthropic');
const { DynamicTool, DynamicStructuredTool } = require('langchain/tools');
const { initializeAgentExecutorWithOptions } = require('langchain/agents');
const fs = require('fs');
const path = require('path');

// Import the MCP client for Nmap
let mcpClientModule;
async function getMcpClient() {
  if (!mcpClientModule) {
    mcpClientModule = await import('../utils/mcpClientSideEffect.mjs');
  }
  return mcpClientModule;
}

// Import the OSINT MCP client
let osintMcpClientModule;
async function getOsintMcpClient() {
  if (!osintMcpClientModule) {
    osintMcpClientModule = await import('../utils/mcpClientOsint.mjs');
  }
  return osintMcpClientModule;
}

// Load documentation for context enhancement
let documentationCache = null;

function loadDocumentation() {
  if (documentationCache) return documentationCache;
  
  try {
    // Try to load from documentation file
    const docsPath = path.join(__dirname, '../../docs/agent_documentation.md');
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

// Custom callback handler to stream thinking process via WebSockets
// Implementing our own handler without extending BaseCallbackHandler
class WebSocketCallbackHandler {
  constructor(sessionId, sendEventToSocket) {
    this.sessionId = sessionId;
    this.sendEventToSocket = sendEventToSocket;
  }

  // Required to register this as a callback handler with LangChain
  get name() {
    return 'WebSocketCallbackHandler';
  }

  // Required for the interface
  async handleLLMStart(llm, prompts) {
    this.sendEventToSocket({
      type: 'llm_start',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      content: 'Starting to think...'
    });
  }

  async handleLLMNewToken(token) {
    this.sendEventToSocket({
      type: 'llm_token',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      content: token
    });
  }

  async handleLLMEnd(output) {
    this.sendEventToSocket({
      type: 'llm_end',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      content: 'Finished thinking'
    });
  }

  async handleToolStart(tool, input) {
    // For Nmap scans, add a progress message
    if (tool.name === 'NmapScanner') {
      this.sendEventToSocket({
        type: 'progress_update',
        sessionId: this.sessionId,
        timestamp: new Date().toISOString(),
        message: 'Starting network scan. This may take some time depending on the scan parameters. The system will automatically reduce scan intensity if needed.'
      });
    }
    
    this.sendEventToSocket({
      type: 'tool_start',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      toolName: tool.name,
      input: input
    });
  }

  async handleToolEnd(output) {
    this.sendEventToSocket({
      type: 'tool_end',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      output: output
    });
  }

  async handleAgentAction(action) {
    this.sendEventToSocket({
      type: 'agent_action',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      tool: action.tool,
      toolInput: action.toolInput,
      log: action.log
    });
  }

  async handleAgentEnd(action) {
    this.sendEventToSocket({
      type: 'agent_end',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      output: action.returnValues?.output,
      log: action.log
    });
  }

  // Additional handlers to match the interface
  async handleChainStart(chain) {}
  async handleChainEnd(outputs) {}
  async handleChainError(error) {}
  async handleToolError(error) {}
  async handleText(text) {}
  async handleLLMError(error) {}
}

// Initialize the LLM with documentation context
function initializeLLM() {
  // Load documentation first
  const documentation = loadDocumentation();
  
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

/**
 * Parse Nmap command input to extract target and flags
 * @param {string} input - Input string like "-T4 -F example.com"
 * @returns {Object} - Object with target and flags properties
 */
function parseNmapInput(input) {
  if (typeof input === 'object' && input.target && input.flags) {
    // Already in the correct format
    return input;
  }

  if (typeof input !== 'string') {
    throw new Error("Invalid input format for NmapScanner. Expected string or object.");
  }

  const inputStr = input.trim();
  
  // Pattern to match: flags followed by target (common pattern in Nmap commands)
  // This handles both:
  // 1. "-T4 -F example.com" (flags then target)
  // 2. "example.com -T4 -F" (target then flags)
  const words = inputStr.split(' ');
  
  // Find which parts are flags (starting with -) and which is the target
  const flags = [];
  let target = '';
  
  for (const word of words) {
    if (word.startsWith('-')) {
      flags.push(word);
    } else if (!target && !word.startsWith('-')) {
      target = word;
    } else if (target) {
      // If we already have a target and this isn't a flag, append it
      // (handles cases where target might have spaces)
      target += ` ${word}`;
    }
  }
  
  // If we didn't find a target, use the last word as target
  if (!target && words.length > 0) {
    target = words[words.length - 1];
    // Remove it from flags if it was mistakenly added
    const targetIndex = flags.indexOf(target);
    if (targetIndex !== -1) {
      flags.splice(targetIndex, 1);
    }
  }
  
  // Join flags back together
  const flagsStr = flags.join(' ');
  
  console.log(`Parsed Nmap input: target="${target}", flags="${flagsStr}"`);
  
  return {
    target: target,
    flags: flagsStr
  };
}

// Initialize the tools
async function initializeTools() {
  // Get the MCP client for Nmap
  const mcpClient = await getMcpClient();
  
  // Get the OSINT MCP client
  const osintMcpClient = await getOsintMcpClient();

  const nmapTool = new DynamicTool({
    name: 'NmapScanner',
    description: `Runs an Nmap scan against a target with specified flags.
IMPORTANT: For large scans use reasonable defaults to avoid timeouts:
- Use -T4 for timing (faster)
- Limit port scans to common ports (-p 1-1000) instead of all ports (-p-)
- Use -F for a fast scan of most common ports
- Only use service detection (-sV) when needed
- Only include OS detection (-O) when critical

Examples:
- "example.com -T4 -F" (scan example.com with fast options)
- "-sV -p 80,443,8080 example.com" (scan specific ports with service detection)

The system will automatically retry with simplified parameters if the scan times out.`,
    func: async (input) => {
      try {
        // Send a progress update through the callback system
        console.log(`Processing Nmap scan input: ${input}`);
        
        // Parse the input to extract target and flags
        const { target, flags } = parseNmapInput(input);
        
        if (!target) {
          return "Error: No target specified for the scan. Please provide a domain or IP address.";
        }
        
        console.log(`Starting Nmap scan of ${target} with flags: ${flags}`);
        
        // Convert flags to array format expected by invokeNmapScan
        const flagsArray = flags.split(' ').filter(flag => flag.trim() !== '');
        
        // For intensive scans, add periodic progress updates
        const isIntensiveScan = flags.includes('-p-') || flags.includes('-sV') || flags.includes('-A');
        let progressUpdateInterval;
        
        if (isIntensiveScan) {
          // Every 20 seconds, send a progress update through the callback
          console.log('Intensive scan detected, will send progress updates');
        }
        
        try {
          const result = await mcpClient.invokeNmapScan({
            target,
            nmap_args: flagsArray
          });
          
          // Clear the interval if it was set
          if (progressUpdateInterval) {
            clearInterval(progressUpdateInterval);
          }
          
          return JSON.stringify(result, null, 2);
        } catch (error) {
          // Clear the interval if it was set
          if (progressUpdateInterval) {
            clearInterval(progressUpdateInterval);
          }
          
          return `Error running Nmap scan: ${error.message}`;
        }
      } catch (error) {
        return `Error running Nmap scan: ${error.message}`;
      }
    }
  });

  // OSINT Tools
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

  return [nmapTool, whoisTool, dnsReconTool, digTool, hostTool, nmapScanTool, dnsTwistTool, osintOverviewTool];
}

// Initialize the agent with direct message override for capability queries
async function initializeAgent(tools, callbacks, conversationHistory = []) {
  const llm = initializeLLM();
  
  // Create a memory component for the agent to remember past interactions
  const agent = await initializeAgentExecutorWithOptions(
    tools,
    llm,
    {
      agentType: "chat-conversational-react-description",
      verbose: true,
      maxIterations: 5,
      callbacks: callbacks,
      // Add enhanced system message
      agentArgs: {
        systemMessage: getEnhancedSystemPrompt(),
        // Add memory/history support
        memory: conversationHistory
      }
    }
  );
  
  return agent;
}

// Process user command with special handling for capability queries
async function processUserCommand(command, sessionId, sendEventToSocket, conversationHistory = []) {
  try {
    // Determine if this is a capability query to provide enhanced responses
    const isCapabilityQuery = command.toLowerCase().includes('what can you do') || 
                            command.toLowerCase().includes('capabilities') ||
                            command.toLowerCase().includes('help') ||
                            command.toLowerCase().includes('scan types') ||
                            command.toLowerCase().includes('what type of scan');
    
    // Create callback handler for WebSocket streaming
    const callbacks = [new WebSocketCallbackHandler(sessionId, sendEventToSocket)];
    
    // Initialize tools and agent
    const tools = await initializeTools();
    
    // Convert conversation history to format expected by LangChain
    const formattedHistory = conversationHistory.map(msg => ({
      type: msg.role === 'user' ? 'human' : 'ai',
      content: msg.content
    }));
    
    const agent = await initializeAgent(tools, callbacks, formattedHistory);
    
    // For capability queries, provide direct detailed response from documentation
    if (isCapabilityQuery) {
      // Get specific content from documentation based on query
      const enhancedResponse = generateCapabilityResponse(command);
      
      // If we have an enhanced response, return it directly
      if (enhancedResponse) {
        sendEventToSocket({
          type: 'llm_token',
          sessionId: sessionId,
          timestamp: new Date().toISOString(),
          content: "Retrieving specialized capability information..."
        });
        
        // Small delay to show the thinking process
        await new Promise(resolve => setTimeout(resolve, 500));
        
        return enhancedResponse;
      }
    }
    
    // Execute the agent with the user command (standard flow)
    const result = await agent.invoke({
      input: command,
      // Add explicit instruction for capability queries
      ...(isCapabilityQuery && {
        context: "This query is about system capabilities. Provide a detailed, specific response based on the documentation."
      })
    }, {
      callbacks: callbacks  // Pass callbacks to the invoke call
    });
    
    return result.output;
  } catch (error) {
    console.error('Error processing user command:', error);
    sendEventToSocket({
      type: 'error',
      sessionId: sessionId,
      timestamp: new Date().toISOString(),
      error: error.message
    });
    
    return `Error processing command: ${error.message}`;
  }
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
  processUserCommand
}; 