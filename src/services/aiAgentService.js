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
  const basePrompt = `You are the NetViz AI Agent, an intelligent assistant specialized in network scanning, analysis, and security tasks using tools like Nmap.

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

  return [nmapTool];
}

// Initialize the agent with direct message override for capability queries
async function initializeAgent(tools, callbacks) {
  const llm = initializeLLM();
  
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
        systemMessage: getEnhancedSystemPrompt()
      }
    }
  );
  
  return agent;
}

// Process user command with special handling for capability queries
async function processUserCommand(command, sessionId, sendEventToSocket) {
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
    const agent = await initializeAgent(tools, callbacks);
    
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
    
    return `As the NetViz AI Agent, I can help you with network scanning and security analysis tasks. My capabilities include:

• Network scanning and enumeration of hosts, ports, and services
• Service identification and version detection
• OS detection and fingerprinting
• Security vulnerability assessment
• Intelligent analysis of scan results
• Explanation of technical findings in plain language
• Results visualization with summary, detailed views, and raw data access

I can perform several types of scans:

1. **Quick Scan**: Fast scan of common ports using optimized parameters (-T4 -F flags)
2. **Service Scan**: Detailed scan that identifies running services on open ports (-sV flag)
3. **Full Port Scan**: Comprehensive scan of all 65535 ports (takes longer but more thorough)
4. **Vulnerability Scan**: Identifies potential security vulnerabilities on the target

You can interact with me using natural language commands like:
• "scan example.com for open ports"
• "run a quick scan on 192.168.1.1"
• "check if port 443 is open on example.com"
• "scan for services on 10.0.0.1"

What type of scan would you like to perform today?`;
  }
  
  if (query.toLowerCase().includes('scan types') || 
      query.toLowerCase().includes('what type of scan') ||
      query.toLowerCase().includes('what kind of scan')) {
    
    return `I can perform several types of network scans:

1. **Quick Scan**
   • Description: Fast scan of common ports using optimized parameters
   • Technical Details: Uses Nmap with -T4 -F flags
   • Best For: Initial reconnaissance or when time is limited
   • Example Command: "run a quick scan on example.com"
   • Expected Output: A list of the most commonly open ports (like 80, 443, 22)

2. **Service Scan**
   • Description: Detailed scan that identifies running services on open ports
   • Technical Details: Uses Nmap with -sV flag
   • Best For: Understanding what services are running on a target
   • Example Command: "scan for services on 192.168.1.1"
   • Expected Output: Port numbers, states, and service identification with versions

3. **Full Port Scan**
   • Description: Comprehensive scan of all 65535 ports
   • Technical Details: Scans the entire port range for complete coverage
   • Best For: Thorough security audits and comprehensive analysis
   • Example Command: "run a comprehensive port scan on example.com"
   • Note: Takes significantly longer than a Quick Scan

4. **Vulnerability Scan**
   • Description: Identifies potential security vulnerabilities on the target
   • Technical Details: Combines service detection with vulnerability assessment
   • Best For: Security audits and penetration testing preparations
   • Example Command: "check for vulnerabilities on example.com"

Which type of scan would you like to run?`;
  }
  
  // If no specific match, return null to use the normal agent flow
  return null;
}

module.exports = {
  processUserCommand
}; 