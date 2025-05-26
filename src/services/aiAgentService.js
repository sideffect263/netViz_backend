const { initializeAgentExecutorWithOptions } = require('langchain/agents');
const { initializeLLM, getEnhancedSystemPrompt, generateCapabilityResponse } = require('./llm/llmConfig');
const { WebSocketCallbackHandler } = require('./callbacks/websocketCallback');
const { EnhancedWebSocketCallbackHandler } = require('./callbacks/enhancedWebsocketCallback');
const { createNmapTool } = require('./tools/nmapTool');
const { createOsintTools } = require('./tools/osintTools');
const { ToolOrchestrator } = require('./tools/toolOrchestrator');
const { createPerplexityTool } = require('./tools/perplexityTool');
const allowedTargets = require('../config/allowedTargets');

// Agent persistence cache
const agentCache = new Map();
const AGENT_CACHE_TTL = 30 * 60 * 1000; // 30 minutes

// Tool instances cache
let toolsCache = null;
let toolsCacheTime = null;
const TOOLS_CACHE_TTL = 10 * 60 * 1000; // 10 minutes

// Tool orchestrator instance
let orchestratorCache = null;

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

// Import the Perplexity MCP client
let perplexityMcpClientModule;
async function getPerplexityMcpClient() {
  if (!perplexityMcpClientModule) {
    perplexityMcpClientModule = await import('../utils/mcpClientPerplexity.mjs');
  }
  return perplexityMcpClientModule;
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

// Enhanced tool initialization with caching and orchestration
async function initializeTools() {
  const now = Date.now();
  
  // Return cached tools if still valid
  if (toolsCache && toolsCacheTime && (now - toolsCacheTime) < TOOLS_CACHE_TTL) {
    return toolsCache;
  }
  
  console.log('Initializing fresh tool instances...');
  
  // Create atomic tools
  const nmapTool = await createNmapTool();
  const osintTools = await createOsintTools();
  const perplexityTool = await createPerplexityTool();
  const atomicTools = [nmapTool, ...osintTools, perplexityTool].filter(Boolean);
  
  // Create tool orchestrator and get orchestrated tools
  if (!orchestratorCache) {
    orchestratorCache = new ToolOrchestrator(atomicTools);
  }
  const orchestratedTools = orchestratorCache.createOrchestratedTools();
  
  // Combine atomic and orchestrated tools
  toolsCache = [...atomicTools, ...orchestratedTools];
  toolsCacheTime = now;
  
  console.log(`Initialized ${atomicTools.length} atomic tools and ${orchestratedTools.length} orchestrated tools`);
  
  return toolsCache;
}

// Enhanced agent initialization with persistence and better configuration
async function initializeAgent(tools, callbacks, conversationHistory = [], sessionId) {
  const cacheKey = `agent_${sessionId}`;
  const now = Date.now();
  
  // Check for cached agent
  const cachedAgent = agentCache.get(cacheKey);
  if (cachedAgent && (now - cachedAgent.timestamp) < AGENT_CACHE_TTL) {
    console.log(`Reusing cached agent for session ${sessionId}`);
    // Update callbacks for the cached agent
    cachedAgent.agent.callbacks = callbacks;
    return cachedAgent.agent;
  }
  
  console.log(`Creating new agent for session ${sessionId}`);
  const llm = initializeLLM();
  
  // Enhanced agent configuration
  const agent = await initializeAgentExecutorWithOptions(
    tools,
    llm,
    {
      agentType: "chat-conversational-react-description",
      verbose: true,
      maxIterations: 8, // Increased for complex workflows
      callbacks: callbacks,
      returnIntermediateSteps: true, // Better debugging
      maxExecutionTime: 300000, // 5 minutes timeout
      // Enhanced system message with tool routing guidance
      agentArgs: {
        systemMessage: getEnhancedSystemPrompt() + `

TOOL SELECTION STRATEGY:
1. For network scanning: Use NmapScanner for custom scans, OSINTNmapScan for quick predefined scans
2. For domain intelligence: Start with WhoisLookup, then DNSRecon for comprehensive analysis
3. For brand protection: Use DNSTwist for typosquatting analysis
4. For comprehensive analysis: Use OSINTOverview to combine multiple tools
5. For web searches and general knowledge: Use search
6. Always explain your tool selection reasoning to the user

WORKFLOW OPTIMIZATION:
- For "quick scan" requests: Use NmapScanner with -T4 -F flags
- For "comprehensive analysis": Use OSINTOverview followed by targeted NmapScanner
- For "security assessment": Combine multiple tools in logical sequence
- Always provide context about why specific tools were chosen`,
        // Enhanced memory handling
        memory: conversationHistory
      }
    }
  );
  
  // Cache the agent
  agentCache.set(cacheKey, {
    agent,
    timestamp: now
  });
  
  // Clean up old cached agents
  cleanupAgentCache();
  
  return agent;
}

// Cleanup expired agents from cache
function cleanupAgentCache() {
  const now = Date.now();
  for (const [key, value] of agentCache.entries()) {
    if ((now - value.timestamp) > AGENT_CACHE_TTL) {
      agentCache.delete(key);
      console.log(`Cleaned up expired agent cache for ${key}`);
    }
  }
}

// Function to check if a target is allowed
function isTargetAllowed(target) {
  if (!target) return true; // If no target, assume it's a general command not requiring target validation
  // Simple check for now, can be expanded (e.g. resolve domain to IP and check both)
  return allowedTargets.has(target);
}

// Enhanced command processing with better tool routing logic
async function processUserCommand(command, sessionId, sendEventToSocket, conversationHistory = []) {
  try {
    const lowerCommand = command.toLowerCase();

    // Handle queries about scannable targets directly
    const isScanScopeQuery = lowerCommand.includes('what can you scan') ||
                             lowerCommand.includes('what systems can you scan') ||
                             lowerCommand.includes('what domains can you scan') ||
                             lowerCommand.includes('what ip can you scan') ||
                             lowerCommand.includes('what ips can you scan') ||
                             lowerCommand.includes('what targets can you scan') ||
                             lowerCommand.includes('list scannable targets') ||
                             lowerCommand.includes('allowed targets') ||
                             lowerCommand.includes('which targets are allowed');

    if (isScanScopeQuery) {
      const targetsArray = Array.from(allowedTargets);
      const responseMessage = `I am restricted to scanning a predefined list of targets for educational and bug bounty purposes. This list currently contains ${targetsArray.length} entries, including hosts like 'scanme.nmap.org', 'testphp.vulnweb.com', and domains like 'google.com', 'github.com'. Scanning any other targets is not permitted.`;
      sendEventToSocket({
        type: 'llm_token',
        sessionId: sessionId,
        timestamp: new Date().toISOString(),
        content: responseMessage
      });
      return responseMessage;
    }

    // Enhanced capability query detection
    const isCapabilityQuery = lowerCommand.includes('what can you do') || 
                            lowerCommand.includes('capabilities') ||
                            lowerCommand.includes('help') ||
                            lowerCommand.includes('scan types') ||
                            lowerCommand.includes('what type of scan');
    
    // Analyze command for tool routing hints
    const commandAnalysis = analyzeCommand(command);
    
    // Check if any identified target is allowed before proceeding with agent logic
    if (commandAnalysis.targets && commandAnalysis.targets.length > 0) {
      const unallowedTargets = commandAnalysis.targets.filter(t => !isTargetAllowed(t));
      if (unallowedTargets.length > 0) {
        const message = `Operation blocked: Scanning is only permitted for the following predefined targets: ${Array.from(allowedTargets).join(', ')}. The target(s) '${unallowedTargets.join(', ')}' are not in the allowed list.`
        sendEventToSocket({
          type: 'error',
          sessionId: sessionId,
          timestamp: new Date().toISOString(),
          error: message
        });
        return message;
      }
    }
    
    // Create enhanced callback handler
    const callbacks = [new EnhancedWebSocketCallbackHandler(sessionId, sendEventToSocket)];
    
    // Send initial analysis to user
    if (commandAnalysis.complexity === 'high') {
      sendEventToSocket({
        type: 'llm_token',
        sessionId: sessionId,
        timestamp: new Date().toISOString(),
        content: `Analyzing complex request: "${command}". This may require multiple tools and steps...`
      });
    }
    
    // Initialize tools and agent with session persistence
    const tools = await initializeTools();
    
    // Convert conversation history to format expected by LangChain
    const formattedHistory = conversationHistory.map(msg => ({
      type: msg.role === 'user' ? 'human' : 'ai',
      content: msg.content
    }));
    
    const agent = await initializeAgent(tools, callbacks, formattedHistory, sessionId);
    
    // For capability queries, provide direct detailed response from documentation
    if (isCapabilityQuery) {
      const enhancedResponse = generateCapabilityResponse(command);
      
      if (enhancedResponse) {
        sendEventToSocket({
          type: 'llm_token',
          sessionId: sessionId,
          timestamp: new Date().toISOString(),
          content: "Retrieving specialized capability information..."
        });
        
        await new Promise(resolve => setTimeout(resolve, 500));
        return enhancedResponse;
      }
    }
    
    // Enhanced command execution with context
    const enhancedCommand = enhanceCommandWithContext(command, commandAnalysis);
    
    // Execute the agent with enhanced input
    const result = await agent.invoke({
      input: enhancedCommand,
      // Add analysis context
      context: `Command Analysis: ${JSON.stringify(commandAnalysis)}`,
      // Add tool routing hints
      toolHints: commandAnalysis.suggestedTools
    }, {
      callbacks: callbacks
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

// Command analysis for better tool routing
function analyzeCommand(command) {
  const lowerCommand = command.toLowerCase();
  const analysis = {
    type: 'unknown',
    complexity: 'low',
    suggestedTools: [],
    targets: [],
    flags: []
  };
  
  // Extract targets (domains, IPs)
  const domainRegex = /(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}/g;
  const ipRegex = /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/g;
  
  analysis.targets = [
    ...(command.match(domainRegex) || []),
    ...(command.match(ipRegex) || [])
  ];
  
  // Analyze command type and suggest tools
  if (lowerCommand.includes('scan') || lowerCommand.includes('port')) {
    analysis.type = 'network_scan';
    if (lowerCommand.includes('quick') || lowerCommand.includes('fast')) {
      analysis.suggestedTools = ['NmapScanner'];
      analysis.flags = ['-T4', '-F'];
    } else if (lowerCommand.includes('comprehensive') || lowerCommand.includes('full')) {
      analysis.complexity = 'high';
      analysis.suggestedTools = ['NmapScanner', 'OSINTOverview'];
    } else {
      analysis.suggestedTools = ['NmapScanner'];
    }
  } else if (lowerCommand.includes('whois') || lowerCommand.includes('registration')) {
    analysis.type = 'domain_intelligence';
    analysis.suggestedTools = ['WhoisLookup'];
  } else if (lowerCommand.includes('dns') || lowerCommand.includes('subdomain')) {
    analysis.type = 'dns_analysis';
    analysis.suggestedTools = ['DNSRecon', 'DigLookup'];
  } else if (lowerCommand.includes('osint') || lowerCommand.includes('intelligence')) {
    analysis.type = 'osint_analysis';
    analysis.complexity = 'high';
    analysis.suggestedTools = ['OSINTOverview'];
  } else if (lowerCommand.includes('typosquat') || lowerCommand.includes('similar domain')) {
    analysis.type = 'brand_protection';
    analysis.suggestedTools = ['DNSTwist'];
  } else if (lowerCommand.includes('comprehensive') || lowerCommand.includes('complete analysis')) {
    analysis.type = 'comprehensive';
    analysis.complexity = 'high';
    analysis.suggestedTools = ['OSINTOverview', 'NmapScanner'];
  } else if (lowerCommand.includes('search') || lowerCommand.includes('find information') || lowerCommand.includes('look up')) {
    analysis.type = 'web_search';
    analysis.suggestedTools = ['search'];
  }
  
  return analysis;
}

// Enhance command with context for better agent performance
function enhanceCommandWithContext(command, analysis) {
  let enhancedCommand = command;
  
  if (analysis.suggestedTools.length > 0) {
    enhancedCommand += `\n\nContext: This appears to be a ${analysis.type} request. Consider using tools: ${analysis.suggestedTools.join(', ')}.`;
  }
  
  if (analysis.targets.length > 0) {
    enhancedCommand += `\nTargets identified: ${analysis.targets.join(', ')}.`;
  }
  
  if (analysis.flags.length > 0) {
    enhancedCommand += `\nSuggested flags: ${analysis.flags.join(' ')}.`;
  }
  
  return enhancedCommand;
}

module.exports = {
  processUserCommand,
  cleanupAgentCache // Export for potential cleanup scheduling
}; 