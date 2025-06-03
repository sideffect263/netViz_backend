const { initializeAgentExecutorWithOptions } = require('langchain/agents');
const { initializeLLM, getEnhancedSystemPrompt, generateCapabilityResponse } = require('./llm/llmConfig');
const { WebSocketCallbackHandler } = require('./callbacks/websocketCallback');
const { EnhancedWebSocketCallbackHandler } = require('./callbacks/enhancedWebsocketCallback');
const { createNmapTool } = require('./tools/nmapTool');
const { createOsintTools } = require('./tools/osintTools');
const { ToolOrchestrator } = require('./tools/toolOrchestrator');
const { createPerplexityTool } = require('./tools/perplexityTool');
const { createMetasploitTools } = require('./tools/metasploitTool');
const { contextManager } = require('./contextManager');
const { securityIntelligence } = require('./securityIntelligenceEngine');
const { langGraphRouter } = require('./langGraphRouter');
// Enhanced autonomous components
const { threatIntelligence } = require('./threatIntelligenceEngine');
const { autonomousDecision } = require('./autonomousDecisionEngine');
const { enhancedLangGraph } = require('./enhancedLangGraphEngine');
// Target Intelligence Service
const { targetIntelligenceService } = require('./targetIntelligenceService');
const allowedTargets = require('../config/allowedTargets');
const fs = require('fs');
const path = require('path');

// Agent persistence cache
const agentCache = new Map();
const AGENT_CACHE_TTL = 30 * 60 * 1000; // 30 minutes

// Tool instances cache
let toolsCache = null;
let toolsCacheTime = null;
const TOOLS_CACHE_TTL = 10 * 60 * 1000; // 10 minutes

// Tool orchestrator instance
let orchestratorCache = null;

// Enhanced autonomous capabilities configuration
const AUTONOMOUS_FEATURES = {
  THREAT_INTELLIGENCE: process.env.ENABLE_THREAT_INTELLIGENCE === 'true',
  AUTONOMOUS_DECISIONS: process.env.ENABLE_AUTONOMOUS_DECISIONS === 'true',
  VULNERABILITY_CORRELATION: process.env.ENABLE_VULN_CORRELATION === 'true',
  CONTINUOUS_ASSESSMENT: process.env.ENABLE_CONTINUOUS_ASSESSMENT === 'true',
  SHODAN_INTEGRATION: !!process.env.SHODAN_API_KEY,
  NVD_INTEGRATION: !!process.env.NVD_API_KEY
};

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

## Enhanced Autonomous Capabilities
- **Threat Intelligence**: Real-time integration with NIST NVD and Shodan APIs for comprehensive vulnerability intelligence
- **Autonomous Decision Making**: Strategic decision engine that adapts assessment strategies based on findings
- **Vulnerability Correlation**: Automatic correlation between discovered services and known vulnerabilities
- **Continuous Assessment**: Persistent monitoring and assessment capabilities

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

- **Autonomous Assessment**: AI-driven comprehensive security assessment
   Details: Uses threat intelligence and autonomous decision making for strategic analysis
   Example: "perform autonomous assessment on example.com"

## Intelligence Capabilities
- **Threat Intelligence Gathering**: Automated correlation with vulnerability databases
- **Strategic Planning**: Multi-phase attack planning and resource optimization
- **Risk Assessment**: Comprehensive risk scoring and threat level determination
- **Continuous Monitoring**: Persistent target monitoring for changes and new vulnerabilities

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
- **Threat Intelligence Engine**: Real-time vulnerability correlation and threat analysis
- **Autonomous Decision Engine**: Strategic decision making for optimal assessment workflows

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
  const metasploitTools = await createMetasploitTools();
  const atomicTools = [nmapTool, ...osintTools, perplexityTool, ...metasploitTools].filter(Boolean);
  
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
  
  // Enhanced agent configuration with autonomous capabilities
  const agent = await initializeAgentExecutorWithOptions(
    tools,
    llm,
    {
      agentType: "chat-conversational-react-description",
      verbose: true,
      maxIterations: 12, // Increased for autonomous operations
      callbacks: callbacks,
      returnIntermediateSteps: true, // Better debugging
      maxExecutionTime: 600000, // 10 minutes timeout for complex operations
      // Enhanced system message with autonomous capabilities
      agentArgs: {
        systemMessage: getEnhancedSystemPrompt() + `

AUTONOMOUS CYBERSECURITY CAPABILITIES:
${AUTONOMOUS_FEATURES.THREAT_INTELLIGENCE ? '✅ Real-time threat intelligence from NIST NVD and Shodan' : '❌ Threat intelligence disabled'}
${AUTONOMOUS_FEATURES.AUTONOMOUS_DECISIONS ? '✅ Autonomous strategic decision making' : '❌ Autonomous decisions disabled'}
${AUTONOMOUS_FEATURES.VULNERABILITY_CORRELATION ? '✅ Automatic vulnerability correlation' : '❌ Vulnerability correlation disabled'}
${AUTONOMOUS_FEATURES.CONTINUOUS_ASSESSMENT ? '✅ Continuous assessment and monitoring' : '❌ Continuous assessment disabled'}

ENHANCED OPERATION MODES:
1. STANDARD MODE: Traditional scan analysis with enhanced intelligence
2. AUTONOMOUS MODE: AI-driven assessment with strategic decision making
3. CONTINUOUS MODE: Persistent monitoring and assessment
4. INTELLIGENCE MODE: Focus on threat intelligence gathering and correlation

AUTONOMOUS DECISION FRAMEWORK:
- Automatically analyzes scan results against threat intelligence databases
- Makes strategic decisions about next assessment steps
- Correlates discovered services with known vulnerabilities
- Prioritizes actions based on risk assessment and exploitability
- Adapts strategy based on target characteristics and previous findings

TOOL SELECTION STRATEGY:
1. For network scanning: Use NmapScanner for custom scans, OSINTNmapScan for quick predefined scans
2. For domain intelligence: Start with WhoisLookup, then DNSRecon for comprehensive analysis
3. For brand protection: Use DNSTwist for typosquatting analysis
4. For comprehensive analysis: Use OSINTOverview to combine multiple tools
5. For web searches and general knowledge: Use search
6. Always explain your tool selection reasoning to the user

AUTONOMOUS WORKFLOW:
1. Initial reconnaissance and target profiling
2. Threat intelligence correlation and analysis
3. Strategic decision making based on findings
4. Adaptive assessment strategy execution
5. Continuous monitoring and validation
6. Intelligence synthesis and reporting

WORKFLOW OPTIMIZATION:
- For "quick scan" requests: Use NmapScanner with -T4 -F flags
- For "comprehensive analysis": Use enhanced autonomous workflow
- For "security assessment": Combine threat intelligence with autonomous decision making
- For "autonomous assessment": Enable full autonomous capabilities
- Always provide context about why specific tools and strategies were chosen

CRITICAL RULES:
1. After EVERY scan, correlate results with threat intelligence
2. Make autonomous strategic decisions about next steps
3. Provide vulnerability correlation and risk assessment
4. Track assessment progress and guide users through methodology
5. Focus on actionable intelligence with strategic context
6. Think like an autonomous security consultant

When responding to questions about your capabilities or scan types, emphasize the enhanced autonomous features when available.`,
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

// Generate response for allowed targets queries
function generateAllowedTargetsResponse() {
  const targetsArray = Array.from(allowedTargets);
  
  // Categorize targets for better presentation
  const vulnerableHosts = [
    'scanme.nmap.org (45.33.32.156)',
    'testphp.vulnweb.com (44.228.249.3)',
    'testasp.vulnweb.com (44.228.249.3)',
    'testaspnet.vulnweb.com (44.228.249.3)',
    'testhtml5.vulnweb.com (44.228.249.3)',
    'demo.testfire.net (65.61.137.117)',
    'zero.webappsecurity.com (54.82.22.214)',
    'juice-shop.herokuapp.com (46.137.15.86)'
  ];
  
  const bugBountyDomains = [
    'google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'microsoft.com',
    'apple.com', 'tesla.com', 'shopify.com', 'github.com', 'hackerone.com',
    'bugcrowd.com', 'uber.com', 'wordpress.org', 'mozilla.org', 'dropbox.com',
    'paypal.com', 'twitter.com', 'slack.com', 'medium.com', 'pinterest.com',
    'stackoverflow.com', 'atlassian.com', 'zoom.us', 'tumblr.com', 'trello.com',
    'linkedin.com', 'reddit.com', 'cloudflare.com', 'digitalocean.com', 'stripe.com',
    'squareup.com', 'bitbucket.org', 'gitlab.com', 'jetbrains.com', 'telegram.org',
    'signal.org', 'protonmail.com', 'heroku.com', 'aws.amazon.com', 'oracle.com',
    'intel.com', 'snapchat.com'
  ];
  
  return `I can scan a restricted list of ${targetsArray.length} authorized targets for educational and bug bounty purposes:

**Intentionally Vulnerable Test Hosts (${vulnerableHosts.length} hosts):**
${vulnerableHosts.join(', ')}

**Bug Bounty Program Scope Domains (${bugBountyDomains.length} domains):**
${bugBountyDomains.join(', ')}

These targets are specifically chosen for safe, legal security testing and learning. Scanning any other targets is strictly prohibited and will be blocked by the system.

**Available Operation Modes:**
• **Standard Analysis**: Enhanced scan analysis with threat intelligence
• **Autonomous Assessment**: AI-driven strategic security assessment ${AUTONOMOUS_FEATURES.AUTONOMOUS_DECISIONS ? '✅' : '❌'}
• **Continuous Monitoring**: Persistent target monitoring ${AUTONOMOUS_FEATURES.CONTINUOUS_ASSESSMENT ? '✅' : '❌'}
• **Intelligence Focus**: Deep threat intelligence analysis ${AUTONOMOUS_FEATURES.THREAT_INTELLIGENCE ? '✅' : '❌'}

**Examples of what you can ask:**
• "scan google.com"
• "perform autonomous assessment on scanme.nmap.org"
• "continuous monitoring of github.com"
• "deep threat intelligence analysis on tesla.com"`;
}

// Enhanced command processing with autonomous capabilities
async function processUserCommand(command, sessionId, sendEventToSocket, conversationHistory = []) {
  try {
    const lowerCommand = command.toLowerCase();

    // Handle queries about scannable targets directly - EXPANDED PATTERNS
    const isScanScopeQuery = lowerCommand.includes('what can you scan') ||
                             lowerCommand.includes('what systems can you scan') ||
                             lowerCommand.includes('what domains can you scan') ||
                             lowerCommand.includes('what domain can you scan') ||
                             lowerCommand.includes('what ip can you scan') ||
                             lowerCommand.includes('what ips can you scan') ||
                             lowerCommand.includes('what targets can you scan') ||
                             lowerCommand.includes('list scannable targets') ||
                             lowerCommand.includes('allowed targets') ||
                             lowerCommand.includes('which targets are allowed') ||
                             lowerCommand.includes('authorized ips') ||
                             lowerCommand.includes('authorized domains') ||
                             lowerCommand.includes('authorized targets') ||
                             lowerCommand.includes('list of authorized') ||
                             lowerCommand.includes('what domains and ip') ||
                             lowerCommand.includes('what domains and ips') ||
                             lowerCommand.includes('domains and ip can you scan') ||
                             lowerCommand.includes('domains and ips can you scan') ||
                             // Additional patterns that were missing
                             lowerCommand.includes('what ips or domains can i scan') ||
                             lowerCommand.includes('what domains or ips can i scan') ||
                             lowerCommand.includes('which ips can i scan') ||
                             lowerCommand.includes('which domains can i scan') ||
                             lowerCommand.includes('what can i scan') ||
                             lowerCommand.includes('what am i allowed to scan') ||
                             lowerCommand.includes('show me allowed targets') ||
                             lowerCommand.includes('list allowed targets') ||
                             lowerCommand.includes('available targets') ||
                             lowerCommand.includes('permitted targets') ||
                             lowerCommand.includes('can i scan') && (lowerCommand.includes('what') || lowerCommand.includes('which'));

    if (isScanScopeQuery) {
      const responseMessage = generateAllowedTargetsResponse();
      
      sendEventToSocket({
        type: 'llm_token',
        sessionId: sessionId,
        timestamp: new Date().toISOString(),
        content: responseMessage
      });
      return responseMessage;
    }

    // Detect autonomous operation requests
    const isAutonomousRequest = lowerCommand.includes('autonomous') ||
                               lowerCommand.includes('intelligent') ||
                               lowerCommand.includes('continuous') ||
                               lowerCommand.includes('threat intelligence') ||
                               lowerCommand.includes('strategic');

    // Analyze command with enhanced intent classification
    const commandAnalysis = enhancedAnalyzeCommand(command, conversationHistory);
    
    // Handle high-confidence conversational responses directly
    if (commandAnalysis.confidence >= 0.90 && commandAnalysis.conversationalResponse && !commandAnalysis.requiresTools) {
      sendEventToSocket({
        type: 'llm_token',
        sessionId: sessionId,
        timestamp: new Date().toISOString(),
        content: commandAnalysis.conversationalResponse
      });
      return commandAnalysis.conversationalResponse;
    }
    
    // Check if any identified target is allowed before proceeding with agent logic
    // Only validate targets for scanning-related intents, not for exploit searches
    const scanningIntents = ['network_scan', 'target_analysis', 'osint_analysis', 'dns_analysis', 'whois_lookup', 'brand_protection'];
    const requiresTargetValidation = scanningIntents.includes(commandAnalysis.intent);
    
    if (requiresTargetValidation && commandAnalysis.targets && commandAnalysis.targets.length > 0) {
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

    // Determine if we should use autonomous capabilities
    const useAutonomousMode = isAutonomousRequest && AUTONOMOUS_FEATURES.AUTONOMOUS_DECISIONS;
    const useEnhancedIntelligence = AUTONOMOUS_FEATURES.THREAT_INTELLIGENCE || AUTONOMOUS_FEATURES.VULNERABILITY_CORRELATION;

    // Route to enhanced autonomous analysis if appropriate
    if (useAutonomousMode || (useEnhancedIntelligence && commandAnalysis.requiresTools)) {
      sendEventToSocket({
        type: 'llm_token',
        sessionId: sessionId,
        timestamp: new Date().toISOString(),
        content: '🤖 Activating autonomous cybersecurity assessment capabilities...'
      });

      // Determine operation mode
      let operationMode = 'intelligence';
      if (lowerCommand.includes('autonomous')) operationMode = 'autonomous';
      if (lowerCommand.includes('continuous')) operationMode = 'monitoring';
      if (lowerCommand.includes('vulnerability')) operationMode = 'vuln_validation';

      // Use enhanced LangGraph engine for autonomous analysis
      try {
        const enhancedResponse = await enhancedLangGraph.performAdvancedAnalysis(
          command,
          null, // scan results will be gathered internally
          conversationHistory,
          sessionId,
          {
            mode: operationMode,
            continuous: lowerCommand.includes('continuous'),
            target: commandAnalysis.targets[0]
          }
        );

        sendEventToSocket({
          type: 'llm_token',
          sessionId: sessionId,
          timestamp: new Date().toISOString(),
          content: enhancedResponse
        });

        // Store the conversation turn in context
        contextManager.addConversationTurn(sessionId, command, enhancedResponse, commandAnalysis);

        return enhancedResponse;
      } catch (error) {
        console.error('Error in autonomous analysis:', error);
        // Fall back to standard processing
        sendEventToSocket({
          type: 'llm_token',
          sessionId: sessionId,
          timestamp: new Date().toISOString(),
          content: '⚠️ Autonomous mode encountered an issue, falling back to standard analysis...'
        });
      }
    }
    
    // Enhanced capability query detection
    const isCapabilityQuery = commandAnalysis.intent === 'capability_query' || 
                            commandAnalysis.intent === 'scan_type_query' ||
                            lowerCommand.includes('what can you do') || 
                            lowerCommand.includes('capabilities') ||
                            lowerCommand.includes('help') ||
                            lowerCommand.includes('scan types') ||
                            lowerCommand.includes('what type of scan');
    
    // Create enhanced callback handler
    const callbacks = [new EnhancedWebSocketCallbackHandler(sessionId, sendEventToSocket)];
    
    // Send initial analysis to user for complex requests
    if (commandAnalysis.complexity === 'high' && commandAnalysis.requiresTools) {
      sendEventToSocket({
        type: 'llm_token',
        sessionId: sessionId,
        timestamp: new Date().toISOString(),
        content: `Analyzing complex request: "${command}". ${useEnhancedIntelligence ? 'Enhanced threat intelligence will be applied.' : 'This may require multiple tools and steps...'}`
      });
    } else if (commandAnalysis.confidence < 0.7) {
      sendEventToSocket({
        type: 'llm_token',
        sessionId: sessionId,
        timestamp: new Date().toISOString(),
        content: `Analyzing request: "${command}". ${useEnhancedIntelligence ? 'Correlating with threat intelligence...' : 'Let me determine the best approach...'}`
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
    
    // Get contextual insights and suggestions
    const contextualInsights = contextManager.getContextualInsights(sessionId);
    const contextualSuggestions = contextManager.generateContextualSuggestions(sessionId, commandAnalysis);
    
    // Add contextual information to the enhanced command
    let contextualCommand = enhancedCommand;
    if (contextualInsights.totalInteractions > 0) {
      contextualCommand += `\n\nSession Context: ${contextualInsights.totalInteractions} previous interactions`;
      
      if (contextualInsights.mostCommonIntent) {
        contextualCommand += `, most common intent: ${contextualInsights.mostCommonIntent.intent}`;
      }
      
      if (contextualInsights.frequentTargets.length > 0) {
        contextualCommand += `, frequent targets: ${contextualInsights.frequentTargets.join(', ')}`;
      }
    }
    
    // Add contextual suggestions if available
    if (contextualSuggestions.length > 0) {
      contextualCommand += `\n\nContextual Suggestions: ${contextualSuggestions.map(s => s.message).join(' | ')}`;
    }

    // Add autonomous capabilities context
    if (useEnhancedIntelligence) {
      contextualCommand += `\n\nEnhanced Capabilities Active: ${Object.entries(AUTONOMOUS_FEATURES).filter(([k, v]) => v).map(([k, v]) => k).join(', ')}`;
    }
    
    // Execute the agent with enhanced input
    const result = await agent.invoke({
      input: contextualCommand,
      // Add analysis context
      context: `Command Analysis: ${JSON.stringify(commandAnalysis)}`,
      // Add tool routing hints
      toolHints: commandAnalysis.suggestedTools,
      // Add session context
      sessionContext: contextualInsights,
      // Add autonomous features context
      autonomousFeatures: AUTONOMOUS_FEATURES
    }, {
      callbacks: callbacks
    });
    
    // Check if this is a follow-up question about scan results
    const isFollowUpQuestion = command.toLowerCase().includes('next') || 
                              command.toLowerCase().includes('what else') ||
                              command.toLowerCase().includes('other scan') ||
                              command.toLowerCase().includes('more info') ||
                              command.toLowerCase().includes('then what');
    
    // Get the last scan results from conversation history
    let lastScanResults = null;
    for (let i = conversationHistory.length - 1; i >= 0; i--) {
      if (conversationHistory[i].assistantResponse && 
          conversationHistory[i].assistantResponse.includes('scan') && 
          conversationHistory[i].assistantResponse.includes('port')) {
        lastScanResults = conversationHistory[i].assistantResponse;
        break;
      }
    }
    
    // Use intelligent response routing for follow-up questions (with enhanced capabilities)
    if (isFollowUpQuestion && lastScanResults) {
      // Check if we should use enhanced analysis for follow-ups
      if (useEnhancedIntelligence && commandAnalysis.targets.length > 0) {
        try {
          const enhancedFollowUp = await enhancedLangGraph.performAdvancedAnalysis(
            command,
            lastScanResults,
            conversationHistory,
            sessionId,
            { mode: 'intelligence', target: commandAnalysis.targets[0] }
          );

          sendEventToSocket({
            type: 'llm_token',
            sessionId: sessionId,
            timestamp: new Date().toISOString(),
            content: enhancedFollowUp
          });

          contextManager.addConversationTurn(sessionId, command, enhancedFollowUp, commandAnalysis);
          return enhancedFollowUp;
        } catch (error) {
          console.error('Error in enhanced follow-up analysis:', error);
          // Fall back to standard routing
        }
      }

      // Route through the response router for intelligent, non-repetitive responses
      const intelligentResponse = await langGraphRouter.routeResponse(
        command,
        lastScanResults,
        conversationHistory,
        sessionId
      );
      
      // Send the intelligent response
      sendEventToSocket({
        type: 'llm_token',
        sessionId: sessionId,
        timestamp: new Date().toISOString(),
        content: intelligentResponse
      });
      
      // Store the conversation turn in context
      contextManager.addConversationTurn(sessionId, command, intelligentResponse, commandAnalysis);
      
      return intelligentResponse;
    }
    
    // Enhanced scan result analysis with automatic exploit correlation
    if (result.output && (result.output.includes('scan') || result.output.includes('port'))) {
      // Check if we have actual scan data from intermediate steps
      let scanData = null;
      let targetFromScan = null;
      let discoveredServices = [];
      
      // Look for actual Nmap scan results in intermediate steps
      if (result.intermediateSteps && result.intermediateSteps.length > 0) {
        for (const step of result.intermediateSteps) {
          if (step.action && step.action.tool === 'NmapScanner' && step.observation) {
            // Extract the actual scan output from the observation
            try {
              const observationData = JSON.parse(step.observation);
              if (observationData.content && observationData.content[0] && observationData.content[0].text) {
                scanData = observationData.content[0].text;
                // Try to extract target from the scan data
                const targetMatch = scanData.match(/Nmap.*scan.*for\s+([^\s\n]+)/i);
                if (targetMatch) {
                  targetFromScan = targetMatch[1];
                }
                
                // Extract discovered services for automatic exploit research
                const portMatches = scanData.match(/(\d+)\/tcp\s+open\s+([^\s\n]+)/gi);
                if (portMatches) {
                  portMatches.forEach(match => {
                    const portServiceMatch = match.match(/(\d+)\/tcp\s+open\s+([^\s\n]+)/i);
                    if (portServiceMatch) {
                      const port = portServiceMatch[1];
                      const service = portServiceMatch[2];
                      discoveredServices.push({ port, service });
                    }
                  });
                }
                break;
              }
            } catch (e) {
              // If not JSON, use the observation directly
              scanData = step.observation;
              // Still try to extract services from plain text
              const portMatches = scanData.match(/(\d+)\/tcp\s+open\s+([^\s\n]+)/gi);
              if (portMatches) {
                portMatches.forEach(match => {
                  const portServiceMatch = match.match(/(\d+)\/tcp\s+open\s+([^\s\n]+)/i);
                  if (portServiceMatch) {
                    const port = portServiceMatch[1];
                    const service = portServiceMatch[2];
                    discoveredServices.push({ port, service });
                  }
                });
              }
            }
          }
        }
      }

      // **NEW: Track target intelligence for scan results**
      if (targetFromScan && scanData && allowedTargets.has(targetFromScan)) {
        try {
          // Track the scan activity
          const targetIntelligence = targetIntelligenceService.trackScanActivity(
            sessionId, 
            targetFromScan, 
            scanData
          );
          
          console.log(`Tracked scan results for ${targetFromScan}:`, {
            services: targetIntelligence.services.length,
            riskScore: targetIntelligence.riskScore,
            phase: targetIntelligence.phase
          });
        } catch (error) {
          console.error('Error tracking scan results:', error);
        }
      }
      
      // AUTOMATIC EXPLOIT RESEARCH: If we discovered services, automatically search for relevant exploits
      if (discoveredServices.length > 0 && targetFromScan && allowedTargets.has(targetFromScan)) {
        let enhancedOutput = result.output;
        
        // Add automatic exploit intelligence section
        enhancedOutput += `\n\n**🎯 AUTOMATIC EXPLOIT INTELLIGENCE:**\n`;
        enhancedOutput += `Based on discovered services, here are the specific exploits you should research immediately:\n`;
        
        // Map services to relevant exploit search terms
        const serviceToExploitMap = {
          'http': ['http', 'apache', 'nginx', 'web server'],
          'https': ['https', 'ssl', 'tls', 'apache', 'nginx'],
          'ssh': ['ssh', 'openssh'],
          'ftp': ['ftp', 'vsftpd'],
          'smtp': ['smtp', 'postfix', 'sendmail'],
          'mysql': ['mysql'],
          'postgresql': ['postgresql', 'postgres'],
          'smb': ['smb', 'samba'],
          'rdp': ['rdp', 'remote desktop'],
          'telnet': ['telnet'],
          'snmp': ['snmp'],
          'dns': ['dns', 'bind'],
          'tomcat': ['tomcat', 'apache tomcat', 'jsp'],
          'apache': ['apache', 'httpd', 'apache tomcat'],
          'coyote': ['tomcat', 'apache tomcat', 'jsp', 'coyote'],
          'jsp': ['jsp', 'tomcat', 'java']
        };
        
        // Check for Tomcat-specific services
        const hasTomcat = discoveredServices.some(s => 
          s.service.toLowerCase().includes('tomcat') || 
          s.service.toLowerCase().includes('coyote') ||
          s.service.toLowerCase().includes('jsp') ||
          s.service.toLowerCase().includes('apache') && s.service.toLowerCase().includes('jsp')
        );
        
        if (hasTomcat) {
          enhancedOutput += `\n**🔥 TOMCAT SERVICES DETECTED - IMMEDIATE ACTION REQUIRED:**\n`;
          enhancedOutput += `• **MetasploitExploitSearch**: Search "tomcat" immediately\n`;
          enhancedOutput += `• **MetasploitExploitSearch**: Search "apache tomcat" for specific modules\n`;
          enhancedOutput += `• **MetasploitExploitSearch**: Search "jsp" for JSP-specific exploits\n`;
          enhancedOutput += `• **Common Tomcat Exploits**: manager interface, JSP upload, directory traversal\n`;
          enhancedOutput += `• **Key Metasploit Modules**: exploit/multi/http/tomcat_mgr_upload, auxiliary/scanner/http/tomcat_mgr_login\n`;
        }
        
        for (const serviceInfo of discoveredServices) {
          const serviceKey = serviceInfo.service.toLowerCase();
          const searchTerms = serviceToExploitMap[serviceKey] || [serviceKey];
          
          enhancedOutput += `\n**Port ${serviceInfo.port} (${serviceInfo.service}):**\n`;
          enhancedOutput += `• **IMMEDIATE ACTION**: Use MetasploitExploitSearch with terms: ${searchTerms.map(term => `"${term}"`).join(', ')}\n`;
          enhancedOutput += `• **Security Risk**: ${getServiceSecurityImplication(serviceInfo.service, serviceInfo.port)}\n`;
          enhancedOutput += `• **Next Command**: Search Metasploit database using the terms above\n`;
        }
        
        // Add proactive guidance for exploit research
        enhancedOutput += `\n**🔍 MANDATORY NEXT STEPS:**\n`;
        enhancedOutput += `1. **Search for web server exploits**: Run MetasploitExploitSearch with "http", "apache", "tomcat"\n`;
        enhancedOutput += `2. **Check SSL/TLS vulnerabilities**: Run MetasploitExploitSearch with "ssl", "tls"\n`;
        enhancedOutput += `3. **Analyze proxy service**: Run MetasploitExploitSearch with "proxy", "http-proxy"\n`;
        enhancedOutput += `4. **Service enumeration**: Use auxiliary/scanner modules for detailed enumeration\n`;
        
        // Add specific technical guidance
        enhancedOutput += `\n**💡 TECHNICAL EXPLOITATION METHODOLOGY:**\n`;
        enhancedOutput += `• **Service enumeration**: auxiliary/scanner/http/http_version, auxiliary/scanner/http/dir_scanner\n`;
        enhancedOutput += `• **Credential attacks**: auxiliary/scanner/http/tomcat_mgr_login for Tomcat manager\n`;
        enhancedOutput += `• **File upload attacks**: exploit/multi/http/tomcat_mgr_upload if manager access gained\n`;
        enhancedOutput += `• **Directory traversal**: Check for path traversal vulnerabilities in web services\n`;
        
        result.output = enhancedOutput;
      }
      
      // Enhanced analysis with threat intelligence if available
      else if (scanData && useEnhancedIntelligence && targetFromScan) {
        try {
          sendEventToSocket({
            type: 'llm_token',
            sessionId: sessionId,
            timestamp: new Date().toISOString(),
            content: '🧠 Correlating scan results with threat intelligence databases...'
          });

          // Gather threat intelligence
          const intelligence = await threatIntelligence.gatherIntelligence(targetFromScan, scanData);
          
          if (intelligence.vulnerabilities.length > 0 || intelligence.riskScore > 30) {
            let enhancedOutput = result.output;
            
            // Add threat intelligence summary
            enhancedOutput += `\n\n**🧠 Threat Intelligence Analysis:**`;
            enhancedOutput += `\n• Risk Score: ${intelligence.riskScore}/100`;
            enhancedOutput += `\n• Threat Level: ${intelligence.threatLevel.toUpperCase()}`;
            enhancedOutput += `\n• Target Type: ${intelligence.targetProfile.type}`;
            
            if (intelligence.targetProfile.organization !== 'Unknown') {
              enhancedOutput += `\n• Organization: ${intelligence.targetProfile.organization}`;
            }
            
            // Add vulnerability intelligence
            if (intelligence.vulnerabilities.length > 0) {
              const criticalVulns = intelligence.vulnerabilities.filter(v => v.severity === 'critical');
              const weaponizedVulns = intelligence.vulnerabilities.filter(v => v.weaponized);
              
              enhancedOutput += `\n\n**🔓 Vulnerability Intelligence:**`;
              enhancedOutput += `\n• Total Vulnerabilities: ${intelligence.vulnerabilities.length}`;
              enhancedOutput += `\n• Critical: ${criticalVulns.length}`;
              enhancedOutput += `\n• Weaponized: ${weaponizedVulns.length}`;
              
              if (weaponizedVulns.length > 0) {
                enhancedOutput += `\n\n**⚠️ Weaponized Vulnerabilities (Immediate Threat):**`;
                weaponizedVulns.slice(0, 3).forEach(vuln => {
                  enhancedOutput += `\n• ${vuln.cveId}: CVSS ${vuln.score}`;
                });
              }
            }
            
            // Add strategic recommendations
            if (intelligence.strategicRecommendations.length > 0) {
              enhancedOutput += `\n\n**🎯 Strategic Recommendations:**`;
              intelligence.strategicRecommendations.slice(0, 3).forEach((rec, index) => {
                enhancedOutput += `\n\n${index + 1}. **${rec.action}** (${rec.priority.toUpperCase()})`;
                enhancedOutput += `\n   ${rec.description}`;
                if (rec.techniques) {
                  enhancedOutput += `\n   Techniques: ${rec.techniques.join(', ')}`;
                }
              });
            }
            
            result.output = enhancedOutput;
          }
        } catch (error) {
          console.error('Error in threat intelligence correlation:', error);
          // Continue with standard analysis
        }
      } else if (scanData && scanData.includes('Nmap Scan Results')) {
        // Standard security intelligence enhancement
        const securityAnalysis = securityIntelligence.analyzeScanResults(scanData, targetFromScan);
        
        // If we have meaningful security insights, create an enhanced response
        if (securityAnalysis.attackSurface.length > 0) {
          let enhancedOutput = result.output;
          
          // Only add security posture if it makes sense
          if (securityAnalysis.securityPosture && securityAnalysis.securityPosture.overallRating) {
            enhancedOutput += `\n\n**Security Assessment:**`;
            enhancedOutput += `\n• Security Posture: ${securityAnalysis.securityPosture.overallRating} (Score: ${securityAnalysis.securityPosture.score}/100)`;
            
            if (securityAnalysis.securityPosture.strengths.length > 0) {
              enhancedOutput += `\n• Strengths: ${securityAnalysis.securityPosture.strengths.join(', ')}`;
            }
            
            if (securityAnalysis.securityPosture.weaknesses.length > 0) {
              enhancedOutput += `\n• Weaknesses: ${securityAnalysis.securityPosture.weaknesses.join(', ')}`;
            }
          }
          
          // Add critical findings if any
          if (securityAnalysis.criticalFindings.length > 0) {
            enhancedOutput += `\n\n**⚠️ Security Concerns:**`;
            securityAnalysis.criticalFindings.forEach(finding => {
              enhancedOutput += `\n• ${finding.service} on port ${finding.port}: ${finding.implications[0]}`;
              if (finding.recommendations.length > 0) {
                enhancedOutput += `\n  → Recommendation: ${finding.recommendations[0].action}`;
              }
            });
          }
          
          // Add strategic next steps
          if (securityAnalysis.nextSteps.length > 0 && !isFollowUpQuestion) {
            enhancedOutput += `\n\n**Strategic Next Steps:**`;
            securityAnalysis.nextSteps.slice(0, 3).forEach((step, index) => {
              enhancedOutput += `\n\n${index + 1}. **${step.action}**`;
              if (step.command) {
                enhancedOutput += `\n   Command: \`nmap ${step.command} ${targetFromScan || '[target]'}\``;
              }
              if (step.rationale) {
                enhancedOutput += `\n   Rationale: ${step.rationale}`;
              }
              enhancedOutput += `\n   Priority: ${step.priority.toUpperCase()}`;
            });
            
            // Add methodology note
            enhancedOutput += `\n\n💡 **Security Methodology Note:** We're currently in the ${securityAnalysis.nextSteps[0] ? 'discovery' : 'assessment'} phase. Each recommended step builds upon previous findings to create a comprehensive security picture.`;
          }
          
          result.output = enhancedOutput;
        }
      }
    }

    // **NEW: Track exploitation attempts**
    if (result.output && (result.output.toLowerCase().includes('exploit') || result.output.toLowerCase().includes('metasploit'))) {
      // Extract targets from the command analysis for exploitation tracking
      if (commandAnalysis.targets && commandAnalysis.targets.length > 0) {
        commandAnalysis.targets.forEach(target => {
          if (allowedTargets.has(target)) {
            try {
              const exploitData = {
                description: command.substring(0, 100) + '...',
                status: 'attempted',
                tool: command.toLowerCase().includes('metasploit') ? 'metasploit' : 'custom'
              };
              
              const targetIntelligence = targetIntelligenceService.trackExploitAttempt(
                sessionId,
                target,
                exploitData
              );
              
              console.log(`Tracked exploitation attempt on ${target}:`, {
                attempts: targetIntelligence.exploitAttempts.length,
                riskScore: targetIntelligence.riskScore,
                phase: targetIntelligence.phase
              });
            } catch (error) {
              console.error('Error tracking exploitation attempt:', error);
            }
          }
        });
      }
    }
    
    // Store the conversation turn in context
    contextManager.addConversationTurn(sessionId, command, result.output, commandAnalysis);
    
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

// Enhanced command analysis with intent classification and confidence scoring
function enhancedAnalyzeCommand(command, conversationHistory = []) {
  const lowerCommand = command.toLowerCase().trim();
  const analysis = {
    intent: 'unknown',
    confidence: 0.0,
    requiresTools: false,
    conversationalResponse: null,
    suggestedTools: [],
    targets: [],
    flags: [],
    complexity: 'low'
  };
  
  // Extract targets (domains, IPs) first
  const domainRegex = /(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}/g;
  const ipRegex = /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/g;
  
  // Service names that shouldn't be treated as targets in exploit searches
  const serviceNames = ['http', 'https', 'ssh', 'ftp', 'smtp', 'smb', 'rdp', 'telnet', 'mysql', 'postgresql', 'mongodb', 'oracle', 'mssql', 'ldap', 'snmp'];
  
  // Extract potential targets
  const potentialTargets = [
    ...(command.match(domainRegex) || []),
    ...(command.match(ipRegex) || [])
  ];
  
  // Check if this is likely an exploit search request first
  const earlyExploitPatterns = [
    /exploit/i,
    /metasploit/i,
    /msf/i,
    /cve/i,
    /vulnerability.*search/i,
    /find.*exploit/i,
    /search.*exploit/i,
    /what.*exploit/i
  ];
  
  const isLikelyExploitSearch = earlyExploitPatterns.some(pattern => pattern.test(lowerCommand));
  
  // If it's an exploit search, filter out service names from targets
  if (isLikelyExploitSearch) {
    analysis.targets = potentialTargets.filter(target => !serviceNames.includes(target.toLowerCase()));
  } else {
    analysis.targets = potentialTargets;
  }

  // 1. CONVERSATIONAL PATTERNS (High Priority - No Tools Needed)
  
  // Greetings
  const greetingPatterns = [
    /^(hi|hello|hey|good morning|good afternoon|good evening|greetings)$/,
    /^(hi|hello|hey)\s*(there|netviz|agent)?$/,
    /^(what's up|how are you|how's it going)$/
  ];
  
  if (greetingPatterns.some(pattern => pattern.test(lowerCommand))) {
    analysis.intent = 'greeting';
    analysis.confidence = 0.95;
    analysis.requiresTools = false;
    analysis.conversationalResponse = `Hello! I'm NetViz AI Agent, your cybersecurity assistant. I can help you with:

• Network scanning and port analysis
• OSINT (Open Source Intelligence) gathering
• Domain and DNS reconnaissance
• Security vulnerability assessment
• Brand protection analysis

What would you like to analyze today? You can ask me to scan a domain, perform OSINT analysis, or ask about my capabilities.`;
    return analysis;
  }

  // Thanks/Appreciation
  const thanksPatterns = [
    /^(thanks|thank you|thx|appreciate it|great|awesome|perfect)$/,
    /^(thanks|thank you)\s*(so much|very much|a lot)?$/,
    /^(that's|that was)\s*(great|awesome|perfect|helpful|useful)$/
  ];
  
  if (thanksPatterns.some(pattern => pattern.test(lowerCommand))) {
    analysis.intent = 'appreciation';
    analysis.confidence = 0.95;
    analysis.requiresTools = false;
    analysis.conversationalResponse = "You're welcome! I'm glad I could help. Feel free to ask if you need any more security analysis or have questions about network reconnaissance.";
    return analysis;
  }

  // Farewells
  const farewellPatterns = [
    /^(bye|goodbye|see you|farewell|take care)$/,
    /^(bye|goodbye)\s*(for now|later)?$/,
    /^(have a good|have a great)\s*(day|evening|night)$/
  ];
  
  if (farewellPatterns.some(pattern => pattern.test(lowerCommand))) {
    analysis.intent = 'farewell';
    analysis.confidence = 0.95;
    analysis.requiresTools = false;
    analysis.conversationalResponse = "Goodbye! Stay secure and feel free to return anytime you need cybersecurity analysis or network reconnaissance assistance.";
    return analysis;
  }

  // 2. SCANNABLE TARGETS QUERIES (High Priority - Direct Response)
  
  const scanTargetsPatterns = [
    /what.*can.*scan/,
    /what.*ips?.*can.*scan/,
    /what.*domains?.*can.*scan/,
    /which.*ips?.*can.*scan/,
    /which.*domains?.*can.*scan/,
    /what.*allowed.*scan/,
    /what.*permitted.*scan/,
    /list.*allowed.*targets/,
    /show.*allowed.*targets/,
    /available.*targets/,
    /permitted.*targets/,
    /authorized.*targets/,
    /scannable.*targets/,
    /what.*targets.*scan/,
    /what.*ips?.*or.*domains?.*can.*scan/,
    /what.*domains?.*or.*ips?.*can.*scan/
  ];
  
  if (scanTargetsPatterns.some(pattern => pattern.test(lowerCommand))) {
    analysis.intent = 'scan_targets_query';
    analysis.confidence = 0.95;
    analysis.requiresTools = false;
    analysis.conversationalResponse = generateAllowedTargetsResponse();
    return analysis;
  }

  // 3. CAPABILITY QUERIES (Medium Priority - Direct Response)
  
  const capabilityPatterns = [
    /what can you do/,
    /what are your capabilities/,
    /help me/,
    /how can you help/,
    /what tools do you have/,
    /what services/,
    /list.*capabilities/,
    /show.*features/
  ];
  
  if (capabilityPatterns.some(pattern => pattern.test(lowerCommand))) {
    analysis.intent = 'capability_query';
    analysis.confidence = 0.90;
    analysis.requiresTools = false;
    // Will be handled by existing capability response system
    return analysis;
  }

  // 4. SCAN TYPE QUERIES (Medium Priority - Direct Response)
  
  const scanTypePatterns = [
    /what.*scan.*types?/,
    /what.*kind.*scan/,
    /what.*type.*scan/,
    /scan.*options/,
    /available.*scans/,
    /list.*scans/
  ];
  
  if (scanTypePatterns.some(pattern => pattern.test(lowerCommand))) {
    analysis.intent = 'scan_type_query';
    analysis.confidence = 0.90;
    analysis.requiresTools = false;
    // Will be handled by existing capability response system
    return analysis;
  }

  // 5. SECURITY KNOWLEDGE QUERIES (Medium Priority - May Need Search Tool)
  
  const securityKnowledgePatterns = [
    /what is.*vulnerability/,
    /explain.*security/,
    /how does.*work/,
    /what.*means?/,
    /define.*security/,
    /tell me about/,
    /explain.*attack/,
    /what.*protocol/,
    /how.*secure/
  ];
  
  if (securityKnowledgePatterns.some(pattern => pattern.test(lowerCommand))) {
    analysis.intent = 'security_knowledge';
    analysis.confidence = 0.85;
    analysis.requiresTools = true; // May need search tool for current information
    analysis.suggestedTools = ['search'];
    analysis.complexity = 'medium';
    return analysis;
  }

  // 6. EXPLOIT SEARCH REQUESTS (High Priority - Requires Metasploit)
  
  const exploitPatterns = [
    /exploit/i,
    /metasploit/i,
    /msf/i,
    /cve/i,
    /vulnerability.*search/i,
    /find.*exploit/i,
    /search.*exploit/i,
    /what.*exploit/i
  ];

  // SQL Injection specific patterns
  const sqlInjectionPatterns = [
    /sql.*inject/i,
    /find.*sql.*inject/i,
    /test.*sql.*inject/i,
    /search.*sql.*inject/i,
    /sql.*vulnerab/i,
    /inject.*vulnerab/i,
    /sql.*attack/i,
    /database.*inject/i,
    /web.*sql/i
  ];
  
  if (sqlInjectionPatterns.some(pattern => pattern.test(lowerCommand))) {
    analysis.intent = 'sql_injection_test';
    analysis.confidence = 0.95;
    analysis.requiresTools = true;
    analysis.complexity = 'high';
    analysis.suggestedTools = ['MetasploitSQLInjectionScan'];
    
    // If a target is specified, note it
    if (analysis.targets.length > 0) {
      console.log(`SQL injection test requested for target: ${analysis.targets[0]}`);
    } else {
      // Check conversation history for previously scanned targets
      if (conversationHistory.length > 0) {
        const lastScan = conversationHistory
          .reverse()
          .find(msg => msg.assistantResponse && msg.assistantResponse.includes('testphp.vulnweb.com'));
        if (lastScan) {
          analysis.targets.push('testphp.vulnweb.com');
          console.log('Using previously scanned target for SQL injection test');
        }
      }
    }
    
    return analysis;
  }
  
  if (exploitPatterns.some(pattern => pattern.test(lowerCommand))) {
    analysis.intent = 'exploit_search';
    analysis.confidence = 0.95;
    analysis.requiresTools = true;
    analysis.complexity = 'medium';
    
    // Extract service/port info
    const portMatch = lowerCommand.match(/port\s*(\d+)/i);
    const serviceMatch = lowerCommand.match(/(ssh|http|https|ftp|smb|rdp|telnet|mysql|postgresql|mongodb)/i);
    
    if (portMatch || serviceMatch) {
      analysis.suggestedTools = ['MetasploitExploitSearch'];
      if (portMatch) analysis.targets.push(`port ${portMatch[1]}`);
      if (serviceMatch) analysis.targets.push(serviceMatch[1]);
    } else {
      // General exploit search
      analysis.suggestedTools = ['MetasploitExploitSearch'];
    }
    
    return analysis;
  }

  // 7. NETWORK SCANNING REQUESTS (High Priority - Requires Tools)
  
  if (lowerCommand.includes('scan') || lowerCommand.includes('port')) {
    analysis.intent = 'network_scan';
    analysis.requiresTools = true;
    
    if (lowerCommand.includes('quick') || lowerCommand.includes('fast')) {
      analysis.confidence = 0.95;
      analysis.suggestedTools = ['NmapScanner'];
      analysis.flags = ['-T4', '-F'];
      analysis.complexity = 'low';
    } else if (lowerCommand.includes('comprehensive') || lowerCommand.includes('full') || lowerCommand.includes('complete')) {
      analysis.confidence = 0.95;
      analysis.complexity = 'high';
      analysis.suggestedTools = ['NmapScanner', 'OSINTOverview'];
    } else if (lowerCommand.includes('vulnerability') || lowerCommand.includes('vuln')) {
      analysis.confidence = 0.95;
      analysis.suggestedTools = ['NmapScanner'];
      analysis.flags = ['-sV', '--script=vuln'];
      analysis.complexity = 'high';
    } else {
      analysis.confidence = 0.90;
      analysis.suggestedTools = ['NmapScanner'];
      analysis.complexity = 'medium';
    }
    return analysis;
  }

  // 8. OSINT ANALYSIS REQUESTS (High Priority - Requires Tools)
  
  const osintPatterns = [
    /osint/,
    /intelligence/,
    /reconnaissance/,
    /recon/,
    /investigate/,
    /research/,
    /analyze.*domain/,
    /domain.*analysis/,
    /comprehensive.*analysis/
  ];
  
  if (osintPatterns.some(pattern => pattern.test(lowerCommand))) {
    analysis.intent = 'osint_analysis';
    analysis.confidence = 0.95;
    analysis.requiresTools = true;
    analysis.complexity = 'high';
    analysis.suggestedTools = ['OSINTOverview'];
    return analysis;
  }

  // 9. SPECIFIC TOOL REQUESTS (High Priority - Requires Specific Tools)
  
  if (lowerCommand.includes('whois') || lowerCommand.includes('registration')) {
    analysis.intent = 'whois_lookup';
    analysis.confidence = 0.95;
    analysis.requiresTools = true;
    analysis.suggestedTools = ['WhoisLookup'];
    analysis.complexity = 'low';
    return analysis;
  }
  
  if (lowerCommand.includes('dns') || lowerCommand.includes('subdomain')) {
    analysis.intent = 'dns_analysis';
    analysis.confidence = 0.95;
    analysis.requiresTools = true;
    analysis.suggestedTools = ['DNSRecon', 'DigLookup'];
    analysis.complexity = 'medium';
    return analysis;
  }
  
  if (lowerCommand.includes('typosquat') || lowerCommand.includes('similar domain')) {
    analysis.intent = 'brand_protection';
    analysis.confidence = 0.95;
    analysis.requiresTools = true;
    analysis.suggestedTools = ['DNSTwist'];
    analysis.complexity = 'medium';
    return analysis;
  }

  // 10. GENERAL SEARCH REQUESTS (Medium Priority - Search Tool)
  
  const searchPatterns = [
    /search/,
    /find.*information/,
    /look up/,
    /tell me about/,
    /what.*latest/,
    /current.*news/,
    /recent.*developments/
  ];
  
  if (searchPatterns.some(pattern => pattern.test(lowerCommand))) {
    analysis.intent = 'web_search';
    analysis.confidence = 0.80;
    analysis.requiresTools = true;
    analysis.suggestedTools = ['search'];
    analysis.complexity = 'low';
    return analysis;
  }

  // 11. CONTEXT-AWARE FOLLOW-UPS
  
  if (conversationHistory.length > 0) {
    const lastUserMessage = conversationHistory
      .filter(msg => msg.role === 'user')
      .slice(-1)[0];
    
    if (lastUserMessage) {
      const contextPatterns = [
        /more.*detail/,
        /explain.*further/,
        /tell me more/,
        /elaborate/,
        /expand.*on/,
        /what.*mean/,
        /can you.*explain/
      ];
      
      if (contextPatterns.some(pattern => pattern.test(lowerCommand))) {
        analysis.intent = 'follow_up_question';
        analysis.confidence = 0.85;
        analysis.requiresTools = false; // Usually can be answered from context
        analysis.conversationalResponse = "I'd be happy to provide more details. Could you specify which aspect you'd like me to elaborate on?";
        return analysis;
      }
    }
  }

  // 12. AMBIGUOUS OR UNCLEAR REQUESTS (Low Priority)
  
  if (lowerCommand.length < 3) {
    analysis.intent = 'unclear';
    analysis.confidence = 0.95;
    analysis.requiresTools = false;
    analysis.conversationalResponse = "I didn't quite understand that. Could you please provide more details about what you'd like me to help you with? I can perform network scans, OSINT analysis, or answer cybersecurity questions.";
    return analysis;
  }

  // 13. DEFAULT CASE - Analyze for potential security context
  
  if (analysis.targets.length > 0) {
    // Has targets but unclear intent - likely wants some form of analysis
    analysis.intent = 'target_analysis';
    analysis.confidence = 0.70;
    analysis.requiresTools = true;
    analysis.suggestedTools = ['OSINTOverview'];
    analysis.complexity = 'medium';
    return analysis;
  }

  // Completely unknown - let the agent decide but with low confidence
  analysis.intent = 'unknown';
  analysis.confidence = 0.30;
  analysis.requiresTools = true; // Let agent decide
  analysis.complexity = 'medium';
  
  return analysis;
}

// Legacy function for backward compatibility
function analyzeCommand(command) {
  const enhanced = enhancedAnalyzeCommand(command);
  return {
    type: enhanced.intent,
    complexity: enhanced.complexity,
    suggestedTools: enhanced.suggestedTools,
    targets: enhanced.targets,
    flags: enhanced.flags
  };
}

// Enhance command with context for better agent performance
function enhanceCommandWithContext(command, analysis) {
  let enhancedCommand = command;
  
  // Add intent and confidence context
  if (analysis.intent && analysis.confidence) {
    enhancedCommand += `\n\nIntent Analysis: ${analysis.intent} (confidence: ${analysis.confidence.toFixed(2)})`;
  }
  
  // Add tool guidance only if tools are actually needed
  if (analysis.requiresTools && analysis.suggestedTools.length > 0) {
    enhancedCommand += `\nRecommended tools: ${analysis.suggestedTools.join(', ')}`;
    enhancedCommand += `\nTool usage rationale: This request requires ${analysis.complexity} complexity analysis`;
    
    // Add specific guidance for NmapScanner
    if (analysis.suggestedTools.includes('NmapScanner') && analysis.targets.length > 0) {
      const target = analysis.targets[0];
      const flags = analysis.flags.length > 0 ? analysis.flags.join(' ') : '-T4 -F';
      enhancedCommand += `\nNmapScanner format example: "${target} ${flags}"`;
      enhancedCommand += `\nIMPORTANT: Always use "target flags" format for NmapScanner, never send flags alone`;
    }
    
    // Add specific guidance for MetasploitExploitSearch
    if (analysis.suggestedTools.includes('MetasploitExploitSearch')) {
      if (analysis.intent === 'exploit_search') {
        enhancedCommand += `\nMetasploit guidance: Search for exploits based on the context`;
        if (command.toLowerCase().includes('port 22') || command.toLowerCase().includes('ssh')) {
          enhancedCommand += `\nSearch term suggestion: "ssh" to find SSH-related exploits`;
        } else if (command.toLowerCase().includes('port 80') || command.toLowerCase().includes('http')) {
          enhancedCommand += `\nSearch term suggestion: "http" or "apache" to find web server exploits`;
        } else if (analysis.targets.length > 0) {
          enhancedCommand += `\nSearch term suggestion: "${analysis.targets[0]}"`;
        }
        enhancedCommand += `\nIMPORTANT: Use MetasploitExploitSearch tool with searchTerm parameter`;
      }
    }
  } else if (!analysis.requiresTools) {
    enhancedCommand += `\nNote: This appears to be a conversational request that can be answered directly without tools`;
  }
  
  if (analysis.targets.length > 0) {
    enhancedCommand += `\nTargets identified: ${analysis.targets.join(', ')}`;
  }
  
  if (analysis.flags.length > 0) {
    enhancedCommand += `\nSuggested parameters: ${analysis.flags.join(' ')}`;
  }
  
  // Add conversational context
  if (analysis.intent === 'greeting' || analysis.intent === 'appreciation' || analysis.intent === 'farewell') {
    enhancedCommand += `\nNote: Respond conversationally without using any tools`;
  }
  
  return enhancedCommand;
}

// Helper function to get security implications for discovered services
function getServiceSecurityImplication(service, port) {
  const implications = {
    'http': 'Unencrypted web traffic, potential for web application attacks, man-in-the-middle attacks',
    'https': 'Encrypted web traffic, but check for SSL/TLS vulnerabilities and certificate issues',
    'ssh': 'Remote administration access, secure but vulnerable to brute force and key-based attacks',
    'ftp': 'File transfer service, often transmits credentials in plaintext',
    'smtp': 'Email service, potential for relay attacks and credential harvesting',
    'mysql': 'Database service, critical target for data exfiltration',
    'postgresql': 'Database service, potential for SQL injection and data breaches',
    'smb': 'File sharing service, common vector for lateral movement and ransomware',
    'rdp': 'Remote desktop access, high-value target for credential attacks',
    'telnet': 'Unencrypted remote access, extremely vulnerable to eavesdropping',
    'snmp': 'Network management protocol, can leak sensitive network information',
    'dns': 'Domain name service, potential for DNS poisoning and information disclosure'
  };
  
  const defaultImplication = `Service on port ${port} requires further analysis for potential vulnerabilities`;
  return implications[service.toLowerCase()] || defaultImplication;
}

module.exports = {
  processUserCommand,
  enhancedAnalyzeCommand,
  cleanupAgentCache // Export for potential cleanup scheduling
}; 