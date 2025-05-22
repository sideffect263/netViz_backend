const { ChatAnthropic } = require('@langchain/anthropic');
const { DynamicTool, DynamicStructuredTool } = require('langchain/tools');
const { initializeAgentExecutorWithOptions } = require('langchain/agents');

// Import the MCP client for Nmap
let mcpClientModule;
async function getMcpClient() {
  if (!mcpClientModule) {
    mcpClientModule = await import('../utils/mcpClientSideEffect.mjs');
  }
  return mcpClientModule;
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

// Initialize the LLM
function initializeLLM() {
  const llm = new ChatAnthropic({
    anthropicApiKey: process.env.ANTHROPIC_API,
    modelName: process.env.ANTHROPIC_MODEL || 'claude-3-sonnet-20240229',
    temperature: 0.7,
    maxTokens: 4000,
    streaming: true,
  });
  
  return llm;
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

// Initialize the agent
async function initializeAgent(tools, callbacks) {
  const llm = initializeLLM();
  
  const agent = await initializeAgentExecutorWithOptions(
    tools,
    llm,
    {
      agentType: "chat-conversational-react-description",
      verbose: true,
      maxIterations: 5,
      callbacks: callbacks
    }
  );
  
  return agent;
}

// Process user command
async function processUserCommand(command, sessionId, sendEventToSocket) {
  try {
    // Create callback handler for WebSocket streaming
    const callbacks = [new WebSocketCallbackHandler(sessionId, sendEventToSocket)];
    
    // Initialize tools and agent
    const tools = await initializeTools();
    const agent = await initializeAgent(tools, callbacks);
    
    // Execute the agent with the user command
    const result = await agent.invoke({
      input: command
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

module.exports = {
  processUserCommand
}; 