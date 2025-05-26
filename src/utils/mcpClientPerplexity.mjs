import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { createSmitheryUrl } from "@smithery/sdk/shared/config.js";
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Default timeout value in milliseconds (3 minutes)
const DEFAULT_TIMEOUT = 180000;

// Default server URL - can be overridden by environment variable
const DEFAULT_SERVER_URL = "https://server.smithery.ai/@arjunkmrm/perplexity-search";

let clientInstance;
let perplexityTools = {};
let isInitializing = false;

/**
 * Validates the environment configuration
 * @throws {Error} If required configuration is missing
 */
function validateConfig() {
  const smitheryApiKey = process.env.SMITHERY_API_KEY || '9f3d1ac5-c314-404e-a19c-606e380cc093'; // Assuming you still use a general Smithery API Key
  const perplexityApiKey = process.env.PERPLEXITY_API_KEY;

  if (!smitheryApiKey) {
    throw new Error("SMITHERY_API_KEY not found in environment variables. Please set it in your .env file.");
  }
  if (!perplexityApiKey) {
    throw new Error("PERPLEXITY_API_KEY not found in environment variables. Please set it in your .env file.");
  }
  
  const serverUrl = process.env.MCP_PERPLEXITY_SERVER_URL || DEFAULT_SERVER_URL;
  if (!serverUrl) {
    throw new Error("MCP_PERPLEXITY_SERVER_URL not found in environment variables and no default URL available.");
  }
  
  return { smitheryApiKey, perplexityApiKey, serverUrl };
}

async function initializeNewClient() {
  // If already initialized and tools are found, return immediately
  if (clientInstance && Object.keys(perplexityTools).length > 0) {
    console.log("Perplexity MCP Client already initialized.");
    return clientInstance;
  }

  // Prevent re-entry if an initialization is already in progress
  if (isInitializing) {
    console.log("Perplexity MCP Client initialization already in progress, waiting...");
    let attempts = 0;
    while (isInitializing && attempts < 100) { // Wait for up to 10 seconds
      await new Promise(resolve => setTimeout(resolve, 100));
      attempts++;
    }
    if (isInitializing) { // If still initializing after waiting
      isInitializing = false; // Reset flag to allow future attempts
      throw new Error("Timed out waiting for ongoing Perplexity MCP client initialization.");
    }
    // If another process finished initialization, return the instance
    if (clientInstance && Object.keys(perplexityTools).length > 0) {
      return clientInstance;
    }
  }

  isInitializing = true;
  console.log("Starting Perplexity MCP Client initialization process...");

  try {
    // Validate configuration
    const { smitheryApiKey, perplexityApiKey, serverUrl } = validateConfig();
    console.log(`Using Perplexity server URL: ${serverUrl}`);

    // Create Smithery URL with API key and config
    const config = { perplexityApiKey };
    const smitheryUrl = createSmitheryUrl(serverUrl, {
      apiKey: smitheryApiKey, // This is the Smithery API key for the MCP server itself
      config: config // This is the Perplexity API key passed as config to the MCP server
    });

    // Create transport with server URL and timeout configuration
    const transport = new StreamableHTTPClientTransport(smitheryUrl, {
      requestTimeout: DEFAULT_TIMEOUT,
      retryAttempts: 3,
      retryDelay: 1000
    });

    clientInstance = new Client({
      name: "NetVizPerplexityClient",
      version: "1.0.0",
    });

    console.log("Connecting to Perplexity MCP server...");
    await clientInstance.connect(transport);
    console.log("Successfully connected to Perplexity MCP server.");

    const toolsResponse = await clientInstance.listTools();
    if (!toolsResponse || !toolsResponse.tools) {
      throw new Error("Invalid response from server when listing Perplexity tools");
    }
    
    console.log("Available tools on Perplexity server:", toolsResponse.tools.map(t => t.name).join(", "));

    // Store all available tools
    toolsResponse.tools.forEach(tool => {
      perplexityTools[tool.name] = tool;
    });

    if (Object.keys(perplexityTools).length === 0) {
      // This might be normal if the server has no pre-defined tools and expects dynamic ones,
      // or if it's a single-function server. Adjust warning if needed.
      console.warn("No specific Perplexity tools found listed on the MCP server. This might be expected for some servers.");
    }

    isInitializing = false;
    return clientInstance;
  } catch (error) {
    console.error("Failed to initialize Perplexity MCP client:", error);
    
    if (error.message.includes("502")) {
      console.error("Server returned 502 Bad Gateway. Check Perplexity server URL and status.");
    } else if (error.message.includes("401") || error.message.includes("Unauthorized")) {
      console.error("Authentication failed. Check your SMITHERY_API_KEY and PERPLEXITY_API_KEY.");
    } else if (error.message.includes("timeout")) {
      console.error("Connection timed out. Check network and Perplexity server responsiveness.");
    }
    
    clientInstance = null;
    perplexityTools = {};
    isInitializing = false;
    throw error;
  }
}

/**
 * Invokes a Perplexity tool on the MCP server
 * @param {string} toolName - Name of the tool to invoke
 * @param {Object} params - Parameters for the tool
 * @returns {Promise<Object>} - The result from the tool
 */
async function invokePerplexityTool(toolName, params) {
  console.log(`[invokePerplexityTool] Checking client status for tool: ${toolName}`);

  if (!clientInstance || !perplexityTools[toolName]) {
    // If toolName is not in perplexityTools, it might be a generic call if the server supports it.
    // For now, we assume tools are listed. If not, this check needs adjustment.
    console.log(`[invokePerplexityTool] Client not fully ready or tool ${toolName} not listed. Attempting to initialize...`);
    try {
      await initializeNewClient();
    } catch (initError) {
      console.error(`Error during initialization for ${toolName}:`, initError);
      throw new Error(`Perplexity MCP client initialization failed: ${initError.message}`);
    }

    if (!clientInstance) { // Check clientInstance again
        throw new Error(`Perplexity MCP client is not initialized after attempting re-initialization.`);
    }
    // If the tool is still not found after init, it might be an issue or the server doesn't list it.
    // For now, we proceed, but this could be a point of failure if the tool truly doesn't exist.
     if (!perplexityTools[toolName]) {
        console.warn(`Tool ${toolName} not found in listed tools after initialization. Proceeding with invocation, but this might fail if the tool does not exist.`);
    }
  }

  try {
    console.log(`Invoking Perplexity tool "${toolName}" with params:`, params);
    const result = await clientInstance.callTool({
      name: toolName,
      arguments: params
    });
    
    console.log(`Perplexity tool "${toolName}" invocation successful.`);
    return result;
  } catch (error) {
    console.error(`Error invoking Perplexity tool "${toolName}":`, error);
    
    const isConnectionIssue = error.message.toLowerCase().includes("client is not connected") ||
                            error.message.toLowerCase().includes("transport closed") ||
                            error.message.toLowerCase().includes("disconnected");
    
    if (isConnectionIssue) {
      console.log("Client disconnected, attempting to reconnect...");
      clientInstance = null;
      perplexityTools = {};
      isInitializing = false; // Reset isInitializing
      
      try {
        await initializeNewClient();
        // No need to check for tool existence here again, will be checked at the start of the function call.
        console.log("Reconnected to Perplexity server, retrying tool invocation...");
        return invokePerplexityTool(toolName, params); // Recursive call to retry
      } catch (reconnectError) {
        console.error("Error during tool invocation after reconnect to Perplexity server:", reconnectError);
        throw reconnectError;
      }
    }
    
    throw error; // Re-throw original error if not a connection issue or if reconnect fails
  }
}

/**
 * Lists all available Perplexity tools
 * @returns {Promise<Array>} - Array of available tool names
 */
async function listAvailablePerplexityTools() {
  if (!clientInstance || Object.keys(perplexityTools).length === 0) {
    // Attempt to initialize if not already, or if tools list is empty
    await initializeNewClient();
  }
  return Object.keys(perplexityTools);
}

export { initializeNewClient as initializePerplexityClient, invokePerplexityTool, listAvailablePerplexityTools }; 