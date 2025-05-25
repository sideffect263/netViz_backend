import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";
import { createSmitheryUrl } from "@smithery/sdk/shared/config.js";
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

// Default timeout value in milliseconds (3 minutes)
const DEFAULT_TIMEOUT = 180000;

// Default server URL - can be overridden by environment variable
const DEFAULT_SERVER_URL = "https://server.smithery.ai/@himanshusanecha/mcp-osint-server";

let clientInstance;
let osintTools = {};
let isInitializing = false;

/**
 * Validates the environment configuration
 * @throws {Error} If required configuration is missing
 */
function validateConfig() {
  const apiKey = process.env.SMITHERY_API_KEY || '9f3d1ac5-c314-404e-a19c-606e380cc093';
  console.log("API Key:", apiKey);
  if (!apiKey) {
    throw new Error("SMITHERY_API_KEY not found in environment variables. Please set it in your .env file.");
  }
  
  const serverUrl = process.env.MCP_SERVER_URL || DEFAULT_SERVER_URL;
  if (!serverUrl) {
    throw new Error("MCP_SERVER_URL not found in environment variables and no default URL available.");
  }
  
  return { apiKey, serverUrl };
}

async function initializeNewClient() {
  // If already initialized and tools are found, return immediately
  if (clientInstance && Object.keys(osintTools).length > 0) {
    console.log("OSINT MCP Client already initialized.");
    return clientInstance;
  }

  // Prevent re-entry if an initialization is already in progress
  if (isInitializing) {
    console.log("OSINT MCP Client initialization already in progress, waiting...");
    let attempts = 0;
    while (isInitializing && attempts < 100) {
      await new Promise(resolve => setTimeout(resolve, 100));
      attempts++;
    }
    if (isInitializing) {
      isInitializing = false;
      throw new Error("Timed out waiting for ongoing OSINT MCP client initialization.");
    }
    if (clientInstance && Object.keys(osintTools).length > 0) {
      return clientInstance;
    }
  }

  isInitializing = true;
  console.log("Starting OSINT MCP Client initialization process...");

  try {
    // Validate configuration
    const { apiKey, serverUrl } = validateConfig();
    console.log(`Using server URL: ${serverUrl}`);

    // Create Smithery URL with API key
    const smitheryUrl = createSmitheryUrl(serverUrl, {
      apiKey: apiKey
    });

    // Create transport with server URL and timeout configuration
    const transport = new StreamableHTTPClientTransport(smitheryUrl, {
      requestTimeout: DEFAULT_TIMEOUT,
      retryAttempts: 3, // Add retry attempts
      retryDelay: 1000 // 1 second delay between retries
    });

    clientInstance = new Client({
      name: "NetVizOsintClient",
      version: "1.0.0",
    });

    console.log("Connecting to OSINT MCP server...");
    await clientInstance.connect(transport);
    console.log("Successfully connected to OSINT MCP server.");

    const toolsResponse = await clientInstance.listTools();
    if (!toolsResponse || !toolsResponse.tools) {
      throw new Error("Invalid response from server when listing tools");
    }
    
    console.log("Available tools on OSINT server:", toolsResponse.tools.map(t => t.name).join(", "));

    // Store all available tools
    toolsResponse.tools.forEach(tool => {
      osintTools[tool.name] = tool;
    });

    if (Object.keys(osintTools).length === 0) {
      throw new Error("No OSINT tools found on the MCP server.");
    }

    isInitializing = false;
    return clientInstance;
  } catch (error) {
    console.error("Failed to initialize OSINT MCP client:", error);
    
    // Provide more helpful error messages based on the error type
    if (error.message.includes("502")) {
      console.error("Server returned 502 Bad Gateway. This usually means the server is down or not accessible.");
      console.error("Please check if the server URL is correct and the server is running.");
    } else if (error.message.includes("401")) {
      console.error("Authentication failed. Please check your SMITHERY_API_KEY.");
    } else if (error.message.includes("timeout")) {
      console.error("Connection timed out. Please check your network connection and try again.");
    }
    
    clientInstance = null;
    osintTools = {};
    isInitializing = false;
    throw error;
  }
}

/**
 * Invokes an OSINT tool on the MCP server
 * @param {string} toolName - Name of the tool to invoke
 * @param {Object} params - Parameters for the tool
 * @returns {Promise<Object>} - The result from the tool
 */
async function invokeOsintTool(toolName, params) {
  console.log(`[invokeOsintTool] Checking client status for tool: ${toolName}`);

  if (!clientInstance || !osintTools[toolName]) {
    console.log(`[invokeOsintTool] Client not fully ready for ${toolName}. Attempting to initialize...`);
    try {
      await initializeNewClient();
    } catch (initError) {
      console.error(`Error during initialization for ${toolName}:`, initError);
      throw new Error(`OSINT MCP client initialization failed: ${initError.message}`);
    }

    if (!clientInstance || !osintTools[toolName]) {
      throw new Error(`OSINT MCP client is not initialized or ${toolName} tool not found.`);
    }
  }

  try {
    console.log(`Invoking OSINT tool "${toolName}" with params:`, params);
    const result = await clientInstance.callTool({
      name: toolName,
      arguments: params
    });
    
    console.log(`OSINT tool "${toolName}" invocation successful.`);
    return result;
  } catch (error) {
    console.error(`Error invoking OSINT tool "${toolName}":`, error);
    
    // Check for connection issues
    const isConnectionIssue = error.message.toLowerCase().includes("client is not connected") ||
                            error.message.toLowerCase().includes("transport closed") ||
                            error.message.toLowerCase().includes("disconnected");
    
    if (isConnectionIssue) {
      console.log("Client disconnected, attempting to reconnect...");
      clientInstance = null;
      osintTools = {};
      isInitializing = false;
      
      try {
        await initializeNewClient();
        if (!clientInstance || !osintTools[toolName]) {
          throw new Error(`OSINT MCP client is not initialized or ${toolName} tool not found after re-initialization.`);
        }
        console.log("Reconnected to server, retrying tool invocation...");
        return invokeOsintTool(toolName, params);
      } catch (reconnectError) {
        console.error("Error during tool invocation after reconnect:", reconnectError);
        throw reconnectError;
      }
    }
    
    throw error;
  }
}

/**
 * Lists all available OSINT tools
 * @returns {Promise<Array>} - Array of available tool names
 */
async function listAvailableTools() {
  if (!clientInstance) {
    await initializeNewClient();
  }
  return Object.keys(osintTools);
}

export { initializeNewClient, invokeOsintTool, listAvailableTools }; 