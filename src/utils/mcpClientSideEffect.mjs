import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createSmitheryUrl } from "@smithery/sdk/shared/config.js"; // Corrected import path
import { Client } from "@modelcontextprotocol/sdk/client/index.js";

// Ensure you have your Smithery API key for the new server in an environment variable
const SMITHERY_API_KEY = process.env.SMITHERY_NMAP_API_KEY || "your-smithery-api-key";
// Default timeout value in milliseconds (3 minutes instead of 60 seconds)
const DEFAULT_TIMEOUT = 180000;

console.log("SMITHERY_NEWMCP_API_KEY:", SMITHERY_API_KEY);
let clientInstance;
let nmapScanTool;
let getInfoTool; // For the 'getInfo' tool on the new server
let isInitializing = false; // Flag to prevent re-entrant initialization

async function initializeNewClient() {
  // If already initialized and nmapScanTool is found, return immediately
  if (clientInstance && nmapScanTool) {
    console.log("New MCP Client already initialized (nmapScanTool found).");
    return clientInstance;
  }

  // Prevent re-entry if an initialization is already in progress
  if (isInitializing) {
    console.log("New MCP Client initialization already in progress, waiting...");
    let attempts = 0;
    while (isInitializing && attempts < 100) {
      await new Promise(resolve => setTimeout(resolve, 100));
      attempts++;
    }
    if (isInitializing) {
      isInitializing = false; // Reset flag on timeout
      throw new Error("Timed out waiting for ongoing New MCP client initialization.");
    }
    // After waiting, if it's now initialized, return
    if (clientInstance && nmapScanTool) {
      return clientInstance;
    }
    // If still not initialized after waiting, proceed to initialize.
  }

  isInitializing = true;
  console.log("Starting New MCP Client initialization process...");

  try {
    const config = {
      requestTimeout: DEFAULT_TIMEOUT // Increase the default timeout to 3 minutes
    };
    const serverUrl = createSmitheryUrl(
      "https://server.smithery.ai/@sideffect263/nmap-mcp-server", // New server URL
      { config, apiKey: SMITHERY_API_KEY }
    );

    const transport = new StreamableHTTPClientTransport(serverUrl);

    clientInstance = new Client({
      name: "NetVizSideEffectNmapClient", // Updated client name
      version: "1.0.0",
    });

    console.log("Connecting to New Nmap MCP server...");
    await clientInstance.connect(transport);
    console.log("Successfully connected to New Nmap MCP server.");

    const toolsResponse = await clientInstance.listTools();
    console.log("Raw tools object from New clientInstance.listTools():", JSON.stringify(toolsResponse, null, 2));

    if (toolsResponse && toolsResponse.tools && Array.isArray(toolsResponse.tools)) {
      console.log(`Available tools on New server: ${toolsResponse.tools.map((t) => t.name).join(", ")}`);
      // Find tools based on the new server's tool names
      nmapScanTool = toolsResponse.tools.find(tool => tool.name === 'nmapScan');
      getInfoTool = toolsResponse.tools.find(tool => tool.name === 'getInfo');
    } else {
      console.error("Could not find a .tools array in the response from New clientInstance.listTools()");
      nmapScanTool = null;
      getInfoTool = null;
    }

    if (!nmapScanTool) {
      console.error("Nmap tool ('nmapScan') not found on the New MCP server. Available tools:", toolsResponse.tools ? toolsResponse.tools.map(t => t.name).join(", ") : "unknown");
      throw new Error("Nmap tool ('nmapScan') not found on the New MCP server.");
    }
    console.log(`Using Nmap tool on New server: ${nmapScanTool.name}`);

    if (getInfoTool) {
      console.log(`Using GetInfo tool on New server: ${getInfoTool.name}`);
    } else {
      console.warn("GetInfo tool ('getInfo') not found on the New MCP server. This might be optional.");
    }
    
    isInitializing = false; // Reset flag on successful completion
    return clientInstance;
  } catch (error) {
    console.error("Failed to initialize New MCP client:", error);
    clientInstance = null;
    nmapScanTool = null;
    getInfoTool = null;
    isInitializing = false; // Reset flag on failure
    throw error; // Re-throw to indicate initialization failure
  }
}

/**
 * Simplifies scan parameters to make them less intensive
 * @param {string} flags - The original Nmap flags
 * @param {number} level - The simplification level (higher means more simplified)
 * @returns {string} - Simplified flags
 */
function simplifyNmapFlags(flags, level = 1) {
  let flagsArray = flags.split(' ').filter(flag => flag.trim() !== '');
  
  // Always start with the original flags
  if (level === 0) return flags;
  
  // Level 1: Limit port range and remove service detection
  if (level === 1) {
    // Replace full port scan with common ports
    if (flags.includes('-p-')) {
      flagsArray = flagsArray.filter(flag => !flag.startsWith('-p'));
      flagsArray.push('-p', '1-1000');
    }
    
    // Remove service detection if present
    flagsArray = flagsArray.filter(flag => flag !== '-sV');
    
    // Add faster timing
    if (!flags.includes('-T')) {
      flagsArray.push('-T4');
    }
  }
  
  // Level 2: Further simplify to just a few ports
  if (level === 2) {
    // Limit to just the most common ports
    flagsArray = flagsArray.filter(flag => !flag.startsWith('-p'));
    flagsArray.push('-p', '22,80,443,3389,8080');
    
    // Remove any script or OS detection
    flagsArray = flagsArray.filter(flag => !flag.startsWith('-A') && !flag.startsWith('-O'));
    
    // Set timing to maximum
    flagsArray = flagsArray.filter(flag => !flag.startsWith('-T'));
    flagsArray.push('-T5');
  }
  
  return flagsArray.join(' ');
}

/**
 * Invokes the Nmap 'nmapScan' tool on the new MCP server with automatic retry on timeout.
 * @param {Object} params - Parameters for the Nmap tool.
 * @param {string} params.target - The target IP or hostname.
 * @param {string[]} params.nmap_args - Array of Nmap arguments (will be joined into a single string for 'flags').
 * @param {number} [params.timeout] - Optional timeout in milliseconds.
 * @returns {Promise<Object>} - The raw result from the 'nmapScan' tool.
 */
async function invokeNmapScan(params) {
  console.log("[invokeNmapScan ENTRY] Checking New client status...");

  if (!clientInstance || !nmapScanTool) {
    console.log("[invokeNmapScan] New Client not fully ready (clientInstance or nmapScanTool missing). Attempting to initialize...");
    try {
      await initializeNewClient();
      console.log("[invokeNmapScan] Initialization attempt finished for New client.");
    } catch (initError) {
      console.error("Error during explicit initialization in invokeNmapScan for New client:", initError);
      throw new Error(`New MCP client initialization failed: ${initError.message}`);
    }

    if (!clientInstance || !nmapScanTool) {
      console.error("[invokeNmapScan] New MCP client still not fully ready after attempted initialization.");
      throw new Error("New MCP client is not initialized or nmapScan tool not found after re-initialization attempt.");
    }
    console.log("[invokeNmapScan] New MCP client successfully initialized/confirmed.");
  } else {
    console.log("[invokeNmapScan] New Client was already ready. Proceeding.");
  }

  // Start with the original flags
  let currentFlags = params.nmap_args.join(' ');
  let simplificationLevel = 0;
  let maxRetries = 2; // Maximum number of retries with simplified parameters
  
  // Track partial results in case we need to return something after a timeout
  let partialResult = null;

  while (simplificationLevel <= maxRetries) {
    const toolInput = {
      target: params.target,
      flags: currentFlags
    };
    
    console.log(`Invoking Nmap tool "${nmapScanTool.name}" on New server with params (simplification level ${simplificationLevel}):`, toolInput);

    try {
      const result = await clientInstance.callTool({
        name: nmapScanTool.name,
        arguments: toolInput
      });
      
      console.log(`New Nmap 'nmapScan' tool invocation successful at simplification level ${simplificationLevel}.`);
      
      // The scan succeeded, return the result
      return result;
    } catch (error) {
      console.error(`Error invoking New Nmap 'nmapScan' tool for target ${params.target} (simplification level ${simplificationLevel}):`, error);
      
      // Check if it's a timeout error
      const isTimeout = error.message.toLowerCase().includes('timeout') || 
                       (error.code && error.code === -32001);
      
      // Check for connection issues
      const isConnectionIssue = error.message.toLowerCase().includes("client is not connected") ||
                              error.message.toLowerCase().includes("transport closed") ||
                              error.message.toLowerCase().includes("disconnected");
      
      if (isConnectionIssue) {
        console.log("New Client disconnected, attempting to reconnect for 'nmapScan'...");
        clientInstance = null;
        nmapScanTool = null;
        getInfoTool = null;
        isInitializing = false; // Reset initializing flag
        
        try {
          await initializeNewClient();
          if (!clientInstance || !nmapScanTool) {
            throw new Error("New MCP client is not initialized or nmapScan tool not found after re-initialization during error handling.");
          }
          console.log("Reconnected to New server, continuing with retries...");
          // Continue with the next retry attempt (don't increment simplificationLevel)
          continue;
        } catch (reconnectError) {
          console.error("Error during New Nmap 'nmapScan' invocation after reconnect:", reconnectError);
          // If we've collected any partial results, return those
          if (partialResult) {
            console.log("Returning partial results from previous attempt");
            return partialResult;
          }
          throw reconnectError;
        }
      }
      
      // If it's a timeout and we haven't reached max retries, simplify the scan parameters
      if (isTimeout && simplificationLevel < maxRetries) {
        simplificationLevel++;
        currentFlags = simplifyNmapFlags(currentFlags, simplificationLevel);
        console.log(`Simplified scan parameters to level ${simplificationLevel}: ${currentFlags}`);
        continue;
      }
      
      // If it's not a timeout or we've reached max retries, throw the error
      if (partialResult) {
        console.log("Returning partial results from previous successful scan");
        return partialResult;
      }
      
      // If we have no partial results, create a basic result
      const errorResult = {
        content: [{
          text: `Scan of ${params.target} failed after ${simplificationLevel} retry attempts: ${error.message}. You may want to try a less intensive scan.`
        }]
      };
      
      return errorResult;
    }
  }
  
  // This should not be reached due to the return statements above
  throw new Error(`Failed to scan ${params.target} after multiple attempts with simplified parameters.`);
}

export { initializeNewClient, invokeNmapScan };

// Optional: Initialize the client when the module is loaded.
// initializeNewClient().catch(error => {
//   console.error("Initial New MCP client connection failed:", error);
//   // Decide how to handle this - maybe the app can run without it, or it should fail hard.
// }); 