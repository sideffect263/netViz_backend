import { StreamableHTTPClientTransport } from "@modelcontextprotocol/sdk/client/streamableHttp.js";
import { createSmitheryUrl } from "@smithery/sdk/shared/config.js";
import { Client } from "@modelcontextprotocol/sdk/client/index.js";

// Ensure you have your Smithery API key in an environment variable or replace 'your-smithery-api-key'
const SMITHERY_API_KEY = process.env.SMITHERY_NMAP_API_KEY || "your-smithery-api-key";

console.log("SMITHERY_API_KEY:", SMITHERY_API_KEY);
let clientInstance;
let nmapTool;
let getScanDetailsTool; // Added for the get-scan-details tool
let isInitializing = false; // Flag to prevent re-entrant initialization

async function initializeClient() {
  // If already initialized and nmapTool is found, return immediately
  // We assume clientInstance is connected if it exists and connect() didn't throw
  if (clientInstance && nmapTool && getScanDetailsTool) { // Check for getScanDetailsTool as well
    console.log("MCP Client already initialized (nmapTool and getScanDetailsTool found).");
    return clientInstance;
  }

  // Prevent re-entry if an initialization is already in progress
  if (isInitializing) {
    console.log("MCP Client initialization already in progress, waiting...");
    // Simple wait strategy: check every 100ms for completion, up to a timeout (e.g., 10s)
    let attempts = 0;
    while (isInitializing && attempts < 100) {
      await new Promise(resolve => setTimeout(resolve, 100));
      attempts++;
    }
    if (isInitializing) {
      throw new Error("Timed out waiting for ongoing MCP client initialization.");
    }
    // After waiting, if it's now initialized, return
    if (clientInstance && nmapTool && getScanDetailsTool) { // Check for getScanDetailsTool
      return clientInstance;
    }
    // If still not initialized after waiting, throw an error or proceed to initialize (careful with loops)
    // For now, let it proceed to try initializing again if the wait didn't result in a ready client.
    // This part might need refinement based on behavior.
  }

  isInitializing = true;
  console.log("Starting MCP Client initialization process...");

  try {
    const config = {}; // Add any specific config for smithery if needed
    const serverUrl = createSmitheryUrl(
      "https://server.smithery.ai/@imjdl/nmap-mcpserver",
      { config, apiKey: SMITHERY_API_KEY }
    );

    const transport = new StreamableHTTPClientTransport(serverUrl);

    clientInstance = new Client({
      name: "NetVizAutoHackerClient",
      version: "1.0.0",
    });

    console.log("Connecting to Nmap MCP server...");
    await clientInstance.connect(transport);
    console.log("Successfully connected to Nmap MCP server.");

    const toolsResponse = await clientInstance.listTools();
    console.log("Raw tools object from clientInstance.listTools():", JSON.stringify(toolsResponse, null, 2)); 
    
    if (toolsResponse && toolsResponse.tools && Array.isArray(toolsResponse.tools)) {
      console.log(`Available tools: ${toolsResponse.tools.map((t) => t.name).join(", ")}`);
      // Find the Nmap tool, specifically named 'run-nmap-scan' based on observed output
      nmapTool = toolsResponse.tools.find(tool => tool.name === 'run-nmap-scan');
      getScanDetailsTool = toolsResponse.tools.find(tool => tool.name === 'get-scan-details'); // Find the get-scan-details tool
    } else {
      console.error("Could not find a .tools array in the response from clientInstance.listTools()");
      nmapTool = null; // Ensure nmapTool is null if not found or structure is wrong
      getScanDetailsTool = null; // Ensure getScanDetailsTool is null
    }
    
    if (!nmapTool) {
        console.error("Nmap tool ('run-nmap-scan') not found on the MCP server. Available tools:", toolsResponse.tools.map(t => t.name));
        throw new Error("Nmap tool ('run-nmap-scan') not found on the MCP server.");
    }
    if (!getScanDetailsTool) { // Check if get-scan-details tool was found
        console.error("Nmap scan details tool ('get-scan-details') not found on the MCP server. Available tools:", toolsResponse.tools.map(t => t.name));
        throw new Error("Nmap scan details tool ('get-scan-details') not found on the MCP server.");
    }
    console.log(`Using Nmap tool: ${nmapTool.name}`);
    console.log(`Using Nmap scan details tool: ${getScanDetailsTool.name}`); // Log the found tool

    return clientInstance;
  } catch (error) {
    console.error("Failed to initialize MCP client:", error);
    clientInstance = null; // Reset on failure
    nmapTool = null;
    getScanDetailsTool = null; // Reset getScanDetailsTool on failure
    isInitializing = false; // Reset flag on failure
    throw error; // Re-throw to indicate initialization failure
  }
  // Ensure the flag is reset on successful completion too
  isInitializing = false;
}

/**
 * Fetches detailed Nmap scan results using a scan ID.
 * @param {string} scanId - The ID of the scan to retrieve details for.
 * @returns {Promise<Object>} - The detailed result from the Nmap get-scan-details tool.
 */
async function getNmapScanDetails(scanId) {
  console.log(`[getNmapScanDetails ENTRY] Requesting details for scan ID: ${scanId}`);

  if (!clientInstance || !getScanDetailsTool) {
    console.log("[getNmapScanDetails] Client not fully ready (clientInstance or getScanDetailsTool missing). Attempting to initialize...");
    try {
      await initializeClient();
      console.log("[getNmapScanDetails] Initialization attempt finished.");
    } catch (initError) {
      console.error("Error during explicit initialization in getNmapScanDetails:", initError);
      throw new Error(`MCP client initialization failed: ${initError.message}`);
    }
    
    if (!clientInstance || !getScanDetailsTool) {
      console.error("[getNmapScanDetails] MCP client still not fully ready after attempted initialization.");
      throw new Error("MCP client is not initialized or get-scan-details tool not found after re-initialization attempt.");
    }
    console.log("[getNmapScanDetails] MCP client successfully initialized/confirmed.");
  } else {
    console.log("[getNmapScanDetails] Client was already ready. Proceeding.");
  }

  const toolInput = { scan_id: scanId };
  console.log(`Invoking Nmap tool "${getScanDetailsTool.name}" with params:`, toolInput);

  try {
    const result = await clientInstance.callTool({ 
      name: getScanDetailsTool.name, 
      arguments: toolInput 
    });
    console.log("Nmap get-scan-details tool invocation successful. Raw Result:", JSON.stringify(result, null, 2));

    // Attempt to parse the nmap:// URI from the response
    if (result && result.content && Array.isArray(result.content) && result.content.length > 0 && result.content[0].text) {
      const summaryText = result.content[0].text;
      const nmapUriMatch = summaryText.match(/(nmap:\/\/scan\/[a-f0-9\-]+)/i);
      
      if (nmapUriMatch && nmapUriMatch[1]) {
        const extractedNmapUri = nmapUriMatch[1];
        console.log(`[getNmapScanDetails] Extracted Nmap URI: ${extractedNmapUri}`);
        return {
          type: "nmap_uri_reference",
          uri: extractedNmapUri,
          summary: summaryText,
          originalResponse: result 
        };
      } else {
        console.warn(`[getNmapScanDetails] Could not extract nmap:// URI from response for scan ID ${scanId}. Returning original response. Summary:`, summaryText);
        return { // Return a consistent error-like structure if URI not found but call succeeded
            type: "nmap_uri_extraction_failed",
            summary: summaryText,
            originalResponse: result,
            error: "Failed to find nmap:// URI in the response text."
        };
      }
    } else {
      console.warn(`[getNmapScanDetails] Unexpected response structure from get-scan-details for scan ID ${scanId}. Cannot extract URI. Response:`, JSON.stringify(result, null, 2));
      return { // Return a consistent error-like structure for unexpected structure
            type: "nmap_unexpected_response_structure",
            originalResponse: result,
            error: "Unexpected response structure from get-scan-details tool."
      };
    }

  } catch (error) {
    console.error(`Error invoking Nmap get-scan-details tool for scan ID ${scanId}:`, error);
    if (error.message.toLowerCase().includes("client is not connected") || 
        error.message.toLowerCase().includes("transport closed") || 
        error.message.toLowerCase().includes("disconnected")) {
        console.log("Client disconnected, attempting to reconnect for get-scan-details...");
        clientInstance = null; 
        nmapTool = null;
        getScanDetailsTool = null;
        isInitializing = false;
        try {
            await initializeClient();
            if (!clientInstance || !getScanDetailsTool) {
                throw new Error("MCP client is not initialized or get-scan-details tool not found after re-initialization during error handling.");
            }
            console.log("Reconnected, retrying Nmap get-scan-details tool invocation...");
            const retryResult = await clientInstance.callTool({ 
              name: getScanDetailsTool.name, 
              arguments: toolInput 
            });
            console.log("Nmap get-scan-details tool invocation successful after retry. Raw Result:", JSON.stringify(retryResult, null, 2));
            // Re-attempt URI extraction after retry
            if (retryResult && retryResult.content && Array.isArray(retryResult.content) && retryResult.content.length > 0 && retryResult.content[0].text) {
              const summaryText = retryResult.content[0].text;
              const nmapUriMatch = summaryText.match(/(nmap:\/\/scan\/[a-f0-9\-]+)/i);
              if (nmapUriMatch && nmapUriMatch[1]) {
                const extractedNmapUri = nmapUriMatch[1];
                console.log(`[getNmapScanDetails] Extracted Nmap URI after retry: ${extractedNmapUri}`);
                return {
                  type: "nmap_uri_reference",
                  uri: extractedNmapUri,
                  summary: summaryText,
                  originalResponse: retryResult
                };
              } else {
                 console.warn(`[getNmapScanDetails] Could not extract nmap:// URI from response after retry for scan ID ${scanId}. Summary:`, summaryText);
                 return {
                    type: "nmap_uri_extraction_failed",
                    summary: summaryText,
                    originalResponse: retryResult,
                    error: "Failed to find nmap:// URI in the response text after retry."
                };
              }
            } else {
               console.warn(`[getNmapScanDetails] Unexpected response structure from get-scan-details after retry for scan ID ${scanId}. Response:`, JSON.stringify(retryResult, null, 2));
               return {
                    type: "nmap_unexpected_response_structure",
                    originalResponse: retryResult,
                    error: "Unexpected response structure from get-scan-details tool after retry."
                };
            }
        } catch (reconnectError) {
            console.error("Error during Nmap get-scan-details invocation after reconnect:", reconnectError);
            throw reconnectError;
        }
    }
    throw error;
  }
}

/**
 * Invokes the Nmap tool on the MCP server to start a scan and then fetches its details.
 * @param {Object} params - Parameters for the Nmap tool.
 * @param {string} params.target - The target IP or hostname.
 * @param {string[]} params.nmap_args - Array of Nmap arguments.
 * @returns {Promise<Object>} - The result from the Nmap tool.
 */
async function invokeNmap(params) {
  console.log("[invokeNmap ENTRY] Checking client status...");
  console.log(`[invokeNmap ENTRY] clientInstance defined: ${!!clientInstance}`);
  console.log(`[invokeNmap ENTRY] nmapTool defined: ${!!nmapTool}`);
  console.log(`[invokeNmap ENTRY] getScanDetailsTool defined: ${!!getScanDetailsTool}`);

  // Check if client is ready (clientInstance exists and nmapTool is found).
  if (!clientInstance || !nmapTool || !getScanDetailsTool) { // Also check getScanDetailsTool
    console.log("[invokeNmap] Client not fully ready (clientInstance, nmapTool, or getScanDetailsTool missing). Attempting to initialize...");
    try {
      await initializeClient();
      console.log("[invokeNmap] Initialization attempt finished.");
      console.log(`[invokeNmap POST-INIT] clientInstance defined: ${!!clientInstance}`);
      console.log(`[invokeNmap POST-INIT] nmapTool defined: ${!!nmapTool}`);
      console.log(`[invokeNmap POST-INIT] getScanDetailsTool defined: ${!!getScanDetailsTool}`);
    } catch (initError) {
      console.error("Error during explicit initialization in invokeNmap:", initError);
      throw new Error(`MCP client initialization failed: ${initError.message}`);
    }
    
    // After attempting initialization, re-check if the client is ready.
    if (!clientInstance || !nmapTool || !getScanDetailsTool) { // Also check getScanDetailsTool
      console.error("[invokeNmap] MCP client still not fully ready after attempted initialization.");
      throw new Error("MCP client is not initialized or Nmap tools not found after re-initialization attempt.");
    }
    console.log("[invokeNmap] MCP client successfully initialized/confirmed.");
  } else {
    console.log("[invokeNmap] Client was already ready. Proceeding.");
  }

  // At this point, clientInstance and nmapTool should both be valid.
  if (!clientInstance || !nmapTool || !getScanDetailsTool) { // Also check getScanDetailsTool
    console.error("[invokeNmap CRITICAL] Client or tools became undefined before tool use!");
    throw new Error("Critical error: Client state (instance or tools) lost before tool invocation.");
  }

  console.log(`Invoking Nmap tool "${nmapTool.name}" to start scan with params: target=${params.target}, options=${params.nmap_args.join(' ')}`);
  
  try {
    // The structure of the input for the Nmap tool might vary.
    // Based on observed schema for "run-nmap-scan": { target: string, options: string }
    const toolInput = {
      target: params.target,
      options: params.nmap_args.join(' ') // Nmap args should be a single string for the 'options' field
    };

    // Correct method is callTool, and it expects a single object argument
    const initialScanResult = await clientInstance.callTool({ 
      name: nmapTool.name, 
      arguments: toolInput 
    });
    console.log("Nmap run-nmap-scan tool invocation successful. Initial Result:", JSON.stringify(initialScanResult, null, 2));

    // Extract scanId from the result
    let scanId = null;
    if (initialScanResult && initialScanResult.content && initialScanResult.content[0] && initialScanResult.content[0].text) {
      const match = initialScanResult.content[0].text.match(/Scan ID: ([a-f0-9\\-]+)/i);
      if (match && match[1]) {
        scanId = match[1];
        console.log(`Extracted Scan ID: ${scanId}`);
      }
    }

    if (!scanId) {
      console.error("Could not extract Scan ID from Nmap run-nmap-scan tool response. Full response:", JSON.stringify(initialScanResult, null, 2));
      // Decide whether to throw an error or return the summary. For now, returning summary.
      // Consider changing this to throw an error if a scanId is always expected.
      return initialScanResult; // Or throw new Error("Failed to extract Scan ID from initial Nmap response.");
    }

    // Now, call getNmapScanDetails to get the detailed results
    console.log(`Fetching details for Scan ID: ${scanId}`);
    const detailedScanResult = await getNmapScanDetails(scanId);
    return detailedScanResult; // Return the detailed results

  } catch (error) {
    console.error("Error invoking Nmap tool (either run-nmap-scan or subsequent get-scan-details):", error);
    // Check if the error is due to a disconnected client and try to reconnect
    // (Assuming disconnect error might still mention "Client is not connected" or similar)
    if (error.message.toLowerCase().includes("client is not connected") || 
        error.message.toLowerCase().includes("transport closed") || 
        error.message.toLowerCase().includes("disconnected")) {
        console.log("Client disconnected, attempting to reconnect...");
        clientInstance = null; // Force reinitialization fully
        nmapTool = null;
        getScanDetailsTool = null;
        isInitializing = false; // Reset initializing flag
        try {
            await initializeClient();
             if (!clientInstance || !nmapTool || !getScanDetailsTool) { // Also check getScanDetailsTool
                throw new Error("MCP client is not initialized or Nmap tools not found after re-initialization during error handling.");
            }
            console.log("Reconnected, retrying Nmap tool invocation sequence...");
            // Retry the entire sequence: run-nmap-scan then get-scan-details
            const retryInitialResult = await clientInstance.callTool({ 
              name: nmapTool.name, 
              arguments: toolInput // toolInput is from the outer scope
            });
            console.log("Nmap run-nmap-scan tool invocation successful after retry. Initial Result:", JSON.stringify(retryInitialResult, null, 2));
            
            let retryScanId = null;
            if (retryInitialResult && retryInitialResult.content && retryInitialResult.content[0] && retryInitialResult.content[0].text) {
              const match = retryInitialResult.content[0].text.match(/Scan ID: ([a-f0-9\\-]+)/i);
              if (match && match[1]) {
                retryScanId = match[1];
                console.log(`Extracted Scan ID after retry: ${retryScanId}`);
              }
            }

            if (!retryScanId) {
              console.error("Could not extract Scan ID from Nmap run-nmap-scan tool response after retry. Full response:", JSON.stringify(retryInitialResult, null, 2));
              return retryInitialResult; // Or throw
            }
            
            const retryDetailedResult = await getNmapScanDetails(retryScanId); // Call with retryScanId
            console.log("Nmap get-scan-details tool invocation successful after retry. Detailed Result:", JSON.stringify(retryDetailedResult, null, 2));
            return retryDetailedResult;
        } catch (reconnectError) {
            console.error("Error during Nmap tool invocation after reconnect:", reconnectError);
            throw reconnectError;
        }
    }
    throw error;
  }
}

// Optional: Export initializeClient if you want to explicitly initialize it at startup
export { initializeClient, invokeNmap, getNmapScanDetails }; // Export getNmapScanDetails as well

// Initialize the client when the module is loaded
// initializeClient().catch(error => {
//   console.error("Initial MCP client connection failed:", error);
//   // Decide how to handle this - maybe the app can run without it, or it should fail hard.
// }); 