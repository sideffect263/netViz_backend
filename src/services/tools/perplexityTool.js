const { DynamicTool } = require("langchain/tools");
// const { initializePerplexityClient, invokePerplexityTool, listAvailablePerplexityTools } = require("../../utils/mcpClientPerplexity.mjs"); // Commented out old require

// Cache for Perplexity tools
let perplexityToolsCache = null;
let lastCacheTime = null;
const CACHE_DURATION = 5 * 60 * 1000; // 5 minutes

/**
 * Creates a LangChain tool for Perplexity search.
 * This tool will allow the agent to use the Perplexity MCP client for web searches.
 */
async function createPerplexityTool() {
  try {
    // Dynamically import the ES Module
    const { initializePerplexityClient, invokePerplexityTool, listAvailablePerplexityTools } = await import("../../utils/mcpClientPerplexity.mjs");

    // Ensure client is initialized
    await initializePerplexityClient();

    // For Perplexity, we might have a generic search tool rather than multiple specific ones.
    // The example provided `await client.listTools()` which might return a specific tool name like 'perplexity_search' or similar.
    // We will assume there's one primary tool for search. If the Perplexity MCP server
    // exposes multiple tools, this logic might need to be adapted or multiple Langchain tools created.

    // Let's assume the main (or only) tool exposed by the Perplexity MCP server is named 'perplexity_search'
    // If listAvailablePerplexityTools() returns specific names, use the first one or a predefined one.
    const availableTools = await listAvailablePerplexityTools();
    let toolName = "perplexity_search"; // Default or expected name

    if (availableTools && availableTools.length > 0) {
      // You might want to pick a specific tool if multiple are listed,
      // or if the server guarantees a certain named tool for general search.
      toolName = availableTools.find(name => name.toLowerCase().includes("search")) || availableTools[0];
      console.log(`Using Perplexity tool from MCP server: ${toolName}`);
    } else {
      // This case means listTools() returned empty or was not as expected.
      // We can still proceed if the MCP server is designed to handle a default tool invocation
      // without it being explicitly listed, or if `toolName` is a known convention.
      console.warn(`No specific tools listed by Perplexity MCP server, or listTools() was not implemented as expected. Proceeding with default tool name "${toolName}". This may fail if the server requires a specific, listed tool.`);
      // It's crucial that the Perplexity MCP server can handle `client.callTool({ name: "perplexity_search", ... })`
      // even if "perplexity_search" isn't in the `listTools()` output.
    }
    
    // It's also possible the server itself doesn't require a `toolName` for a simple pass-through query.
    // The example `const tools = await client.listTools()` suggests tools are named.
    // We will proceed assuming a named tool is used.

    return new DynamicTool({
      name: "search", // This is the name LangChain will use
      description: `Performs a web search using Perplexity to answer questions or find information. Input should be a search query string. Provides concise answers from up-to-date sources. Useful for general knowledge, current events, and specific information lookups. The Perplexity MCP tool name being called is '${toolName}'.`,
      func: async (input) => {
        if (typeof input !== 'string' || input.trim() === "") {
          return "Input to search must be a non-empty string search query.";
        }
        try {
          console.log(`search Tool: Invoking MCP tool '${toolName}' with input: ${input}`);
          // The Perplexity MCP server's tool (e.g., 'perplexity_search') likely expects parameters.
          // Based on the schema `{ "perplexityApiKey": "string" }` for config,
          // the tool arguments might be something like `{ "query": "string" }`.
          // We'll assume the input string is directly the query.
          const result = await invokePerplexityTool(toolName, { query: input });
          
          // Process the result: The MCP SDK's `callTool` returns a result object.
          // We need to extract the meaningful part for the LLM.
          // This depends on the Perplexity MCP server's response structure.
          // Let's assume it returns an object like `{ answer: "..." }` or similar.
          if (result && typeof result === 'object') {
            // Attempt to find a common key for the answer.
            const answerKey = Object.keys(result).find(k => k.toLowerCase().includes('answer') || k.toLowerCase().includes('result') || k.toLowerCase().includes('text'));
            if (answerKey) {
              console.log(`search Tool: Successfully received response. Extracted answer from key '${answerKey}'.`);
              return String(result[answerKey]);
            }
            // If no common key, return the stringified object, which might be useful.
             console.warn("search Tool: Response received, but couldn't find a standard answer key. Returning stringified result.", result);
            return JSON.stringify(result);
          } else if (result) {
            // If the result is a primitive (e.g. string directly), return it.
            console.log("search Tool: Successfully received primitive response.");
            return String(result);
          }
          console.warn("search Tool: Received an empty or unexpected result from invokePerplexityTool.", result);
          return "Perplexity search did not return a result or the result was empty.";

        } catch (error) {
          console.error(`Error in search tool (calling MCP tool '${toolName}'):`, error);
          return `Error performing Perplexity search: ${error.message}. Check if the Perplexity MCP server is running and configured correctly.`;
        }
      },
    });

  } catch (error) {
    console.error("Failed to create Perplexity Search tool:", error);
    // Return null or throw, so it can be filtered out in aiAgentService
    return null; 
  }
}

module.exports = { createPerplexityTool }; 