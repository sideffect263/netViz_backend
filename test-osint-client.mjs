import { initializeNewClient, invokeOsintTool, listAvailableTools } from './src/utils/mcpClientOsint.mjs';
import dotenv from 'dotenv';

// Load environment variables
dotenv.config();

async function testAllOsintTools() {
  try {
    console.log('Initializing OSINT MCP client for comprehensive test...');
    await initializeNewClient();

    console.log('\nListing available tools...');
    const tools = await listAvailableTools();
    console.log('Available OSINT tools:', tools);

    if (tools.length === 0) {
      console.log('No OSINT tools found to test.');
      return;
    }

    const testTarget = 'example.com'; // Common target for testing

    for (const toolName of tools) {
      console.log(`\n--- Testing tool: ${toolName} ---`);
      
      // Basic parameters - some tools might need more or different ones.
      // This is a starting point for discovery.
      let params = { target: testTarget };

      // Adjust params based on known tool requirements (example for nmap_scan)
      if (toolName === 'nmap_scan') {
        params = {
          target: testTarget,
          // Defaulting to a very light scan for testing.
          // The actual nmap_scan tool in mcp-osint-server might have its own defaults
          // or expect flags in a specific format.
          // For now, let's assume it can take simple flags or has sensible defaults.
          flags: '-F' // Fast scan (top 100 ports)
        };
      }
      // Add other tool-specific parameter adjustments here if known upfront

      try {
        console.log(`Invoking ${toolName} with parameters:`, params);
        const result = await invokeOsintTool(toolName, params);
        console.log(`Result for ${toolName}:`, JSON.stringify(result, null, 2));
      } catch (error) {
        console.error(`Error testing tool ${toolName}:`, error.message);
        if (error.response && error.response.data) {
          console.error('Error details:', JSON.stringify(error.response.data, null, 2));
        }
      }
    }

  } catch (error) {
    console.error('Error during comprehensive OSINT client test:', error);
  }
}

// Run the comprehensive test
testAllOsintTools(); 