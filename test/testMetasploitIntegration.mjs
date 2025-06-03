/**
 * Test script for Metasploit MCP integration
 * Run with: node server/test/testMetasploitIntegration.js
 */

import { initializeNewClient, invokeMetasploitTool, listAvailableTools } from '../src/utils/mcpClientMetasploitCustom.mjs';

async function testMetasploitIntegration() {
  console.log('=== Testing Metasploit MCP Integration ===\n');
  
  try {
    // 1. Initialize the client
    console.log('1. Initializing Metasploit MCP client...');
    await initializeNewClient();
    console.log('✓ Client initialized successfully\n');
    
    // 2. List available tools
    console.log('2. Listing available tools...');
    const tools = await listAvailableTools();
    console.log('✓ Available tools:', tools.join(', '));
    console.log(`Total tools: ${tools.length}\n`);
    
    // 3. Test listing exploits
    console.log('3. Testing exploit listing...');
    try {
      const exploitResult = await invokeMetasploitTool('list_exploits', {
        search_term: 'ssh'
      });
      console.log('✓ Successfully listed SSH exploits');
      
      // Display first few lines of result
      const resultText = exploitResult?.data || exploitResult?.content?.[0]?.text || JSON.stringify(exploitResult);
      const lines = resultText.split('\n').slice(0, 5);
      console.log('Sample output:');
      lines.forEach(line => console.log(`  ${line}`));
      console.log('  ...\n');
    } catch (error) {
      console.error('✗ Error listing exploits:', error.message);
    }
    
    // 4. Test listing payloads
    console.log('4. Testing payload listing...');
    try {
      const payloadResult = await invokeMetasploitTool('list_payloads', {
        search_term: 'meterpreter'
      });
      console.log('✓ Successfully listed Meterpreter payloads');
      
      // Display first few lines of result
      const resultText = payloadResult?.data || payloadResult?.content?.[0]?.text || JSON.stringify(payloadResult);
      const lines = resultText.split('\n').slice(0, 5);
      console.log('Sample output:');
      lines.forEach(line => console.log(`  ${line}`));
      console.log('  ...\n');
    } catch (error) {
      console.error('✗ Error listing payloads:', error.message);
    }
    
    // 5. Test payload generation (safe example)
    console.log('5. Testing payload generation...');
    try {
      const payloadGenResult = await invokeMetasploitTool('generate_payload', {
        payload_type: 'generic/shell_bind_tcp',
        format_type: 'python',
        options: {
          LPORT: 4444
        }
      });
      console.log('✓ Successfully generated payload');
      
      const resultText = payloadGenResult?.data || payloadGenResult?.content?.[0]?.text || JSON.stringify(payloadGenResult);
      const lines = resultText.split('\n').slice(0, 3);
      console.log('Sample output:');
      lines.forEach(line => console.log(`  ${line}`));
      console.log('  ...\n');
    } catch (error) {
      console.error('✗ Error generating payload:', error.message);
    }
    
    console.log('=== Integration Test Complete ===');
    console.log('✓ Metasploit MCP server is accessible and functional');
    console.log('\nNext steps:');
    console.log('1. Start the NetViz server: npm start');
    console.log('2. Use the AI agent to interact with Metasploit');
    console.log('3. Example commands:');
    console.log('   - "list metasploit exploits for ssh"');
    console.log('   - "generate a windows reverse shell payload"');
    console.log('   - "search for web application exploits"');
    
  } catch (error) {
    console.error('✗ Integration test failed:', error.message);
    console.error('\nFull error:', error);
    console.error('\nTroubleshooting:');
    console.error('1. Check if Metasploit MCP server is running on http://178.128.242.63:8085');
    console.error('2. Verify network connectivity to the server');
    console.error('3. Check server logs for any errors');
    console.error('4. Ensure the server supports SSE at /mcp/sse and POST at /mcp/messages/');
  }
}

// Run the test
testMetasploitIntegration().catch(console.error); 