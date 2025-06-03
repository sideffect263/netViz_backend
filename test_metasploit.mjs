// Test script to check Metasploit MCP connection
import { MetasploitMCPClient } from './src/utils/working_mcp_client.mjs';

async function testMetasploitConnection() {
  console.log('Testing Metasploit MCP client connection...');
  
  const client = new MetasploitMCPClient('http://178.128.242.63:8085');
  
  try {
    console.log('Attempting to connect...');
    await client.connect();
    console.log('✅ Successfully connected to Metasploit MCP server');
    
    console.log('Testing exploit search...');
    const exploits = await client.listExploits('http');
    console.log('✅ Exploit search worked, found:', exploits.length, 'results');
    
    if (exploits.length > 0) {
      console.log('First few exploits:', exploits.slice(0, 3));
    }
    
    await client.disconnect();
    console.log('✅ Test completed successfully');
    
  } catch (error) {
    console.error('❌ Test failed:', error.message);
    console.error('Full error:', error);
  }
}

testMetasploitConnection(); 