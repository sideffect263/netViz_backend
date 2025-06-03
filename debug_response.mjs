// Debug script to see the raw MCP response
import { MetasploitMCPClient } from './src/utils/working_mcp_client.mjs';

async function debugResponse() {
  console.log('Debugging MCP response...');
  
  const client = new MetasploitMCPClient('http://178.128.242.63:8085');
  
  try {
    await client.connect();
    console.log('Connected to MCP server');
    
    // Call the raw tool to see what we get back
    console.log('Calling list_exploits tool directly...');
    const rawResult = await client.client.callTool({
      name: 'list_exploits',
      arguments: { search_term: 'http' }
    });
    
    console.log('\n=== RAW MCP RESPONSE ===');
    console.log('Type:', typeof rawResult);
    console.log('Full response:', JSON.stringify(rawResult, null, 2));
    
    if (rawResult && rawResult.content) {
      console.log('\n=== CONTENT ANALYSIS ===');
      console.log('Content length:', rawResult.content.length);
      rawResult.content.forEach((item, index) => {
        console.log(`Content ${index}:`, {
          type: item.type,
          textLength: item.text ? item.text.length : 'N/A',
          textPreview: item.text ? item.text.substring(0, 200) + '...' : 'N/A'
        });
      });
    }
    
    await client.disconnect();
    
  } catch (error) {
    console.error('Error:', error);
  }
}

debugResponse(); 