/**
 * Test script for verifying the MCP client integration
 */
const mcpClient = require('./src/utils/mcpClient');

// Target to scan (use a safe target for testing)
const target = '127.0.0.1';

async function testMcpNmap() {
  console.log(`Testing MCP Nmap scan against ${target}`);
  
  try {
    // Basic port scan
    console.log('Running basic port scan...');
    const result = await mcpClient.invokeNmap({
      target: target,
      nmap_args: ['-T4', '-p', '80,443,22,21']
    });
    
    console.log('Scan completed successfully!');
    console.log('Results:', JSON.stringify(result, null, 2));
    return true;
  } catch (error) {
    console.error('ERROR:', error.message);
    return false;
  }
}

// Run the test
testMcpNmap()
  .then(success => {
    if (success) {
      console.log('MCP integration test passed!');
      process.exit(0);
    } else {
      console.log('MCP integration test failed!');
      process.exit(1);
    }
  })
  .catch(error => {
    console.error('Test execution error:', error);
    process.exit(1);
  }); 