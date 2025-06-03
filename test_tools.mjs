// Test script to check if Metasploit tools are created properly
import { createMetasploitTools } from './src/services/tools/metasploitTool.js';

async function testToolCreation() {
  console.log('Testing Metasploit tool creation...');
  
  try {
    console.log('Creating Metasploit tools...');
    const tools = await createMetasploitTools();
    
    console.log('✅ Tools created successfully!');
    console.log('Number of tools:', tools.length);
    
    if (tools.length > 0) {
      console.log('Tool names:');
      tools.forEach((tool, index) => {
        console.log(`  ${index + 1}. ${tool.name}`);
      });
      
      // Test calling the first tool
      console.log('\nTesting first tool (MetasploitExploitSearch)...');
      const firstTool = tools[0];
      if (firstTool && firstTool.name === 'MetasploitExploitSearch') {
        const result = await firstTool.func({ searchTerm: 'http' });
        console.log('✅ Tool call successful!');
        console.log('Result preview:', result.substring(0, 200) + '...');
      }
    } else {
      console.log('❌ No tools were created');
    }
    
  } catch (error) {
    console.error('❌ Tool creation failed:', error.message);
    console.error('Full error:', error);
  }
}

testToolCreation(); 