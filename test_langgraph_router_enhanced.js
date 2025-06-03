// Enhanced Test script for LangGraph Router
// Tests advanced features like repetition detection and session persistence
// Run with: node test_langgraph_router_enhanced.js

import { langGraphRouter } from './src/services/langGraphRouter.js';

async function testAdvancedFeatures() {
  console.log('🔬 Testing Advanced LangGraph Router Features...\n');

  // Test Session Persistence
  console.log('=== Session Persistence Test ===');
  const sessionId = "persistent-test-session";
  
  try {
    // First interaction
    const response1 = await langGraphRouter.routeResponse(
      "scan google.com for open ports",
      null,
      [],
      sessionId
    );
    console.log('✅ First interaction:', response1.substring(0, 80) + '...\n');
    
    // Wait a moment to simulate time passage
    await new Promise(resolve => setTimeout(resolve, 100));
    
    // Second interaction with context
    const response2 = await langGraphRouter.routeResponse(
      "what did we discover about google.com?",
      null,
      [
        { role: 'user', content: 'scan google.com for open ports' },
        { role: 'assistant', content: response1 }
      ],
      sessionId
    );
    console.log('✅ Context-aware response:', response2.substring(0, 80) + '...\n');
    
  } catch (error) {
    console.log('❌ Session persistence error:', error.message, '\n');
  }

  // Test Repetition Detection with Escalation
  console.log('=== Repetition Detection Test ===');
  try {
    const conversationHistory = [
      { role: 'user', content: 'what should I do next?' },
      { role: 'assistant', content: 'I need more context about your current findings...' },
      { role: 'user', content: 'what should I do next?' },
      { role: 'assistant', content: 'As I mentioned, I need to know what you have discovered so far...' },
      { role: 'user', content: 'what should I do next?' },
      { role: 'assistant', content: 'I notice you keep asking the same question...' }
    ];

    const response = await langGraphRouter.routeResponse(
      "what should I do next?",
      null,
      conversationHistory,
      "repetition-test-session"
    );
    
    console.log('✅ Advanced repetition response:', response.substring(0, 100) + '...\n');
    
    // Check if response indicates advanced analysis
    if (response.includes('Advanced') || response.includes('advanced')) {
      console.log('✅ Repetition detection triggered advanced response\n');
    } else {
      console.log('⚠️ Repetition detection may need adjustment\n');
    }
    
  } catch (error) {
    console.log('❌ Repetition detection error:', error.message, '\n');
  }

  // Test Complex Scan Analysis
  console.log('=== Complex Scan Analysis Test ===');
  try {
    const complexScanResults = `
Nmap scan report for hackthebox.eu (104.18.40.219)
Host is up (0.022s latency).
Not shown: 996 closed ports
PORT     STATE    SERVICE     VERSION
22/tcp   open     ssh         OpenSSH 7.4 (protocol 2.0)
80/tcp   open     http        nginx 1.18.0
443/tcp  open     https       nginx 1.18.0
3000/tcp open     ppp?        Node.js Express framework
8080/tcp filtered http-proxy
9000/tcp filtered cslistener
MAC Address: 02:42:68:12:28:DB (Unknown)

Service detection performed. Please report any incorrect results at https://nmap.org/submit/ .
Nmap done: 1 IP address (1 host up) scanned in 25.34 seconds
    `;

    const response = await langGraphRouter.routeResponse(
      "provide comprehensive security analysis of these results",
      complexScanResults,
      [],
      "complex-analysis-session"
    );
    
    console.log('✅ Complex analysis response:', response.substring(0, 120) + '...\n');
    
    // Check for security intelligence integration
    if (response.includes('Risk') || response.includes('Security') || response.includes('Vulnerability')) {
      console.log('✅ Security intelligence integration working\n');
    } else {
      console.log('⚠️ Security analysis may need enhancement\n');
    }
    
  } catch (error) {
    console.log('❌ Complex analysis error:', error.message, '\n');
  }

  // Test Edge Cases
  console.log('=== Edge Cases Test ===');
  try {
    // Empty scan results
    const emptyResponse = await langGraphRouter.routeResponse(
      "analyze these scan results",
      "",
      [],
      "edge-case-session-1"
    );
    console.log('✅ Empty scan results handled:', emptyResponse.substring(0, 80) + '...\n');
    
    // Very long conversation history
    const longHistory = Array(20).fill().map((_, i) => [
      { role: 'user', content: `question ${i + 1}` },
      { role: 'assistant', content: `response ${i + 1}` }
    ]).flat();
    
    const longHistoryResponse = await langGraphRouter.routeResponse(
      "what's our conversation summary?",
      null,
      longHistory,
      "edge-case-session-2"
    );
    console.log('✅ Long history handled:', longHistoryResponse.substring(0, 80) + '...\n');
    
  } catch (error) {
    console.log('❌ Edge case error:', error.message, '\n');
  }

  console.log('🎉 Advanced testing complete!');
}

// Performance benchmark
async function benchmarkPerformance() {
  console.log('\n⏱️ Performance Benchmark...');
  
  const startTime = Date.now();
  const promises = [];
  
  // Run 5 concurrent requests
  for (let i = 0; i < 5; i++) {
    promises.push(
      langGraphRouter.routeResponse(
        `what should I scan next? (test ${i + 1})`,
        null,
        [],
        `benchmark-session-${i + 1}`
      )
    );
  }
  
  try {
    await Promise.all(promises);
    const endTime = Date.now();
    console.log(`✅ 5 concurrent requests completed in ${endTime - startTime}ms`);
    console.log(`Average: ${(endTime - startTime) / 5}ms per request\n`);
  } catch (error) {
    console.log('❌ Performance test failed:', error.message, '\n');
  }
}

// Run all tests
async function runAllTests() {
  await testAdvancedFeatures();
  await benchmarkPerformance();
}

runAllTests().catch(console.error); 