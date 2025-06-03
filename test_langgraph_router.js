// Test script for LangGraph Router
// Run with: node test_langgraph_router.js

import { langGraphRouter } from './src/services/langGraphRouter.js';

async function testLangGraphRouter() {
  console.log('🧪 Testing LangGraph Router...\n');

  // Test 1: Basic next steps question
  console.log('Test 1: Next steps question');
  try {
    const response1 = await langGraphRouter.routeResponse(
      "what should I do next?",
      null,
      [],
      "test-session-1"
    );
    console.log('✅ Response:', response1.substring(0, 100) + '...\n');
  } catch (error) {
    console.log('❌ Error:', error.message, '\n');
  }

  // Test 2: First scan question
  console.log('Test 2: First scan question');
  try {
    const response2 = await langGraphRouter.routeResponse(
      "how do I start scanning google.com?",
      null,
      [],
      "test-session-2"
    );
    console.log('✅ Response:', response2.substring(0, 100) + '...\n');
  } catch (error) {
    console.log('❌ Error:', error.message, '\n');
  }

  // Test 3: More info question with scan results
  console.log('Test 3: More info with scan results');
  try {
    const mockScanResults = `Nmap scan report for scanme.nmap.org (45.33.32.156)
Host is up (0.11s latency).
Not shown: 995 closed ports
PORT     STATE    SERVICE     VERSION
22/tcp   open     ssh         OpenSSH 6.6.1p1 Ubuntu 2ubuntu2.13
80/tcp   open     http        Apache httpd 2.4.7
443/tcp  open     https       Apache httpd 2.4.7
8080/tcp filtered http-proxy
MAC Address: 00:0C:29:0C:47:D5 (VMware)`;

    const response3 = await langGraphRouter.routeResponse(
      "tell me more about these scan results",
      mockScanResults,
      [],
      "test-session-3"
    );
    console.log('✅ Response:', response3.substring(0, 100) + '...\n');
  } catch (error) {
    console.log('❌ Error:', error.message, '\n');
  }

  // Test 4: Specific scan type question
  console.log('Test 4: Specific scan type');
  try {
    const response4 = await langGraphRouter.routeResponse(
      "how do I run a vulnerability scan?",
      null,
      [],
      "test-session-4"
    );
    console.log('✅ Response:', response4.substring(0, 100) + '...\n');
  } catch (error) {
    console.log('❌ Error:', error.message, '\n');
  }

  // Test 5: Security analysis with scan results
  console.log('Test 5: Security analysis');
  try {
    const mockScanResults2 = `Nmap scan report for testphp.vulnweb.com (44.228.249.3)
Host is up (0.11s latency).
Not shown: 998 closed ports
PORT     STATE    SERVICE     VERSION
80/tcp   open     http        Apache httpd 2.4.7
443/tcp  open     https       Apache httpd 2.4.7
MAC Address: 00:0C:29:0C:47:D5 (VMware)`;

    const response5 = await langGraphRouter.routeResponse(
      "analyze the security posture of this target",
      mockScanResults2,
      [],
      "test-session-5"
    );
    console.log('✅ Response:', response5.substring(0, 100) + '...\n');
  } catch (error) {
    console.log('❌ Error:', error.message, '\n');
  }

  // Test 6: Repetitive question handling
  console.log('Test 6: Repetitive question handling');
  try {
    const conversationHistory = [
      { role: 'user', content: 'what should I do next?' },
      { role: 'assistant', content: 'Based on your current findings...' },
      { role: 'user', content: 'what should I do next?' },
      { role: 'assistant', content: 'As mentioned before...' }
    ];

    const response6 = await langGraphRouter.routeResponse(
      "what should I do next?",
      null,
      conversationHistory,
      "test-session-6"
    );
    console.log('✅ Response:', response6.substring(0, 100) + '...\n');
  } catch (error) {
    console.log('❌ Error:', error.message, '\n');
  }

  console.log('🎉 Testing complete!');
}

// Run the tests
testLangGraphRouter().catch(console.error); 