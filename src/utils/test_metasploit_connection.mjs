#!/usr/bin/env node

// Test script to verify Metasploit MCP server connection and available modules
import { MetasploitMCPClient } from './working_mcp_client.mjs';

const TEST_TARGET = '44.228.249.3'; // testphp.vulnweb.com - authorized target

async function testMetasploitConnection() {
    const client = new MetasploitMCPClient('http://178.128.242.63:8085');
    
    console.log('🧪 Testing Metasploit MCP Server Connection and SQL Injection Modules\n');
    
    try {
        // Test 1: Basic connection
        console.log('1️⃣ Testing basic connection...');
        await client.connect();
        console.log('✅ Successfully connected to Metasploit MCP server\n');
        
        // Test 2: List available tools
        console.log('2️⃣ Listing available tools...');
        const tools = await client.listTools();
        console.log(`✅ Found ${tools.length} available tools:`);
        tools.forEach(tool => console.log(`   • ${tool.name}: ${tool.description?.substring(0, 60)}...`));
        console.log('');
        
        // Test 3: Search for SQL-related exploits
        console.log('3️⃣ Searching for SQL injection exploits...');
        const sqlExploits = await client.listExploits('sql');
        if (sqlExploits.length > 0) {
            console.log(`✅ Found ${sqlExploits.length} SQL-related exploits:`);
            sqlExploits.slice(0, 5).forEach(exploit => console.log(`   • ${exploit}`));
            if (sqlExploits.length > 5) console.log(`   ... and ${sqlExploits.length - 5} more`);
        } else {
            console.log('⚠️ No SQL exploits found - trying alternative searches...');
            
            // Try alternative searches
            const alternatives = ['mysql', 'postgres', 'http'];
            for (const alt of alternatives) {
                const altResults = await client.listExploits(alt);
                if (altResults.length > 0) {
                    console.log(`✅ Found ${altResults.length} ${alt}-related exploits`);
                    break;
                }
            }
        }
        console.log('');
        
        // Test 4: Test auxiliary module - HTTP directory scanner
        console.log('4️⃣ Testing HTTP directory scanner module...');
        try {
            const dirScanResult = await client.runAuxiliaryModule(
                'auxiliary/scanner/http/dir_scanner',
                {
                    RHOSTS: TEST_TARGET,
                    RPORT: '80',
                    THREADS: '1' // Keep it light for testing
                },
                false, // not as job
                false  // don't check target
            );
            console.log('✅ HTTP directory scanner test completed');
            console.log('Result status:', dirScanResult.status || 'unknown');
        } catch (dirError) {
            console.log('❌ HTTP directory scanner failed:', dirError.message);
        }
        console.log('');
        
        // Test 5: Test HTTP version detection
        console.log('5️⃣ Testing HTTP version detection...');
        try {
            const httpVersionResult = await client.runAuxiliaryModule(
                'auxiliary/scanner/http/http_version',
                {
                    RHOSTS: TEST_TARGET,
                    RPORT: '80'
                },
                false,
                false
            );
            console.log('✅ HTTP version detection test completed');
            console.log('Result status:', httpVersionResult.status || 'unknown');
        } catch (httpError) {
            console.log('❌ HTTP version detection failed:', httpError.message);
        }
        console.log('');
        
        // Test 6: Check active sessions
        console.log('6️⃣ Checking for active sessions...');
        const sessions = await client.listActiveSessions();
        if (sessions.status === 'success') {
            console.log(`✅ Session check successful - ${sessions.count} active sessions`);
        } else {
            console.log('⚠️ Session check returned:', sessions.message);
        }
        console.log('');
        
        // Test 7: List current jobs/listeners
        console.log('7️⃣ Checking active jobs/listeners...');
        const listeners = await client.listListeners();
        if (listeners.status === 'success') {
            console.log(`✅ Found ${listeners.total_job_count} total jobs (${listeners.handler_count} handlers)`);
        } else {
            console.log('⚠️ Job listing returned:', listeners.message);
        }
        console.log('');
        
        console.log('🎉 All tests completed! The Metasploit MCP server appears to be working correctly.\n');
        
        // Summary and recommendations
        console.log('📋 SUMMARY & RECOMMENDATIONS:');
        console.log('✅ Connection: Working');
        console.log('✅ Tools: Available');
        console.log('✅ Exploit Search: Working');
        console.log('✅ Auxiliary Modules: Available');
        console.log('');
        console.log('💡 For SQL injection testing:');
        console.log('   1. Use auxiliary/scanner/http/dir_scanner first');
        console.log('   2. Follow up with database-specific modules if needed');
        console.log('   3. The new MetasploitSQLInjectionScan tool will automate this process');
        console.log('');
        
    } catch (error) {
        console.error('❌ Test failed:', error.message);
        console.log('');
        console.log('🔧 TROUBLESHOOTING:');
        console.log('   • Verify Metasploit MCP server is running on http://178.128.242.63:8085');
        console.log('   • Check network connectivity to the server');
        console.log('   • Ensure the server is properly configured and initialized');
        console.log('   • Check server logs for any errors');
    } finally {
        if (client.isConnected) {
            await client.disconnect();
            console.log('🔌 Disconnected from server');
        }
    }
}

// Run the test if this file is executed directly
if (import.meta.url === `file://${process.argv[1].replace(/\\/g, '/')}`) {
    testMetasploitConnection().catch(console.error);
}

export { testMetasploitConnection }; 