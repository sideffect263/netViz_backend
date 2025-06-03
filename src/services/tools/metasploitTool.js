const { DynamicStructuredTool, DynamicTool } = require('langchain/tools');
const { z } = require('zod');

// Import the MCP client for Metasploit
let mcpClientModule;
async function getMcpClient() {
  if (!mcpClientModule) {
    mcpClientModule = await import('../../utils/working_mcp_client.mjs');
  }
  return mcpClientModule;
}

// Known SQL injection modules in Metasploit
const SQL_INJECTION_MODULES = [
  'auxiliary/admin/mysql/mysql_sql',
  'auxiliary/scanner/mysql/mysql_login',
  'auxiliary/scanner/mssql/mssql_login',
  'auxiliary/scanner/postgres/postgres_login',
  'auxiliary/scanner/http/blind_sql_query',
  'auxiliary/admin/http/wp_custom_contact_forms',
  'auxiliary/scanner/http/sqlmap'
];

// HTTP enumeration modules for web application testing
const HTTP_ENUM_MODULES = [
  'auxiliary/scanner/http/dir_scanner',
  'auxiliary/scanner/http/files_dir',
  'auxiliary/scanner/http/http_version',
  'auxiliary/scanner/http/options',
  'auxiliary/scanner/http/trace',
  'auxiliary/scanner/http/verb_auth_bypass'
];

/**
 * Create the Metasploit exploit search tool
 * @returns {DynamicTool} - The configured exploit search tool
 */
async function createExploitSearchTool() {
  const { MetasploitMCPClient } = await getMcpClient();
  const client = new MetasploitMCPClient('http://178.128.242.63:8085');

  return new DynamicTool({
    name: 'MetasploitExploitSearch',
    description: `Search for Metasploit exploits by keyword, CVE, or service name. This tool helps identify available exploitation modules for discovered vulnerabilities.

Examples of search terms:
- "apache" for Apache web server exploits
- "ssh" for SSH service exploits  
- "ms17-010" for specific vulnerability
- "CVE-2021-44228" for exploits by CVE
- "sql" for SQL injection related exploits
- "http" for HTTP/web-related exploits

Use this when you need to:
- Find exploits for a specific vulnerability (e.g., "ms17-010", "CVE-2021-44228")
- Search for exploits targeting a service (e.g., "apache", "ssh", "smb", "sql")
- Identify available attack vectors for a target`,
    func: async (searchTerm) => {
      try {
        if (!client.isConnected) {
          await client.connect();
        }
        
        console.log(`Searching for Metasploit exploits: ${searchTerm}`);
        const exploits = await client.listExploits(searchTerm);
        
        if (Array.isArray(exploits) && exploits.length > 0) {
          // Limit to top 15 most relevant results for better output
          const topExploits = exploits.slice(0, 15);
          return `Found ${exploits.length} exploits matching "${searchTerm}". Top results:\n\n${topExploits.map(e => `• ${e}`).join('\n')}`;
        } else {
          // Provide helpful suggestions for common search terms
          let suggestions = '';
          if (searchTerm.toLowerCase().includes('sql')) {
            suggestions = `\n\nSuggested alternative searches:\n• "mysql" for MySQL-specific modules\n• "postgres" for PostgreSQL modules\n• "mssql" for Microsoft SQL Server modules\n• "http" for web application testing modules`;
          }
          return `No exploits found matching "${searchTerm}". Try a broader search term or check the vulnerability database.${suggestions}`;
        }
      } catch (error) {
        console.error('MetasploitExploitSearch error:', error);
        return `Error searching exploits: ${error.message}. Please verify the Metasploit MCP server is running.`;
      }
    }
  });
}

/**
 * Create the Metasploit vulnerability check tool
 * @returns {DynamicStructuredTool} - The configured vulnerability check tool
 */
async function createVulnerabilityCheckTool() {
  const { MetasploitMCPClient } = await getMcpClient();
  const client = new MetasploitMCPClient('http://178.128.242.63:8085');

  return new DynamicStructuredTool({
    name: 'MetasploitVulnerabilityCheck',
    description: `Check if a target is vulnerable to a specific exploit without actually exploiting it. This performs a safe vulnerability assessment.
IMPORTANT: Only use against authorized targets!
Use this to:
- Verify if a target is vulnerable before exploitation
- Perform safe vulnerability validation
- Gather exploit-specific intelligence`,
    schema: z.object({
      module_name: z.string().describe('The full exploit module path (e.g., "exploit/windows/smb/ms17_010_eternalblue")'),
      target: z.string().describe('Target IP address or hostname'),
      port: z.number().optional().describe('Target port (if different from default)'),
      additional_options: z.record(z.string()).optional().describe('Additional module options if needed')
    }),
    func: async ({ module_name, target, port, additional_options = {} }) => {
      try {
        if (!client.isConnected) {
          await client.connect();
        }
        
        // Build options object
        const options = {
          RHOSTS: target,
          ...additional_options
        };
        
        if (port) {
          options.RPORT = port.toString();
        }
        
        console.log(`Checking vulnerability: ${module_name} against ${target}${port ? `:${port}` : ''}`);
        
        // Run exploit in check mode
        const result = await client.runExploit(
          module_name,
          options,
          null,  // no payload for check
          null,  // no payload options
          false, // not as job
          true   // check vulnerability only
        );
        
        return JSON.stringify(result, null, 2);
      } catch (error) {
        console.error('MetasploitVulnerabilityCheck error:', error);
        return `Error checking vulnerability: ${error.message}. Verify the module path and target accessibility.`;
      }
    }
  });
}

/**
 * Create the enhanced Metasploit auxiliary module tool with SQL injection support
 * @returns {DynamicStructuredTool} - The configured auxiliary module tool
 */
async function createAuxiliaryModuleTool() {
  const { MetasploitMCPClient } = await getMcpClient();
  const client = new MetasploitMCPClient('http://178.128.242.63:8085');

  return new DynamicStructuredTool({
    name: 'MetasploitAuxiliary',
    description: `Run Metasploit auxiliary modules for scanning, enumeration, and intelligence gathering.

**SQL Injection Testing Modules:**
${SQL_INJECTION_MODULES.map(m => `• ${m}`).join('\n')}

**HTTP Web Application Testing:**
${HTTP_ENUM_MODULES.map(m => `• ${m}`).join('\n')}

**Other Common Uses:**
• Service enumeration (auxiliary/scanner/smb/smb_version)
• Credential testing (auxiliary/scanner/ssh/ssh_login)
• Information gathering (auxiliary/gather/*)

**For SQL Injection Testing on Web Apps:**
Use auxiliary/scanner/http/dir_scanner first to find web directories, then use database-specific modules if backend databases are identified.`,
    schema: z.object({
      module_name: z.string().describe('The auxiliary module path (e.g., "auxiliary/scanner/http/dir_scanner")'),
      target: z.string().describe('Target host IP address or hostname'),
      port: z.number().optional().describe('Target port (defaults based on module)'),
      additional_options: z.record(z.any()).optional().describe('Additional module-specific options'),
      run_as_job: z.boolean().optional().default(false).describe('Run in background as job')
    }),
    func: async ({ module_name, target, port, additional_options = {}, run_as_job = false }) => {
      try {
        if (!client.isConnected) {
          await client.connect();
        }
        
        // Validate module exists in our known modules
        const allKnownModules = [...SQL_INJECTION_MODULES, ...HTTP_ENUM_MODULES];
        const isKnownModule = allKnownModules.some(mod => mod.includes(module_name) || module_name.includes(mod.split('/').pop()));
        
        // Build options object
        const options = {
          RHOSTS: target,
          ...additional_options
        };
        
        // Set appropriate default ports
        if (port) {
          options.RPORT = port.toString();
        } else if (module_name.includes('http')) {
          options.RPORT = '80';
        } else if (module_name.includes('mysql')) {
          options.RPORT = '3306';
        } else if (module_name.includes('postgres')) {
          options.RPORT = '5432';
        } else if (module_name.includes('mssql')) {
          options.RPORT = '1433';
        }
        
        console.log(`Running auxiliary module: ${module_name}`);
        console.log(`Target: ${target}${options.RPORT ? `:${options.RPORT}` : ''}`);
        console.log(`Options:`, JSON.stringify(options, null, 2));
        
        // Warn if using unknown module
        if (!isKnownModule) {
          console.warn(`Warning: ${module_name} not in known modules list. This may fail.`);
        }
        
        const result = await client.runAuxiliaryModule(
          module_name,
          options,
          run_as_job,
          false // don't check target compatibility
        );
        
        return JSON.stringify(result, null, 2);
      } catch (error) {
        console.error('MetasploitAuxiliary error:', error);
        
        // Provide helpful error messages
        if (error.message.includes('unknown module') || error.message.includes('Invalid module')) {
          return `Module "${module_name}" not found. Try searching for available modules first using MetasploitExploitSearch. For SQL injection testing, consider these alternatives:\n\n${SQL_INJECTION_MODULES.map(m => `• ${m}`).join('\n')}`;
        }
        
        return `Error running auxiliary module: ${error.message}`;
      }
    }
  });
}

/**
 * Create SQL injection specific tool for easier use
 * @returns {DynamicStructuredTool} - SQL injection testing tool
 */
async function createSQLInjectionTool() {
  const { MetasploitMCPClient } = await getMcpClient();
  const client = new MetasploitMCPClient('http://178.128.242.63:8085');

  return new DynamicStructuredTool({
    name: 'MetasploitSQLInjectionScan',
    description: `Specialized tool for SQL injection testing using Metasploit modules. This automatically selects appropriate modules based on the target.

This tool will:
1. First scan for web directories to identify potential injection points
2. Then attempt database-specific testing if databases are identified
3. Provide detailed results about potential SQL injection vulnerabilities

Perfect for testing web applications for SQL injection vulnerabilities.`,
    schema: z.object({
      target: z.string().describe('Target web application IP or hostname'),
      port: z.number().optional().default(80).describe('Web server port (default: 80)'),
      path: z.string().optional().default('/').describe('Starting path for directory scanning (default: /)'),
      database_type: z.enum(['auto', 'mysql', 'postgres', 'mssql']).optional().default('auto').describe('Database type if known')
    }),
    func: async ({ target, port = 80, path = '/', database_type = 'auto' }) => {
      try {
        if (!client.isConnected) {
          await client.connect();
        }
        
        let results = `SQL Injection Testing Results for ${target}:${port}\n\n`;
        
        // Step 1: Directory scanning to find potential injection points
        console.log(`Step 1: Scanning directories on ${target}:${port}`);
        const dirScanOptions = {
          RHOSTS: target,
          RPORT: port.toString(),
          PATH: path
        };
        
        try {
          const dirResult = await client.runAuxiliaryModule(
            'auxiliary/scanner/http/dir_scanner',
            dirScanOptions,
            false,
            false
          );
          
          results += `🔍 **Directory Scan Results:**\n`;
          results += `${JSON.stringify(dirResult, null, 2)}\n\n`;
        } catch (dirError) {
          results += `⚠️ Directory scan failed: ${dirError.message}\n\n`;
        }
        
        // Step 2: HTTP version detection
        console.log(`Step 2: HTTP service detection`);
        try {
          const httpVersionResult = await client.runAuxiliaryModule(
            'auxiliary/scanner/http/http_version',
            { RHOSTS: target, RPORT: port.toString() },
            false,
            false
          );
          
          results += `🌐 **HTTP Service Information:**\n`;
          results += `${JSON.stringify(httpVersionResult, null, 2)}\n\n`;
        } catch (httpError) {
          results += `⚠️ HTTP version detection failed: ${httpError.message}\n\n`;
        }
        
        // Step 3: Database-specific testing if specified
        if (database_type !== 'auto') {
          const dbModuleMap = {
            mysql: 'auxiliary/scanner/mysql/mysql_login',
            postgres: 'auxiliary/scanner/postgres/postgres_login',
            mssql: 'auxiliary/scanner/mssql/mssql_login'
          };
          
          const dbModule = dbModuleMap[database_type];
          if (dbModule) {
            console.log(`Step 3: Testing ${database_type} database`);
            const dbPortMap = { mysql: 3306, postgres: 5432, mssql: 1433 };
            
            try {
              const dbResult = await client.runAuxiliaryModule(
                dbModule,
                { RHOSTS: target, RPORT: dbPortMap[database_type].toString() },
                false,
                false
              );
              
              results += `🗄️ **${database_type.toUpperCase()} Database Test:**\n`;
              results += `${JSON.stringify(dbResult, null, 2)}\n\n`;
            } catch (dbError) {
              results += `⚠️ ${database_type} database test failed: ${dbError.message}\n\n`;
            }
          }
        }
        
        // Step 4: Recommendations
        results += `💡 **Next Steps for SQL Injection Testing:**\n`;
        results += `1. Manually test discovered web directories for SQL injection\n`;
        results += `2. Use tools like SQLmap for automated SQL injection testing\n`;
        results += `3. If databases were identified, test direct database connections\n`;
        results += `4. Look for login forms, search functions, and URL parameters\n`;
        results += `5. Test common injection points: ?id=1, ?cat=1, login forms\n\n`;
        
        results += `📚 **Manual Testing Tips:**\n`;
        results += `• Try basic payloads: ' OR 1=1-- , '; DROP TABLE--\n`;
        results += `• Test error-based injection: ' AND 1=0--\n`;
        results += `• Look for database error messages in responses\n`;
        results += `• Test both GET and POST parameters\n`;
        
        return results;
        
      } catch (error) {
        console.error('MetasploitSQLInjectionScan error:', error);
        return `Error during SQL injection testing: ${error.message}`;
      }
    }
  });
}

/**
 * Create the Metasploit session management tool
 * @returns {DynamicTool} - The configured session management tool
 */
async function createSessionManagementTool() {
  const { MetasploitMCPClient } = await getMcpClient();
  const client = new MetasploitMCPClient('http://178.128.242.63:8085');

  return new DynamicTool({
    name: 'MetasploitSessions',
    description: `List and manage active Metasploit sessions. Use this to check for successful exploitations and active connections.`,
    func: async () => {
      try {
        if (!client.isConnected) {
          await client.connect();
        }
        
        console.log('Listing active Metasploit sessions...');
        const result = await client.listActiveSessions();
        
        if (result.status === 'success' && result.count > 0) {
          let response = `🎯 **Active Sessions: ${result.count}**\n\n`;
          for (const [id, session] of Object.entries(result.sessions)) {
            response += `**Session ${id}:**\n`;
            response += `  • Type: ${session.type}\n`;
            response += `  • Info: ${session.info}\n`;
            response += `  • Tunnel: ${session.tunnel_local} → ${session.tunnel_peer}\n`;
            response += `  • Last Seen: ${session.last_seen || 'Unknown'}\n\n`;
          }
          return response;
        } else {
          return '📭 **No active sessions found.**\n\nThis means no successful exploitations have created persistent connections to targets.';
        }
      } catch (error) {
        console.error('MetasploitSessions error:', error);
        return `Error listing sessions: ${error.message}`;
      }
    }
  });
}

/**
 * Create the Metasploit payload generator tool
 * @returns {DynamicStructuredTool} - The configured payload generator tool
 */
async function createPayloadGeneratorTool() {
  const { MetasploitMCPClient } = await getMcpClient();
  const client = new MetasploitMCPClient('http://178.128.242.63:8085');

  return new DynamicStructuredTool({
    name: 'MetasploitPayloadGenerator',
    description: `Generate Metasploit payloads for testing. 
SECURITY NOTE: Only generate payloads for authorized security testing!
Common payload types:
- windows/meterpreter/reverse_tcp
- linux/x64/meterpreter/reverse_tcp
- python/meterpreter/reverse_tcp`,
    schema: z.object({
      payload_type: z.string().describe('The payload type (e.g., "windows/meterpreter/reverse_tcp")'),
      lhost: z.string().describe('Listener host IP address'),
      lport: z.number().describe('Listener port number'),
      format_type: z.string().default('exe').describe('Output format (exe, elf, py, ps1, dll, etc.)'),
      additional_params: z.record(z.any()).optional().describe('Additional parameters like encoder')
    }),
    func: async ({ payload_type, lhost, lport, format_type = 'exe', additional_params = {} }) => {
      try {
        if (!client.isConnected) {
          await client.connect();
        }
        
        const options = {
          LHOST: lhost,
          LPORT: lport.toString()
        };
        
        console.log(`Generating payload: ${payload_type} with format ${format_type}`);
        console.log(`Listener: ${lhost}:${lport}`);
        
        const result = await client.generatePayload(
          payload_type,
          format_type,
          options,
          additional_params
        );
        
        return JSON.stringify(result, null, 2);
      } catch (error) {
        console.error('MetasploitPayloadGenerator error:', error);
        return `Error generating payload: ${error.message}`;
      }
    }
  });
}

/**
 * Create all Metasploit tools including the new SQL injection tool
 * @returns {Array} - Array of configured Metasploit tools
 */
async function createMetasploitTools() {
  try {
    const tools = await Promise.all([
      createExploitSearchTool(),
      createVulnerabilityCheckTool(),
      createAuxiliaryModuleTool(),
      createSQLInjectionTool(), // New specialized SQL injection tool
      createSessionManagementTool(),
      createPayloadGeneratorTool()
    ]);
    
    console.log('Successfully created enhanced Metasploit tools with SQL injection support');
    return tools;
  } catch (error) {
    console.error('Error creating Metasploit tools:', error);
    // Return empty array if Metasploit server is not available
    return [];
  }
}

module.exports = {
  createMetasploitTools,
  createExploitSearchTool,
  createVulnerabilityCheckTool,
  createAuxiliaryModuleTool,
  createSQLInjectionTool,
  createSessionManagementTool,
  createPayloadGeneratorTool,
  SQL_INJECTION_MODULES,
  HTTP_ENUM_MODULES
};