const { DynamicTool } = require('langchain/tools');

// Import the MCP client for Nmap
let mcpClientModule;
async function getMcpClient() {
  if (!mcpClientModule) {
    mcpClientModule = await import('../../utils/mcpClientSideEffect.mjs');
  }
  return mcpClientModule;
}

/**
 * Parse Nmap command input to extract target and flags
 * @param {string} input - Input string like "-T4 -F example.com"
 * @returns {Object} - Object with target and flags properties
 */
function parseNmapInput(input) {
  if (typeof input === 'object' && input.target && input.flags) {
    // Already in the correct format
    return input;
  }

  if (typeof input !== 'string') {
    throw new Error("Invalid input format for NmapScanner. Expected string or object.");
  }

  const inputStr = input.trim();
  
  // Split input into words
  const words = inputStr.split(/\s+/).filter(word => word.trim() !== '');
  
  if (words.length === 0) {
    throw new Error("Empty input provided to NmapScanner.");
  }
  
  let target = '';
  const flags = [];
  
  // More robust parsing logic
  for (let i = 0; i < words.length; i++) {
    const word = words[i];
    
    if (word.startsWith('-')) {
      // This is a flag
      flags.push(word);
      
      // Check if this flag expects a parameter (like -p 80 or -T 4)
      const flagsWithParams = ['-p', '-T', '--top-ports', '--exclude-ports'];
      if (flagsWithParams.includes(word) && i + 1 < words.length) {
        // Add the next word as part of this flag
        i++; // Skip the next word in main loop
        flags.push(words[i]);
      }
    } else {
      // This might be a target
      // Check if it looks like a domain or IP address
      const isDomain = /^[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z0-9]([a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?)*\.[a-zA-Z]{2,}$/.test(word);
      const isIP = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/.test(word);
      const isCIDR = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\/[0-9]{1,2}$/.test(word);
      
      if ((isDomain || isIP || isCIDR) && !target) {
        target = word;
      } else if (!target) {
        // If we haven't found a target yet and this doesn't look like a flag,
        // assume it's a target (could be a hostname that doesn't match our regex)
        target = word;
      } else {
        // We already have a target, so this might be additional flags or parameters
        // If it's a standalone number, it might be a port parameter for a previous flag
        if (/^\d+$/.test(word) && flags.length > 0) {
          // Check if the last flag was -p or similar that expects a port
          const lastFlag = flags[flags.length - 1];
          if (lastFlag === '-p' || lastFlag === '--port') {
            flags.push(word);
          } else {
            // Standalone number not associated with a flag - might be an error
            console.warn(`Unexpected number '${word}' in input, ignoring.`);
          }
        } else {
          // Other unexpected input, treat as additional flag
          flags.push(word);
        }
      }
    }
  }
  
  // Validation
  if (!target) {
    throw new Error("No target found in input. Please provide a domain or IP address.");
  }
  
  // Final validation of target format
  const targetValidation = /^[a-zA-Z0-9.-\/]+$/;
  if (!targetValidation.test(target)) {
    throw new Error(`Invalid target format: '${target}'. Target should only contain letters, numbers, dots, hyphens, and forward slashes.`);
  }
  
  // Join flags back together, ensuring proper spacing
  const flagsStr = flags.join(' ');
  
  console.log(`Parsed Nmap input: target="${target}", flags="${flagsStr}"`);
  
  return {
    target: target,
    flags: flagsStr
  };
}

/**
 * Create the Nmap scanner tool
 * @returns {DynamicTool} - The configured Nmap tool
 */
async function createNmapTool() {
  // Get the MCP client for Nmap
  const mcpClient = await getMcpClient();

  return new DynamicTool({
    name: 'NmapScanner',
    description: `Runs an Nmap scan against a target with specified flags.
IMPORTANT: For large scans use reasonable defaults to avoid timeouts:
- Use -T4 for timing (faster)
- Limit port scans to common ports (-p 1-1000) instead of all ports (-p-)
- Use -F for a fast scan of most common ports
- Only use service detection (-sV) when needed
- Only include OS detection (-O) when critical

Examples:
- "example.com -T4 -F" (scan example.com with fast options)
- "-sV -p 80,443,8080 example.com" (scan specific ports with service detection)

The system will automatically retry with simplified parameters if the scan times out.`,
    func: async (input) => {
      try {
        // Send a progress update through the callback system
        console.log(`Processing Nmap scan input: ${input}`);
        
        // Parse the input to extract target and flags
        const { target, flags } = parseNmapInput(input);
        
        if (!target) {
          return "Error: No target specified for the scan. Please provide a domain or IP address.";
        }
        
        console.log(`Starting Nmap scan of ${target} with flags: ${flags}`);
        
        // Convert flags to array format expected by invokeNmapScan
        const flagsArray = flags.split(' ').filter(flag => flag.trim() !== '');
        
        // For intensive scans, add periodic progress updates
        const isIntensiveScan = flags.includes('-p-') || flags.includes('-sV') || flags.includes('-A');
        let progressUpdateInterval;
        
        if (isIntensiveScan) {
          // Every 20 seconds, send a progress update through the callback
          console.log('Intensive scan detected, will send progress updates');
        }
        
        try {
          const result = await mcpClient.invokeNmapScan({
            target,
            nmap_args: flagsArray
          });
          
          // Clear the interval if it was set
          if (progressUpdateInterval) {
            clearInterval(progressUpdateInterval);
          }
          
          return JSON.stringify(result, null, 2);
        } catch (error) {
          // Clear the interval if it was set
          if (progressUpdateInterval) {
            clearInterval(progressUpdateInterval);
          }
          
          return `Error running Nmap scan: ${error.message}`;
        }
      } catch (error) {
        return `Error running Nmap scan: ${error.message}`;
      }
    }
  });
}

module.exports = {
  createNmapTool,
  parseNmapInput
}; 