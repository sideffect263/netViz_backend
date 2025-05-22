const { exec } = require('child_process');
const util = require('util');
const execPromise = util.promisify(exec);
const path = require('path');
const fs = require('fs').promises;
const Anthropic = require('@anthropic-ai/sdk');
const { isValidDomain, isValidIPv4, isValidIPv6 } = require('../utils/validation');
// const mcpClient = require('../utils/mcpClient'); // Old import removed

// Helper to dynamically import the ESM mcpClient
let newMcpClientModule; // Renamed variable
async function getMcpClient() {
  if (!newMcpClientModule) {
    newMcpClientModule = await import('../utils/mcpClientSideEffect.mjs'); // Import the new client
    // If you want to call initializeNewClient on load (it's also called before each use):
    // await newMcpClientModule.initializeNewClient(); 
  }
  return newMcpClientModule;
}

// Initialize Anthropic client
console.log("ANTHROPIC_API Key (loaded in autoHackerService):", process.env.ANTHROPIC_API); // Added for debugging
console.log("ANTHROPIC_MODEL (loaded in autoHackerService):", process.env.ANTHROPIC_MODEL); // Added for debugging
const anthropic = new Anthropic({
  apiKey: process.env.ANTHROPIC_API, // Make sure this is added to your .env file
});

// Track child processes for cancellation
const runningProcesses = new Map();

/**
 * Main function to execute the autonomous scan
 */
exports.executeScan = async (scanId, target, scanDepth, aiMode, scanStore) => {
  try {
    console.log(`[Scan ${scanId}] Starting scan for target: ${target}`);
    console.log(`[Scan ${scanId}] Scan depth: ${scanDepth}, AI mode: ${aiMode}`);

    // Validate target
    if (!isValidDomain(target) && !isValidIPv4(target) && !isValidIPv6(target)) {
      throw new Error('Invalid target: must be a valid domain or IP address');
    }

    // Update scan status
    updateScanStatus(scanId, 'running', 5, 'target_validation', scanStore);
    console.log(`[Scan ${scanId}] Target validation completed`);

    // Define scan stages based on depth
    const stages = getScanStagesForDepth(scanDepth);
    console.log(`[Scan ${scanId}] Will execute ${stages.length} stages: ${stages.map(s => s.name).join(', ')}`);
    
    let scanResults = {};
    let aiContext = '';

    for (const stage of stages) {
      try {
        console.log(`[Scan ${scanId}] Starting stage: ${stage.name}`);
        
        // Update current stage
        updateScanStatus(
          scanId, 
          'running', 
          calculateProgress(stages, stages.indexOf(stage)), 
          stage.name, 
          scanStore
        );

        // Execute the stage
        const stageResults = await executeStage(scanId, target, stage, scanDepth);
        console.log(`[Scan ${scanId}] Completed stage: ${stage.name}`);
        scanResults[stage.name] = stageResults;

        // Add completed stage
        const scan = scanStore.get(scanId);
        // Persist raw stage results for front-end polling
        if (!scan.stageResults) scan.stageResults = {};
        scan.stageResults[stage.name] = stageResults;
        scan.completedStages.push(stage.name);
        scanStore.set(scanId, scan);

        // Check if scan was cancelled
        if (scan.status === 'cancelled') {
          console.log(`[Scan ${scanId}] Scan was cancelled during stage: ${stage.name}`);
          return;
        }

        // Update AI context with results from this stage
        aiContext += `\n== ${stage.name.toUpperCase()} RESULTS ==\n${JSON.stringify(stageResults, null, 2)}\n`;

        // If this stage has AI intervention, process with AI
        if (stage.aiIntervention) {
          console.log(`[Scan ${scanId}] Processing ${stage.name} results with AI`);
          const aiInsights = await processWithAI(
            target, 
            scanResults, 
            aiMode, 
            `Analyzing results from the ${stage.name} stage. ${stage.aiPrompt || ''}`,
            aiContext
          );
          
          // Add AI insights to stage results
          scanResults[`${stage.name}_ai_insights`] = aiInsights;
          console.log(`[Scan ${scanId}] AI analysis completed for ${stage.name}`);
          
          // Update the AI context
          aiContext += `\n== AI ANALYSIS FOR ${stage.name.toUpperCase()} ==\n${aiInsights}\n`;

          // Persist AI insights for this stage so UI can show them live
          const scanLive = scanStore.get(scanId);
          if (!scanLive.aiInsights) scanLive.aiInsights = {};
          scanLive.aiInsights[stage.name] = aiInsights;
          scanStore.set(scanId, scanLive);
        }
      } catch (error) {
        console.error(`[Scan ${scanId}] Error in stage ${stage.name}:`, error);
        scanResults[stage.name] = { error: error.message };
      }
    }

    // Final AI analysis
    console.log(`[Scan ${scanId}] Starting final AI analysis`);
    updateScanStatus(scanId, 'running', 95, 'ai_analysis', scanStore);
    
    const finalAiAnalysis = await processWithAI(
      target,
      scanResults,
      aiMode,
      `Provide a comprehensive security analysis of ${target} based on all scan results.`,
      aiContext
    );
    console.log(`[Scan ${scanId}] Final AI analysis completed`);

    // Complete the scan
    const scan = scanStore.get(scanId);
    scan.status = 'completed';
    scan.progress = 100;
    scan.endTime = new Date();
    scan.results = {
      ...scanResults,
      final_analysis: finalAiAnalysis,
      summary: {
        vulnerabilities: extractVulnerabilities(scanResults, finalAiAnalysis),
        aiInsights: finalAiAnalysis
      }
    };
    scan.stageResults = scan.stageResults || {};
    scan.aiInsights = scan.aiInsights || {};
    scanStore.set(scanId, scan);
    console.log(`[Scan ${scanId}] Scan completed successfully`);

  } catch (error) {
    console.error(`[Scan ${scanId}] Fatal error in scan:`, error);
    const scan = scanStore.get(scanId);
    scan.status = 'failed';
    scan.error = error.message;
    scan.endTime = new Date();
    scanStore.set(scanId, scan);
  }
};

/**
 * Execute a specific scan stage
 */
async function executeStage(scanId, target, stage, scanDepth) {
  switch (stage.name) {
    case 'port_scan':
      return await runPortScan(scanId, target, scanDepth);
    case 'service_detection':
      return await runServiceDetection(scanId, target, scanDepth);
    case 'vulnerability_scan':
      return await runVulnerabilityScan(scanId, target, scanDepth);
    case 'web_analysis':
      return await runWebAnalysis(scanId, target, scanDepth);
    case 'ssl_scan':
      return await runSSLScan(scanId, target);
    case 'dns_analysis':
      return await runDNSAnalysis(scanId, target);
    default:
      throw new Error(`Unknown stage: ${stage.name}`);
  }
}

/**
 * Run nmap port scan
 */
async function runPortScan(scanId, target, scanDepth) {
  const scanOptions = {
    basic: ['-T4', '-p', '80,443,22,21,25,53,3389'],
    medium: ['-T4', '-p', '1-1000'],
    deep: ['-T4', '-p', '1-65535']
  };

  console.log(`[Scan ${scanId}] Running port scan using NEW MCP SIDEEFFECT for target: ${target}`);
  
  try {
    const mcpClient = await getMcpClient(); // Get the imported new module
    const result = await mcpClient.invokeNmapScan({ // Call the new function
      target: target,
      nmap_args: scanOptions[scanDepth] 
    });
    
    console.log(`[Scan ${scanId}] Port scan completed via NEW MCP SIDEEFFECT`);
    
    let nmapOutputText = "";
    // The new server returns content[0].text which contains a summary and then the full XML stringified.
    // We need to extract a text part that parseNmapOutputFromText can work with.
    // For now, let's assume the summary part is sufficient or adapt parsing later.
    if (result && result.content && Array.isArray(result.content) && result.content.length > 0 && result.content[0].text) {
      // Extract the summary part before "Full XML Output:"
      const fullText = result.content[0].text;
      const xmlMarker = "\n\nFull XML Output:\n";
      const xmlStartIndex = fullText.indexOf(xmlMarker);
      if (xmlStartIndex !== -1) {
        nmapOutputText = fullText.substring(0, xmlStartIndex); 
      } else {
        nmapOutputText = fullText; // Fallback to full text if marker not found
      }
    } else {
      console.warn(`[Scan ${scanId}] Unexpected Nmap MCP SIDEEFFECT result structure:`, JSON.stringify(result, null, 2));
      return {
        ports: [], 
        hosts: [],
        summary: `Port scan for ${target} completed, but output parsing might be incorrect.` 
      };
    }
    
    console.log(`[Scan ${scanId}] Raw nmap output (summary part) from NEW MCP SIDEEFFECT:\n${nmapOutputText}`);
    
    const parsedResults = parseNmapOutputFromText(nmapOutputText);
    console.log(`[Scan ${scanId}] Parsed port scan results: `, JSON.stringify(parsedResults, null, 2));
    
    return parsedResults;

  } catch (error) {
    console.error(`[Scan ${scanId}] Error in NEW MCP SIDEEFFECT port scan:`, error);
    throw new Error(`Port scan failed: ${error.message}`);
  }
}

/**
 * Parse nmap output from text format
 */
function parseNmapOutputFromText(nmapOutput) {
  // Basic parsing of nmap output text
  const result = {
    ports: [],
    hosts: []
  };

  // Accept lines like "80/tcp  open  http" OR "80/tcp  -  http" (new MCP summary)
  const portRegex = /(\d+)\/(tcp|udp)\s+(open|closed|filtered|\-)?\s*-?\s*(\S+)/g;
  let match;
  
  while ((match = portRegex.exec(nmapOutput)) !== null) {
    result.ports.push({
      port: match[1],
      protocol: match[2],
      state: match[3] && match[3] !== '-' ? match[3] : '-',
      service: match[4],
      scripts: [] // Will be filled if script output is found
    });
  }

  return result;
}

/**
 * Run nmap service detection
 */
async function runServiceDetection(scanId, target, scanDepth) {
  const scanOptions = {
    basic: ['-sV', '-T4', '-F'],
    medium: ['-sV', '-T4', '-p', '1-1000'],
    deep: ['-sV', '-O', '-T4', '-p', '1-65535']
  };

  console.log(`[Scan ${scanId}] Running service detection using NEW MCP SIDEEFFECT for target: ${target}`);
  
  try {
    const mcpClient = await getMcpClient(); // Get the imported new module
    const result = await mcpClient.invokeNmapScan({ // Call the new function
      target: target,
      nmap_args: scanOptions[scanDepth]
    });
    
    console.log(`[Scan ${scanId}] Service detection completed via NEW MCP SIDEEFFECT`);
    
    let nmapOutputText = "";
    if (result && result.content && Array.isArray(result.content) && result.content.length > 0 && result.content[0].text) {
      const fullText = result.content[0].text;
      const xmlMarker = "\n\nFull XML Output:\n";
      const xmlStartIndex = fullText.indexOf(xmlMarker);
      if (xmlStartIndex !== -1) {
        nmapOutputText = fullText.substring(0, xmlStartIndex); 
      } else {
        nmapOutputText = fullText; 
      }
    } else {
      console.warn(`[Scan ${scanId}] Unexpected Nmap MCP SIDEEFFECT result structure for service detection:`, JSON.stringify(result, null, 2));
      return {
        ports: [], 
        hosts: [],
        summary: `Service detection for ${target} completed, but output parsing might be incorrect.` 
      };
    }

    console.log(`[Scan ${scanId}] Raw service detection output (summary part) from NEW MCP SIDEEFFECT:\n${nmapOutputText}`);
    
    const parsedResults = parseNmapOutputFromText(nmapOutputText); // Existing parser
    console.log(`[Scan ${scanId}] Parsed service detection results:`, JSON.stringify(parsedResults, null, 2));
    
    return parsedResults;
  } catch (error) {
    console.error(`[Scan ${scanId}] Error in NEW MCP SIDEEFFECT service detection:`, error);
    throw new Error(`Service detection failed: ${error.message}`);
  }
}

/**
 * Run vulnerability scan using nmap scripts
 */
async function runVulnerabilityScan(scanId, target, scanDepth) {
  const scanOptions = {
    basic: ['--script', 'vuln', '-T4', '-F'],
    medium: ['--script', 'vuln', '-T4', '-p', '1-1000'],
    deep: ['--script', 'vuln', '-T4', '-p', '1-65535']
  };

  console.log(`[Scan ${scanId}] Running vulnerability scan using NEW MCP SIDEEFFECT for target: ${target}`);
  
  try {
    const mcpClient = await getMcpClient(); // Get the imported new module
    const result = await mcpClient.invokeNmapScan({ // Call the new function
      target: target,
      nmap_args: scanOptions[scanDepth]
    });
    
    console.log(`[Scan ${scanId}] Vulnerability scan completed via NEW MCP SIDEEFFECT`);
    
    let nmapOutputText = "";
    if (result && result.content && Array.isArray(result.content) && result.content.length > 0 && result.content[0].text) {
      const fullText = result.content[0].text;
      const xmlMarker = "\n\nFull XML Output:\n";
      const xmlStartIndex = fullText.indexOf(xmlMarker);
      if (xmlStartIndex !== -1) {
        // For vulnerability scans, parseNmapOutputWithScripts needs more than just summary.
        // It might be better to parse the JSON stringified XML for richer data if available.
        // However, sticking to current parsers, we might lose script details from summary only.
        // Let's pass the full text for now to parseNmapOutputWithScripts, as it might contain script output before the XML marker.
        nmapOutputText = fullText.substring(0, xmlStartIndex); // Or fullText if scripts are above XML summary
      } else {
        nmapOutputText = fullText; 
      }
    } else {
      console.warn(`[Scan ${scanId}] Unexpected Nmap MCP SIDEEFFECT result structure for vulnerability scan:`, JSON.stringify(result, null, 2));
      return { 
        ports: [], 
        hosts: [],
        vulnerabilities: [],
        summary: `Vulnerability scan for ${target} completed, but output parsing might be incorrect.` 
      };
    }

    console.log(`[Scan ${scanId}] Raw vulnerability scan output (summary part or full if no marker) from NEW MCP SIDEEFFECT:\n${nmapOutputText}`);
    
    // parseNmapOutputWithScripts might need adjustment if the summary doesn't have enough detail for scripts.
    // The new server structure might put script details in the XML part.
    const parsedResults = parseNmapOutputWithScripts(nmapOutputText);
    console.log(`[Scan ${scanId}] Parsed vulnerability scan results:`, JSON.stringify(parsedResults, null, 2));
    
    return parsedResults;
  } catch (error) {
    console.error(`[Scan ${scanId}] Error in NEW MCP SIDEEFFECT vulnerability scan:`, error);
    throw new Error(`Vulnerability scan failed: ${error.message}`);
  }
}

/**
 * Parse nmap output that includes script results
 */
function parseNmapOutputWithScripts(nmapOutput) {
  const result = parseNmapOutputFromText(nmapOutput);
  
  // Extract vulnerability information from script output
  const scriptRegex = /\|\s+([^:]+):\s+(.*?)(?=\n\||\n\n|$)/gs;
  let match;
  
  // Track current port for associating scripts
  let currentPort = null;
  
  // Split the output by lines to track context
  const lines = nmapOutput.split('\n');
  for (let i = 0; i < lines.length; i++) {
    const line = lines[i];
    
    // Check if line contains port information
    const portMatch = /^(\d+)\/(tcp|udp)/.exec(line);
    if (portMatch) {
      currentPort = portMatch[1];
      continue;
    }
    
    // Check for script output
    if (line.startsWith('|') && currentPort) {
      const scriptMatch = /\|\s+([^:]+):\s+(.*)/.exec(line);
      if (scriptMatch) {
        // Find the port in our result
        const port = result.ports.find(p => p.port === currentPort);
        if (port) {
          port.scripts = port.scripts || [];
          port.scripts.push({
            id: scriptMatch[1].trim(),
            output: scriptMatch[2].trim()
          });
        }
      }
    }
  }
  
  return result;
}

/**
 * Run web analysis for HTTP/HTTPS services
 */
async function runWebAnalysis(scanId, target, scanDepth) {
  // Use whatweb for basic web fingerprinting
  const whatwebCommand = `whatweb -a 3 ${target}`;
  console.log(`[Scan ${scanId}] Running web analysis command: ${whatwebCommand}`);
  
  try {
    const whatwebResult = await runCommand(scanId, whatwebCommand);
    console.log(`[Scan ${scanId}] Web analysis raw output:\n${whatwebResult.stdout}`);
    return {
      whatweb: whatwebResult.stdout
    };
  } catch (error) {
    console.log(`[Scan ${scanId}] Web analysis failed, falling back to curl: ${error.message}`);
    // If whatweb fails, try a basic curl
    const curlCommand = `curl -sL -A "Mozilla/5.0" -m 10 --insecure https://${target}`;
    console.log(`[Scan ${scanId}] Running fallback curl command: ${curlCommand}`);
    
    const curlResult = await runCommand(scanId, curlCommand);
    console.log(`[Scan ${scanId}] Curl raw output:\n${curlResult.stdout.substring(0, 5000)}`);
    
    return {
      curl: curlResult.stdout.substring(0, 5000) // Limit output size
    };
  }
}

/**
 * Run SSL/TLS scan
 */
async function runSSLScan(scanId, target) {
  const command = `sslscan --no-colour ${target}`;
  console.log(`[Scan ${scanId}] Running SSL scan command: ${command}`);
  
  try {
    const result = await runCommand(scanId, command);
    console.log(`[Scan ${scanId}] SSL scan raw output:\n${result.stdout}`);
    
    const parsedResults = parseSSLScanOutput(result.stdout);
    console.log(`[Scan ${scanId}] Parsed SSL scan results:`, JSON.stringify(parsedResults, null, 2));
    
    return parsedResults;
  } catch (error) {
    console.log(`[Scan ${scanId}] SSL scan failed: ${error.message}`);
    return { error: error.message };
  }
}

/**
 * Run DNS analysis
 */
async function runDNSAnalysis(scanId, target) {
  // Use dig for DNS lookups
  const commands = [
    `dig ANY ${target}`,
    `dig MX ${target}`,
    `dig TXT ${target}`,
    `dig NS ${target}`
  ];
  
  const results = {};
  
  for (const command of commands) {
    try {
      const result = await runCommand(scanId, command);
      const type = command.split(' ')[1]; // Extract record type
      results[type] = result.stdout;
    } catch (error) {
      results[command.split(' ')[1]] = { error: error.message };
    }
  }
  
  return results;
}

/**
 * Process scan results with Anthropic API
 */
async function processWithAI(target, scanResults, aiMode, prompt, context) {
  console.log(`[AI] Processing with mode: ${aiMode}`);
  console.log(`[AI] Target: ${target}`);
  console.log(`[AI] Prompt: ${prompt}`);
  console.log(`[AI] Context length: ${context.length} characters`);
  
  const systemPrompt = getAISystemPrompt(aiMode);
  console.log(`[AI] System prompt: ${systemPrompt}`);
  
  try {
    console.log(`[AI] Sending request to Anthropic API...`);
    const aiResponse = await anthropic.messages.create({
      model: process.env.ANTHROPIC_MODEL,
      max_tokens: 4000,
      system: systemPrompt,
      messages: [
        {
          role: "user",
          content: `${prompt}\n\nTarget: ${target}\n\nContext:\n${context}`
        }
      ],
    });
    
    console.log(`[AI] Received response from Anthropic API`);
    console.log(`[AI] Response length: ${aiResponse.content[0].text.length} characters`);
    
    return aiResponse.content[0].text;
  } catch (error) {
    console.error('[AI] Error calling Anthropic API:', error);
    return `Error processing with AI: ${error.message}`;
  }
}

/**
 * Get AI system prompt based on mode
 */
function getAISystemPrompt(aiMode) {
  const basePrompt = `You are an expert cybersecurity analyst specializing in network reconnaissance and vulnerability assessment. 
You analyze scan results and provide detailed, technical insights based on the findings.`;
  
  const modePrompts = {
    defensive: `${basePrompt} Focus on defensive security measures, hardening recommendations, and how to protect against potential vulnerabilities found. Your goal is to help secure the system.`,
    offensive: `${basePrompt} Focus on identifying exploitable vulnerabilities, attack vectors, and potential security flaws from an offensive security perspective. Your goal is to highlight security weaknesses.`,
    comprehensive: `${basePrompt} Provide a comprehensive analysis covering both offensive and defensive aspects. Identify vulnerabilities and suggest specific remediation steps. Include technical details but also offer a high-level summary.`
  };
  
  return modePrompts[aiMode] || modePrompts.comprehensive;
}

/**
 * Extract and structure vulnerabilities from scan results and AI analysis
 */
function extractVulnerabilities(scanResults, aiAnalysis) {
  // Extract clear vulnerabilities from nmap vuln scan results
  const vulnScanResults = scanResults.vulnerability_scan || {};
  const extractedVulns = [];
  
  // Add structured vulnerabilities from scans
  if (vulnScanResults.ports) {
    vulnScanResults.ports.forEach(port => {
      if (port.scripts) {
        port.scripts.forEach(script => {
          if (script.id.includes('vuln')) {
            extractedVulns.push({
              id: extractedVulns.length + 1,
              name: script.id,
              severity: determineSeverity(script.output),
              description: script.output,
              port: port.port,
              service: port.service
            });
          }
        });
      }
    });
  }
  
  // Add SSL/TLS vulnerabilities if found
  if (scanResults.ssl_scan && scanResults.ssl_scan.vulnerabilities) {
    scanResults.ssl_scan.vulnerabilities.forEach(vuln => {
      extractedVulns.push({
        id: extractedVulns.length + 1,
        name: vuln.name,
        severity: vuln.severity,
        description: vuln.description
      });
    });
  }
  
  // For now, return the basic extracted vulnerabilities
  // More sophisticated extraction would involve NLP analysis of the AI output
  return extractedVulns;
}

/**
 * Determine severity level based on output text
 */
function determineSeverity(text) {
  const textLower = text.toLowerCase();
  if (textLower.includes('critical') || textLower.includes('high risk')) {
    return 'high';
  } else if (textLower.includes('medium risk') || textLower.includes('warning')) {
    return 'medium';
  } else {
    return 'low';
  }
}

/**
 * Parse nmap output into structured JSON
 */
function parseNmapOutput(output) {
  // Basic parsing of nmap output
  const result = {
    ports: [],
    hosts: []
  };

  const portRegex = /(\d+)\/(tcp|udp)\s+(open|closed|filtered)\s+(\S+)/g;
  let match;
  
  while ((match = portRegex.exec(output)) !== null) {
    result.ports.push({
      port: match[1],
      protocol: match[2],
      state: match[3],
      service: match[4],
      scripts: [] // Will be filled if script output is found
    });
  }

  return result;
}

/**
 * Parse sslscan output into structured JSON
 */
function parseSSLScanOutput(output) {
  const result = {
    certificates: [],
    protocols: [],
    ciphers: [],
    vulnerabilities: []
  };

  // Parse supported protocols
  const protocolRegex = /SSL\s+([^\s]+)\s+:\s+([A-Za-z]+)/g;
  let protocolMatch;
  while ((protocolMatch = protocolRegex.exec(output)) !== null) {
    result.protocols.push({
      version: protocolMatch[1],
      supported: protocolMatch[2].toLowerCase() === 'enabled'
    });
  }

  // Check for common vulnerabilities based on output text
  if (output.includes('Heartbleed')) {
    result.vulnerabilities.push({
      name: 'Heartbleed',
      severity: 'high',
      description: 'Server is vulnerable to the Heartbleed attack (CVE-2014-0160)'
    });
  }
  
  if (output.includes('POODLE')) {
    result.vulnerabilities.push({
      name: 'POODLE',
      severity: 'medium',
      description: 'Server is vulnerable to the POODLE attack against SSLv3 (CVE-2014-3566)'
    });
  }
  
  if (output.includes('FREAK')) {
    result.vulnerabilities.push({
      name: 'FREAK',
      severity: 'medium',
      description: 'Server is vulnerable to the FREAK attack (CVE-2015-0204)'
    });
  }
  
  if (output.includes('LOGJAM')) {
    result.vulnerabilities.push({
      name: 'LOGJAM',
      severity: 'medium',
      description: 'Server is vulnerable to the LOGJAM attack (CVE-2015-4000)'
    });
  }

  return result;
}

/**
 * Run a system command and track the process
 */
async function runCommand(scanId, command) {
  return new Promise((resolve, reject) => {
    const childProcess = exec(command, { timeout: 300000 }, (error, stdout, stderr) => {
      // Remove from tracking
      runningProcesses.delete(scanId);
      
      if (error) {
        reject(error);
        return;
      }
      
      resolve({ stdout, stderr });
    });
    
    // Track the process for possible cancellation
    const processes = runningProcesses.get(scanId) || [];
    processes.push(childProcess);
    runningProcesses.set(scanId, processes);
  });
}

/**
 * Update scan status
 */
function updateScanStatus(scanId, status, progress, currentStage, scanStore) {
  if (!scanStore.has(scanId)) return;
  
  const scan = scanStore.get(scanId);
  scan.status = status;
  scan.progress = progress;
  scan.currentStage = currentStage;
  scanStore.set(scanId, scan);
}

/**
 * Calculate progress percentage based on completed stages
 */
function calculateProgress(stages, currentStageIndex) {
  const stageProgress = (currentStageIndex / stages.length) * 100;
  return Math.min(Math.round(stageProgress), 95); // Cap at 95% until fully complete
}

/**
 * Define scan stages based on depth
 */
function getScanStagesForDepth(scanDepth) {
  const basicStages = [
    { name: 'port_scan', aiIntervention: false },
    { name: 'service_detection', aiIntervention: true, aiPrompt: 'Identify key services and potential security implications.' },
    { name: 'vulnerability_scan', aiIntervention: true, aiPrompt: 'Analyze the vulnerabilities found and prioritize them.' }
  ];
  
  const mediumStages = [
    ...basicStages,
    { name: 'web_analysis', aiIntervention: true, aiPrompt: 'Identify web technologies and potential vulnerabilities.' },
    { name: 'ssl_scan', aiIntervention: false }
  ];
  
  const deepStages = [
    ...mediumStages,
    { name: 'dns_analysis', aiIntervention: true, aiPrompt: 'Analyze DNS configuration for security issues.' }
  ];
  
  switch (scanDepth) {
    case 'basic':
      return basicStages;
    case 'medium':
      return mediumStages;
    case 'deep':
      return deepStages;
    default:
      return mediumStages;
  }
}

/**
 * Cancel an ongoing scan
 */
exports.cancelScan = (scanId) => {
  if (runningProcesses.has(scanId)) {
    const processes = runningProcesses.get(scanId);
    for (const process of processes) {
      try {
        process.kill();
      } catch (error) {
        console.error(`Error killing process for scan ${scanId}:`, error);
      }
    }
    runningProcesses.delete(scanId);
  }
};

// Export functions for testing
exports.runPortScan = runPortScan;
exports.runServiceDetection = runServiceDetection;
exports.runVulnerabilityScan = runVulnerabilityScan;
exports.parseNmapOutputFromText = parseNmapOutputFromText;
exports.parseNmapOutputWithScripts = parseNmapOutputWithScripts; 