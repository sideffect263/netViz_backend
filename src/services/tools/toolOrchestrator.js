const { DynamicTool } = require('langchain/tools');

/**
 * Tool Orchestrator - Intelligent tool chaining and workflow management
 * This provides higher-level tools that combine multiple atomic tools
 */

class ToolOrchestrator {
  constructor(tools) {
    this.tools = new Map();
    this.workflows = new Map();
    
    // Index tools by name for easy access
    tools.forEach(tool => {
      this.tools.set(tool.name, tool);
    });
    
    this.initializeWorkflows();
  }
  
  initializeWorkflows() {
    // Define intelligent workflows that combine multiple tools
    this.workflows.set('comprehensive_domain_analysis', {
      name: 'Comprehensive Domain Analysis',
      description: 'Complete intelligence gathering on a domain using multiple tools in optimal sequence',
      steps: [
        { tool: 'WhoisLookup', required: true },
        { tool: 'DNSRecon', required: true },
        { tool: 'NmapScanner', required: false, condition: 'if_ip_found' },
        { tool: 'DNSTwist', required: false, condition: 'if_brand_protection_needed' }
      ]
    });
    
    this.workflows.set('security_assessment', {
      name: 'Security Assessment',
      description: 'Comprehensive security analysis combining OSINT and active scanning',
      steps: [
        { tool: 'OSINTOverview', required: true },
        { tool: 'NmapScanner', required: true, params: { flags: ['-sV', '-sC', '-T4'] } },
        { tool: 'DNSTwist', required: false, condition: 'if_domain_target' }
      ]
    });
    
    this.workflows.set('quick_reconnaissance', {
      name: 'Quick Reconnaissance',
      description: 'Fast initial reconnaissance for time-sensitive analysis',
      steps: [
        { tool: 'DigLookup', required: true },
        { tool: 'NmapScanner', required: true, params: { flags: ['-T4', '-F'] } },
        { tool: 'WhoisLookup', required: false }
      ]
    });
  }
  
  async executeWorkflow(workflowName, target, options = {}) {
    const workflow = this.workflows.get(workflowName);
    if (!workflow) {
      throw new Error(`Unknown workflow: ${workflowName}`);
    }
    
    const results = [];
    let context = { target, ...options };
    
    console.log(`Executing workflow: ${workflow.name} for target: ${target}`);
    
    for (const step of workflow.steps) {
      try {
        // Check if step should be executed based on conditions
        if (!this.shouldExecuteStep(step, context, results)) {
          console.log(`Skipping step ${step.tool} due to condition: ${step.condition}`);
          continue;
        }
        
        const tool = this.tools.get(step.tool);
        if (!tool) {
          console.warn(`Tool ${step.tool} not found, skipping step`);
          continue;
        }
        
        console.log(`Executing step: ${step.tool}`);
        
        // Prepare input for the tool
        const input = this.prepareToolInput(step, target, context);
        
        // Execute the tool
        const result = await tool.func(input);
        
        // Store result and update context
        const stepResult = {
          tool: step.tool,
          input,
          output: result,
          timestamp: new Date().toISOString()
        };
        
        results.push(stepResult);
        context = this.updateContext(context, stepResult);
        
        console.log(`Completed step: ${step.tool}`);
        
      } catch (error) {
        console.error(`Error in workflow step ${step.tool}:`, error);
        
        if (step.required) {
          throw new Error(`Required step ${step.tool} failed: ${error.message}`);
        }
        
        // Continue with non-required steps
        results.push({
          tool: step.tool,
          error: error.message,
          timestamp: new Date().toISOString()
        });
      }
    }
    
    return {
      workflow: workflow.name,
      target,
      results,
      summary: this.generateWorkflowSummary(workflow, results)
    };
  }
  
  shouldExecuteStep(step, context, previousResults) {
    if (!step.condition) return true;
    
    switch (step.condition) {
      case 'if_ip_found':
        return previousResults.some(r => 
          r.output && r.output.includes('A record') || r.output.includes('IPv4')
        );
        
      case 'if_brand_protection_needed':
        return context.includeBrandProtection === true;
        
      case 'if_domain_target':
        return /^[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9]\.[a-zA-Z]{2,}$/.test(context.target);
        
      default:
        return true;
    }
  }
  
  prepareToolInput(step, target, context) {
    if (step.params) {
      // For tools that need specific parameters
      if (step.tool === 'NmapScanner' && step.params.flags) {
        return `${step.params.flags.join(' ')} ${target}`;
      }
    }
    
    return target;
  }
  
  updateContext(context, stepResult) {
    // Extract useful information from step results to inform future steps
    const newContext = { ...context };
    
    if (stepResult.tool === 'WhoisLookup' && stepResult.output) {
      // Extract name servers, registrar info, etc.
      if (stepResult.output.includes('Name Server:')) {
        newContext.hasNameServers = true;
      }
    }
    
    if (stepResult.tool === 'DNSRecon' && stepResult.output) {
      // Extract IP addresses found
      const ipMatches = stepResult.output.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/g);
      if (ipMatches) {
        newContext.discoveredIPs = [...(newContext.discoveredIPs || []), ...ipMatches];
      }
    }
    
    return newContext;
  }
  
  generateWorkflowSummary(workflow, results) {
    const successful = results.filter(r => !r.error).length;
    const failed = results.filter(r => r.error).length;
    
    return {
      workflowName: workflow.name,
      totalSteps: results.length,
      successful,
      failed,
      executionTime: this.calculateExecutionTime(results),
      keyFindings: this.extractKeyFindings(results)
    };
  }
  
  calculateExecutionTime(results) {
    if (results.length === 0) return 0;
    
    const start = new Date(results[0].timestamp);
    const end = new Date(results[results.length - 1].timestamp);
    return end - start;
  }
  
  extractKeyFindings(results) {
    const findings = [];
    
    results.forEach(result => {
      if (result.error) return;
      
      switch (result.tool) {
        case 'WhoisLookup':
          if (result.output.includes('Registrar:')) {
            findings.push('Domain registration information found');
          }
          break;
          
        case 'DNSRecon':
          if (result.output.includes('A record')) {
            findings.push('DNS A records discovered');
          }
          if (result.output.includes('MX record')) {
            findings.push('Mail servers identified');
          }
          break;
          
        case 'NmapScanner':
          if (result.output.includes('open')) {
            findings.push('Open ports detected');
          }
          break;
          
        case 'DNSTwist':
          if (result.output.includes('domain')) {
            findings.push('Similar domains found');
          }
          break;
      }
    });
    
    return findings;
  }
  
  // Create orchestrated tools that can be used by the agent
  createOrchestratedTools() {
    const tools = [];
    
    // Create combined overview tool
    const overviewTool = this.createOverviewTool();
    if (overviewTool) {
      tools.push(overviewTool);
    }
    
    // Create vulnerability assessment tool
    const vulnAssessmentTool = this.createVulnerabilityAssessmentTool();
    if (vulnAssessmentTool) {
      tools.push(vulnAssessmentTool);
    }
    
    // Create quick reconnaissance tool
    const quickReconTool = this.createQuickReconnaissanceTool();
    if (quickReconTool) {
      tools.push(quickReconTool);
    }
    
    return tools;
  }
  
  /**
   * Get a tool by name from the tools map
   * @param {string} name - The tool name
   * @returns {Object|null} The tool object or null if not found
   */
  getToolByName(name) {
    return this.tools.get(name) || null;
  }
  
  /**
   * Create the overview tool (formerly ComprehensiveDomainAnalysis)
   * @returns {DynamicTool|null} The overview tool or null if dependencies are missing
   */
  createOverviewTool() {
    const requiredTools = ['WhoisLookup', 'DNSRecon'];
    const missingTools = requiredTools.filter(name => !this.tools.has(name));
    
    if (missingTools.length > 0) {
      console.log(`Skipping overview tool - missing dependencies: ${missingTools.join(', ')}`);
      return null;
    }
    
    return new DynamicTool({
      name: 'ComprehensiveDomainAnalysis',
      description: `Performs complete domain intelligence gathering using multiple tools in optimal sequence.
This tool automatically:
1. Gathers WHOIS registration information
2. Performs comprehensive DNS reconnaissance
3. Conducts port scanning if IP addresses are found
4. Optionally checks for typosquatting domains

Perfect for thorough domain analysis when you need complete intelligence.
Usage: Provide just the domain name (e.g., "example.com")`,
      func: async (input) => {
        try {
          const result = await this.executeWorkflow('comprehensive_domain_analysis', input.trim());
          return this.formatWorkflowResult(result);
        } catch (error) {
          return `Error in comprehensive domain analysis: ${error.message}`;
        }
      }
    });
  }
  
  /**
   * Create the quick reconnaissance tool
   * @returns {DynamicTool} The quick reconnaissance tool
   */
  createQuickReconnaissanceTool() {
    return new DynamicTool({
      name: 'QuickReconnaissance',
      description: `Performs fast initial reconnaissance for time-sensitive analysis.
This tool automatically:
1. Quick DNS lookup for basic information
2. Fast port scan of common ports
3. Basic WHOIS information if time permits

Perfect for rapid initial assessment when speed is critical.
Usage: Provide domain name or IP address (e.g., "example.com" or "192.168.1.1")`,
      func: async (input) => {
        try {
          const result = await this.executeWorkflow('quick_reconnaissance', input.trim());
          return this.formatWorkflowResult(result);
        } catch (error) {
          return `Error in quick reconnaissance: ${error.message}`;
        }
      }
    });
  }
  
  /**
   * Create a vulnerability assessment tool that combines scanning with exploit research
   * @returns {DynamicTool|null} The vulnerability assessment tool or null if dependencies are missing
   */
  createVulnerabilityAssessmentTool() {
    const nmapTool = this.getToolByName('NmapScanner');
    const exploitSearchTool = this.getToolByName('MetasploitExploitSearch');
    
    if (!nmapTool || !exploitSearchTool) {
      console.log('Skipping vulnerability assessment tool - missing dependencies');
      return null;
    }
    
    return new DynamicTool({
      name: 'VulnerabilityAssessment',
      description: `Performs comprehensive vulnerability assessment by:
1. Scanning target for open ports and services
2. Identifying service versions
3. Searching for known exploits for discovered services
This tool combines network scanning with exploit intelligence to provide a complete security picture.

Example usage: "assess vulnerabilities on scanme.nmap.org"`,
      func: async (target) => {
        try {
          console.log(`Starting vulnerability assessment for ${target}`);
          
          // Step 1: Service version scan
          console.log('Step 1: Scanning for services and versions...');
          const scanResult = await nmapTool.func(`${target} -sV`);
          
          // Parse scan results to extract services
          const services = this.parseServicesFromScan(scanResult);
          
          if (services.length === 0) {
            return `Vulnerability Assessment Complete for ${target}:\n\nNo open services detected. The target appears to be well-protected or filtered.`;
          }
          
          // Step 2: Search for exploits for each service
          console.log('Step 2: Searching for exploits...');
          const exploitResults = [];
          
          for (const service of services) {
            try {
              // Create search terms from service info
              const searchTerms = [
                service.product,
                service.version ? `${service.product} ${service.version}` : null,
                service.info
              ].filter(Boolean);
              
              for (const term of searchTerms) {
                const exploits = await exploitSearchTool.func({ searchTerm: term });
                if (exploits && !exploits.includes('No exploits found')) {
                  exploitResults.push({
                    service: `${service.port}/${service.protocol} - ${service.product} ${service.version || ''}`,
                    exploits: exploits
                  });
                  break; // Found exploits, no need to try other terms
                }
              }
            } catch (error) {
              console.error(`Error searching exploits for ${service.product}:`, error);
            }
          }
          
          // Step 3: Generate comprehensive report
          let report = `🔍 Vulnerability Assessment Report for ${target}\n\n`;
          report += `📊 Scan Summary:\n`;
          report += scanResult + '\n\n';
          
          if (exploitResults.length > 0) {
            report += `⚠️ Potential Vulnerabilities Found:\n\n`;
            for (const result of exploitResults) {
              report += `Service: ${result.service}\n`;
              report += result.exploits + '\n\n';
            }
            
            report += `🎯 Recommendations:\n`;
            report += `1. Update all services to their latest versions\n`;
            report += `2. Review and patch the identified vulnerabilities\n`;
            report += `3. Consider running MetasploitVulnerabilityCheck for specific exploits\n`;
            report += `4. Implement proper firewall rules to limit exposure\n`;
          } else {
            report += `✅ No known exploits found for the discovered services.\n\n`;
            report += `Note: This doesn't mean the system is secure. Always:\n`;
            report += `- Keep services updated to latest versions\n`;
            report += `- Follow security best practices\n`;
            report += `- Perform regular security assessments\n`;
          }
          
          return report;
          
        } catch (error) {
          return `Error during vulnerability assessment: ${error.message}`;
        }
      }
    });
  }
  
  /**
   * Parse services from Nmap scan output
   * @param {string} scanOutput - The Nmap scan output
   * @returns {Array} Array of service objects
   */
  parseServicesFromScan(scanOutput) {
    const services = [];
    const lines = scanOutput.split('\n');
    
    for (const line of lines) {
      // Match lines like: "22/tcp open ssh OpenSSH 7.4 (protocol 2.0)"
      const serviceMatch = line.match(/(\d+)\/(tcp|udp)\s+open\s+(\S+)\s*(.*)?/);
      if (serviceMatch) {
        const [_, port, protocol, service, versionInfo] = serviceMatch;
        
        // Try to extract product and version from version info
        let product = service;
        let version = '';
        let info = versionInfo || '';
        
        // Common patterns for version extraction
        const versionMatch = versionInfo?.match(/^(\S+)\s+([\d.]+)/);
        if (versionMatch) {
          product = versionMatch[1];
          version = versionMatch[2];
        }
        
        services.push({
          port: parseInt(port),
          protocol,
          service,
          product,
          version,
          info: info.trim()
        });
      }
    }
    
    return services;
  }
  
  formatWorkflowResult(result) {
    let output = `\n=== ${result.workflow} Results ===\n`;
    output += `Target: ${result.target}\n`;
    output += `Execution Summary: ${result.summary.successful}/${result.summary.totalSteps} steps completed\n\n`;
    
    result.results.forEach((step, index) => {
      output += `--- Step ${index + 1}: ${step.tool} ---\n`;
      if (step.error) {
        output += `Error: ${step.error}\n`;
      } else {
        output += `${step.output}\n`;
      }
      output += '\n';
    });
    
    if (result.summary.keyFindings.length > 0) {
      output += '=== Key Findings ===\n';
      result.summary.keyFindings.forEach(finding => {
        output += `• ${finding}\n`;
      });
    }
    
    return output;
  }
}

module.exports = {
  ToolOrchestrator
}; 