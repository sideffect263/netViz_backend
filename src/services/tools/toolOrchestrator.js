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
    const orchestratedTools = [];
    
    // Comprehensive Domain Analysis Tool
    orchestratedTools.push(new DynamicTool({
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
    }));
    
    // Security Assessment Tool
    orchestratedTools.push(new DynamicTool({
      name: 'SecurityAssessment',
      description: `Performs comprehensive security assessment combining OSINT and active scanning.
This tool automatically:
1. Runs complete OSINT overview
2. Performs detailed port scan with service detection
3. Checks for brand protection issues if domain target

Perfect for security audits and penetration testing preparation.
Usage: Provide domain name or IP address (e.g., "example.com" or "192.168.1.1")`,
      func: async (input) => {
        try {
          const result = await this.executeWorkflow('security_assessment', input.trim());
          return this.formatWorkflowResult(result);
        } catch (error) {
          return `Error in security assessment: ${error.message}`;
        }
      }
    }));
    
    // Quick Reconnaissance Tool
    orchestratedTools.push(new DynamicTool({
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
    }));
    
    return orchestratedTools;
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