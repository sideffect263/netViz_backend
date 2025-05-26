// Enhanced WebSocket callback handler with improved reasoning visibility
class EnhancedWebSocketCallbackHandler {
  constructor(sessionId, sendEventToSocket) {
    this.sessionId = sessionId;
    this.sendEventToSocket = sendEventToSocket;
    this.currentThought = '';
    this.toolSelectionReasoning = [];
    this.workflowSteps = [];
  }

  get name() {
    return 'EnhancedWebSocketCallbackHandler';
  }

  async handleLLMStart(llm, prompts) {
    this.sendEventToSocket({
      type: 'llm_start',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      content: 'Starting to analyze your request...',
      phase: 'analysis'
    });
  }

  async handleLLMNewToken(token) {
    this.currentThought += token;
    
    // Detect reasoning patterns and extract insights
    this.extractReasoningInsights(token);
    
    this.sendEventToSocket({
      type: 'llm_token',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      content: token,
      phase: 'thinking'
    });
  }

  async handleLLMEnd(output) {
    // Analyze the complete thought for insights
    this.analyzeCompleteThought();
    
    this.sendEventToSocket({
      type: 'llm_end',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      content: 'Analysis complete',
      phase: 'analysis_complete',
      insights: this.extractThoughtInsights()
    });
    
    // Reset for next thought
    this.currentThought = '';
  }

  async handleToolStart(tool, input) {
    // Analyze tool selection reasoning
    const toolReasoning = this.analyzeToolSelection(tool, input);
    
    this.sendEventToSocket({
      type: 'tool_selection',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      toolName: tool.name,
      reasoning: toolReasoning,
      phase: 'tool_selection'
    });
    
    // Send progress update for specific tools
    if (tool.name === 'NmapScanner') {
      this.sendEventToSocket({
        type: 'progress_update',
        sessionId: this.sessionId,
        timestamp: new Date().toISOString(),
        message: 'Starting network scan. This may take some time depending on the scan parameters.',
        phase: 'scanning'
      });
    } else if (tool.name.includes('Comprehensive') || tool.name.includes('Security')) {
      this.sendEventToSocket({
        type: 'progress_update',
        sessionId: this.sessionId,
        timestamp: new Date().toISOString(),
        message: `Executing ${tool.name} workflow. This involves multiple steps and may take several minutes.`,
        phase: 'workflow_execution'
      });
    }
    
    this.sendEventToSocket({
      type: 'tool_start',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      toolName: tool.name,
      input: input,
      phase: 'tool_execution'
    });
  }

  async handleToolEnd(output) {
    // Analyze tool output for key insights
    const insights = this.analyzeToolOutput(output);
    
    this.sendEventToSocket({
      type: 'tool_end',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      output: output,
      insights: insights,
      phase: 'tool_complete'
    });
  }

  async handleAgentAction(action) {
    // Extract and format the agent's reasoning
    const reasoning = this.extractAgentReasoning(action);
    
    this.sendEventToSocket({
      type: 'agent_reasoning',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      action: action.tool,
      reasoning: reasoning,
      phase: 'decision_making'
    });
    
    this.sendEventToSocket({
      type: 'agent_action',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      tool: action.tool,
      toolInput: action.toolInput,
      log: action.log,
      phase: 'action_execution'
    });
  }

  async handleAgentEnd(action) {
    this.sendEventToSocket({
      type: 'agent_end',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      output: action.returnValues?.output,
      log: action.log,
      phase: 'completion'
    });
  }

  // Enhanced reasoning extraction methods
  extractReasoningInsights(token) {
    // Look for specific reasoning patterns
    if (token.includes('I need to') || token.includes('I should')) {
      this.toolSelectionReasoning.push({
        type: 'intention',
        content: token,
        timestamp: new Date().toISOString()
      });
    }
    
    if (token.includes('because') || token.includes('since')) {
      this.toolSelectionReasoning.push({
        type: 'justification',
        content: token,
        timestamp: new Date().toISOString()
      });
    }
  }

  analyzeCompleteThought() {
    // Analyze the complete thought for strategic insights
    const thought = this.currentThought.toLowerCase();
    
    if (thought.includes('comprehensive') || thought.includes('thorough')) {
      this.sendEventToSocket({
        type: 'strategic_insight',
        sessionId: this.sessionId,
        timestamp: new Date().toISOString(),
        insight: 'Agent is planning a comprehensive analysis approach',
        confidence: 'high'
      });
    }
    
    if (thought.includes('quick') || thought.includes('fast')) {
      this.sendEventToSocket({
        type: 'strategic_insight',
        sessionId: this.sessionId,
        timestamp: new Date().toISOString(),
        insight: 'Agent is optimizing for speed over completeness',
        confidence: 'high'
      });
    }
  }

  analyzeToolSelection(tool, input) {
    const reasoning = {
      toolName: tool.name,
      rationale: '',
      expectedOutcome: '',
      complexity: 'medium'
    };
    
    switch (tool.name) {
      case 'NmapScanner':
        reasoning.rationale = 'Selected for network port scanning and service detection';
        reasoning.expectedOutcome = 'Open ports, running services, and potential vulnerabilities';
        reasoning.complexity = input.includes('-A') || input.includes('-sV') ? 'high' : 'medium';
        break;
        
      case 'WhoisLookup':
        reasoning.rationale = 'Selected for domain registration and ownership information';
        reasoning.expectedOutcome = 'Registrar details, creation date, name servers';
        reasoning.complexity = 'low';
        break;
        
      case 'DNSRecon':
        reasoning.rationale = 'Selected for comprehensive DNS enumeration';
        reasoning.expectedOutcome = 'DNS records, subdomains, mail servers';
        reasoning.complexity = 'medium';
        break;
        
      case 'ComprehensiveDomainAnalysis':
        reasoning.rationale = 'Selected for complete domain intelligence gathering using multiple tools';
        reasoning.expectedOutcome = 'Complete domain profile including WHOIS, DNS, and security information';
        reasoning.complexity = 'high';
        break;
        
      case 'SecurityAssessment':
        reasoning.rationale = 'Selected for thorough security analysis combining OSINT and active scanning';
        reasoning.expectedOutcome = 'Security posture assessment with vulnerabilities and recommendations';
        reasoning.complexity = 'high';
        break;
        
      default:
        reasoning.rationale = `Selected ${tool.name} for specialized analysis`;
        reasoning.expectedOutcome = 'Tool-specific intelligence data';
    }
    
    return reasoning;
  }

  analyzeToolOutput(output) {
    const insights = [];
    
    if (typeof output === 'string') {
      // Look for security-relevant findings
      if (output.includes('open') && output.includes('port')) {
        insights.push({
          type: 'security_finding',
          severity: 'medium',
          description: 'Open ports detected - potential attack surface'
        });
      }
      
      if (output.includes('vulnerability') || output.includes('CVE')) {
        insights.push({
          type: 'security_finding',
          severity: 'high',
          description: 'Potential vulnerabilities identified'
        });
      }
      
      if (output.includes('domain') && output.includes('similar')) {
        insights.push({
          type: 'brand_protection',
          severity: 'medium',
          description: 'Similar domains found - potential typosquatting risk'
        });
      }
      
      // Look for infrastructure insights
      if (output.includes('A record') || output.includes('IPv4')) {
        insights.push({
          type: 'infrastructure',
          severity: 'info',
          description: 'IP address information discovered'
        });
      }
      
      if (output.includes('MX record') || output.includes('mail')) {
        insights.push({
          type: 'infrastructure',
          severity: 'info',
          description: 'Mail server configuration identified'
        });
      }
    }
    
    return insights;
  }

  extractAgentReasoning(action) {
    if (!action.log) return 'No reasoning available';
    
    // Extract thought and observation patterns from ReAct logs
    const lines = action.log.split('\n');
    const reasoning = {
      thought: '',
      observation: '',
      action_plan: ''
    };
    
    lines.forEach(line => {
      if (line.includes('Thought:')) {
        reasoning.thought = line.replace(/^.*Thought:\s*/, '').trim();
      } else if (line.includes('Observation:')) {
        reasoning.observation = line.replace(/^.*Observation:\s*/, '').trim();
      } else if (line.includes('Action:')) {
        reasoning.action_plan = line.replace(/^.*Action:\s*/, '').trim();
      }
    });
    
    return reasoning;
  }

  extractThoughtInsights() {
    return {
      toolSelectionCount: this.toolSelectionReasoning.length,
      reasoningPatterns: this.toolSelectionReasoning.map(r => r.type),
      complexity: this.currentThought.length > 500 ? 'high' : 'medium'
    };
  }

  // Additional handlers to match the interface
  async handleChainStart(chain) {}
  async handleChainEnd(outputs) {}
  async handleChainError(error) {}
  async handleToolError(error) {}
  async handleText(text) {}
  async handleLLMError(error) {}
}

module.exports = {
  EnhancedWebSocketCallbackHandler
}; 