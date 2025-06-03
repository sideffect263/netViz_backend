// Enhanced WebSocket callback handler with improved reasoning visibility and robust error handling
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

  // Safe event sending with error handling
  safelyEmitEvent(eventData) {
    try {
      if (this.sendEventToSocket && typeof this.sendEventToSocket === 'function') {
        this.sendEventToSocket({
          ...eventData,
          sessionId: this.sessionId,
          timestamp: new Date().toISOString()
        });
      }
    } catch (error) {
      console.error('Error sending WebSocket event:', error);
    }
  }

  // Safe tool name extraction with multiple fallback methods
  safeGetToolName(tool) {
    try {
      if (!tool) return 'Unknown Tool';
      
      // Method 1: Direct name property
      if (tool.name && typeof tool.name === 'string') {
        return tool.name;
      }
      
      // Method 2: Constructor name
      if (tool.constructor && tool.constructor.name) {
        return tool.constructor.name;
      }
      
      // Method 3: Class name from toString
      if (tool.toString) {
        const match = tool.toString().match(/class\s+(\w+)/);
        if (match && match[1]) {
          return match[1];
        }
      }
      
      // Method 4: Type property
      if (tool.type && typeof tool.type === 'string') {
        return tool.type;
      }
      
      // Method 5: _name property (some tools use this)
      if (tool._name && typeof tool._name === 'string') {
        return tool._name;
      }
      
      return 'Unknown Tool';
    } catch (error) {
      console.error('Error extracting tool name:', error);
      return 'Unknown Tool';
    }
  }

  async handleLLMStart(llm, prompts) {
    try {
      this.safelyEmitEvent({
        type: 'llm_start',
        content: 'Starting to analyze your request...',
        phase: 'analysis'
      });
    } catch (error) {
      console.error('Error in handleLLMStart:', error);
    }
  }

  async handleLLMNewToken(token) {
    try {
      if (token && typeof token === 'string') {
        this.currentThought += token;
        
        // Detect reasoning patterns and extract insights
        this.extractReasoningInsights(token);
        
        this.safelyEmitEvent({
          type: 'llm_token',
          content: token,
          phase: 'thinking'
        });
      }
    } catch (error) {
      console.error('Error in handleLLMNewToken:', error);
    }
  }

  async handleLLMEnd(output) {
    try {
      // Analyze the complete thought for insights
      this.analyzeCompleteThought();
      
      this.safelyEmitEvent({
        type: 'llm_end',
        content: 'Analysis complete',
        phase: 'analysis_complete',
        insights: this.extractThoughtInsights()
      });
      
      // Reset for next thought
      this.currentThought = '';
    } catch (error) {
      console.error('Error in handleLLMEnd:', error);
    }
  }

  async handleToolStart(tool, input) {
    try {
      const toolName = this.safeGetToolName(tool);
      
      // Analyze tool selection reasoning
      const toolReasoning = this.analyzeToolSelection(tool, input);
      
      this.safelyEmitEvent({
        type: 'tool_selection',
        toolName: toolName,
        reasoning: toolReasoning,
        phase: 'tool_selection'
      });
      
      // Send progress update for specific tools
      if (toolName === 'NmapScanner') {
        this.safelyEmitEvent({
          type: 'progress_update',
          message: 'Starting network scan. This may take some time depending on the scan parameters.',
          phase: 'scanning'
        });
      } else if (toolName && (toolName.includes('Comprehensive') || toolName.includes('Security'))) {
        this.safelyEmitEvent({
          type: 'progress_update',
          message: `Executing ${toolName} workflow. This involves multiple steps and may take several minutes.`,
          phase: 'workflow_execution'
        });
      }
      
      this.safelyEmitEvent({
        type: 'tool_start',
        toolName: toolName,
        input: input,
        phase: 'tool_execution'
      });
    } catch (error) {
      console.error('Error in handleToolStart:', error);
      this.safelyEmitEvent({
        type: 'tool_start',
        toolName: 'Unknown Tool',
        input: input || 'No input provided',
        phase: 'tool_execution',
        error: 'Error processing tool start'
      });
    }
  }

  async handleToolEnd(output) {
    try {
      // Analyze tool output for key insights
      const insights = this.analyzeToolOutput(output);
      
      this.safelyEmitEvent({
        type: 'tool_end',
        output: output,
        insights: insights,
        phase: 'tool_complete'
      });
    } catch (error) {
      console.error('Error in handleToolEnd:', error);
    }
  }

  async handleAgentAction(action) {
    try {
      // Extract and format the agent's reasoning
      const reasoning = this.extractAgentReasoning(action);
      
      this.safelyEmitEvent({
        type: 'agent_reasoning',
        action: action?.tool || 'Unknown Action',
        reasoning: reasoning,
        phase: 'decision_making'
      });
      
      this.safelyEmitEvent({
        type: 'agent_action',
        tool: action?.tool || 'Unknown Tool',
        toolInput: action?.toolInput || {},
        log: action?.log || '',
        phase: 'action_execution'
      });
    } catch (error) {
      console.error('Error in handleAgentAction:', error);
    }
  }

  async handleAgentEnd(action) {
    try {
      this.safelyEmitEvent({
        type: 'agent_end',
        output: action?.returnValues?.output || 'No output available',
        log: action?.log || '',
        phase: 'completion'
      });
    } catch (error) {
      console.error('Error in handleAgentEnd:', error);
    }
  }

  // Enhanced reasoning extraction methods
  extractReasoningInsights(token) {
    try {
      if (!token || typeof token !== 'string') return;
      
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
    } catch (error) {
      console.error('Error extracting reasoning insights:', error);
    }
  }

  analyzeCompleteThought() {
    try {
      if (!this.currentThought || typeof this.currentThought !== 'string') return;
      
      // Analyze the complete thought for strategic insights
      const thought = this.currentThought.toLowerCase();
      
      if (thought.includes('comprehensive') || thought.includes('thorough')) {
        this.safelyEmitEvent({
          type: 'strategic_insight',
          insight: 'Agent is planning a comprehensive analysis approach',
          confidence: 'high'
        });
      }
      
      if (thought.includes('quick') || thought.includes('fast')) {
        this.safelyEmitEvent({
          type: 'strategic_insight',
          insight: 'Agent is optimizing for speed over completeness',
          confidence: 'high'
        });
      }
    } catch (error) {
      console.error('Error analyzing complete thought:', error);
    }
  }

  analyzeToolSelection(tool, input) {
    try {
      const toolName = this.safeGetToolName(tool);
      const reasoning = {
        toolName: toolName,
        rationale: '',
        expectedOutcome: '',
        complexity: 'medium'
      };
      
      switch (toolName) {
        case 'NmapScanner':
          reasoning.rationale = 'Selected for network port scanning and service detection';
          reasoning.expectedOutcome = 'Open ports, running services, and potential vulnerabilities';
          reasoning.complexity = (input && typeof input === 'string' && (input.includes('-A') || input.includes('-sV'))) ? 'high' : 'medium';
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
          reasoning.rationale = `Selected ${toolName} for specialized analysis`;
          reasoning.expectedOutcome = 'Tool-specific intelligence data';
      }
      
      return reasoning;
    } catch (error) {
      console.error('Error analyzing tool selection:', error);
      return {
        toolName: 'Unknown Tool',
        rationale: 'Error analyzing tool selection',
        expectedOutcome: 'Unknown',
        complexity: 'medium'
      };
    }
  }

  analyzeToolOutput(output) {
    try {
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
    } catch (error) {
      console.error('Error analyzing tool output:', error);
      return [];
    }
  }

  extractAgentReasoning(action) {
    try {
      if (!action || !action.log) return 'No reasoning available';
      
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
    } catch (error) {
      console.error('Error extracting agent reasoning:', error);
      return 'Error extracting reasoning';
    }
  }

  extractThoughtInsights() {
    try {
      return {
        toolSelectionCount: this.toolSelectionReasoning.length,
        reasoningPatterns: this.toolSelectionReasoning.map(r => r.type),
        complexity: this.currentThought.length > 500 ? 'high' : 'medium'
      };
    } catch (error) {
      console.error('Error extracting thought insights:', error);
      return {
        toolSelectionCount: 0,
        reasoningPatterns: [],
        complexity: 'medium'
      };
    }
  }

  // Additional handlers to match the interface
  async handleChainStart(chain) {
    try {
      this.safelyEmitEvent({
        type: 'chain_start',
        phase: 'chain_execution'
      });
    } catch (error) {
      console.error('Error in handleChainStart:', error);
    }
  }
  
  async handleChainEnd(outputs) {
    try {
      this.safelyEmitEvent({
        type: 'chain_end',
        phase: 'chain_complete'
      });
    } catch (error) {
      console.error('Error in handleChainEnd:', error);
    }
  }
  
  async handleChainError(error) {
    try {
      this.safelyEmitEvent({
        type: 'chain_error',
        error: error?.message || 'Chain execution error',
        phase: 'error'
      });
    } catch (err) {
      console.error('Error in handleChainError:', err);
    }
  }
  
  async handleToolError(error) {
    try {
      this.safelyEmitEvent({
        type: 'tool_error',
        error: error?.message || 'Tool execution error',
        phase: 'error'
      });
    } catch (err) {
      console.error('Error in handleToolError:', err);
    }
  }
  
  async handleText(text) {
    try {
      if (text && typeof text === 'string') {
        this.safelyEmitEvent({
          type: 'text',
          content: text,
          phase: 'text_processing'
        });
      }
    } catch (error) {
      console.error('Error in handleText:', error);
    }
  }
  
  async handleLLMError(error) {
    try {
      this.safelyEmitEvent({
        type: 'llm_error',
        error: error?.message || 'LLM processing error',
        phase: 'error'
      });
    } catch (err) {
      console.error('Error in handleLLMError:', err);
    }
  }
}

module.exports = {
  EnhancedWebSocketCallbackHandler
}; 