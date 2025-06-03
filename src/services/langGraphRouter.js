// LangGraph-based Response Router for Intelligent Conversation Management
// Replaces custom response router with sophisticated state-based workflows

const { StateGraph, END, START } = require('@langchain/langgraph');
const { MemorySaver } = require('@langchain/langgraph');
const { HumanMessage, AIMessage } = require('@langchain/core/messages');
const { securityIntelligence } = require('./securityIntelligenceEngine');

// Define the conversation state schema
class ConversationState {
  constructor() {
    this.messages = [];
    this.currentPhase = 'discovery';
    this.scanResults = null;
    this.previousFindings = [];
    this.questionType = null;
    this.repetitionCount = 0;
    this.lastResponse = null;
    this.targetInfo = null;
    this.sessionContext = {};
  }
}

class LangGraphRouter {
  constructor() {
    this.memory = new MemorySaver();
    this.graph = this.buildWorkflowGraph();
    this.app = this.graph.compile({ checkpointer: this.memory });
    
    // Question classification patterns
    this.questionPatterns = {
      nextSteps: {
        patterns: [
          /what.*next/i,
          /what.*should.*do.*next/i,
          /what.*other.*scan/i,
          /what.*else.*can.*do/i,
          /next.*step/i,
          /after.*this/i,
          /then.*what/i,
          /what.*more/i,
          /additional.*scan/i,
          /further.*analysis/i,
          /what.*recommend/i,
          /what.*suggest/i,
          /guidance/i,
          /advice/i
        ],
        priority: 'high'
      },
      firstScan: {
        patterns: [
          /first.*scan/i,
          /start.*scanning/i,
          /begin.*scan/i,
          /initial.*scan/i,
          /where.*start/i,
          /how.*begin/i,
          /how.*scan/i,
          /scan.*\w+\.(com|org|net|edu)/i, // Domain scanning
          /scan.*\d+\.\d+\.\d+\.\d+/i      // IP scanning
        ],
        priority: 'medium'
      },
      moreInfo: {
        patterns: [
          /tell.*more/i,
          /more.*info/i,
          /additional.*detail/i,
          /explain.*further/i,
          /elaborate/i,
          /what.*mean/i,
          /details/i,
          /breakdown/i,
          /analyze.*these/i,
          /about.*these.*results/i
        ],
        priority: 'medium'
      },
      specificScan: {
        patterns: [
          /service.*scan/i,
          /vulnerability.*scan/i,
          /os.*detection/i,
          /comprehensive.*scan/i,
          /quick.*scan/i,
          /port.*scan/i,
          /how.*run.*scan/i,
          /what.*type.*scan/i,
          /scan.*type/i,
          /nmap/i
        ],
        priority: 'high'
      },
      toolRecommendation: {
        patterns: [
          /what.*tool/i,
          /which.*tool/i,
          /recommend.*tool/i,
          /suggest.*tool/i,
          /what.*use.*for/i,
          /what.*scan.*perform/i,
          /what.*do.*next/i,
          /based.*tools.*have/i,
          /tools.*recommend/i,
          /using.*for.*scan/i
        ],
        priority: 'high'
      },
      securityAnalysis: {
        patterns: [
          /security.*analysis/i,
          /vulnerability.*assessment/i,
          /risk.*analysis/i,
          /threat.*assessment/i,
          /security.*posture/i,
          /analyze.*security/i,
          /security.*of/i,
          /comprehensive.*analysis/i,
          /provide.*analysis/i
        ],
        priority: 'high'
      },
      generalQuestion: {
        patterns: [
          /what.*can.*you.*do/i,
          /help/i,
          /capabilities/i,
          /features/i,
          /how.*work/i,
          /explain/i,
          /what.*is/i,
          /how.*to/i
        ],
        priority: 'low'
      }
    };
  }

  // Build the LangGraph workflow
  buildWorkflowGraph() {
    const workflow = new StateGraph({
      channels: {
        messages: {
          reducer: (x, y) => x.concat(y),
          default: () => []
        },
        currentPhase: {
          reducer: (x, y) => y ?? x,
          default: () => 'discovery'
        },
        scanResults: {
          reducer: (x, y) => y ?? x,
          default: () => null
        },
        previousFindings: {
          reducer: (x, y) => [...(x || []), ...(y || [])],
          default: () => []
        },
        questionType: {
          reducer: (x, y) => y ?? x,
          default: () => null
        },
        repetitionCount: {
          reducer: (x, y) => y ?? x,
          default: () => 0
        },
        lastResponse: {
          reducer: (x, y) => y ?? x,
          default: () => null
        },
        targetInfo: {
          reducer: (x, y) => ({ ...(x || {}), ...(y || {}) }),
          default: () => ({})
        },
        sessionContext: {
          reducer: (x, y) => ({ ...(x || {}), ...(y || {}) }),
          default: () => ({})
        },
        analysisResult: {
          reducer: (x, y) => y ?? x,
          default: () => null
        }
      }
    });

    // Add nodes to the workflow
    workflow.addNode('analyze_input', this.analyzeInput.bind(this));
    workflow.addNode('detect_repetition', this.detectRepetition.bind(this));
    workflow.addNode('classify_question', this.classifyQuestion.bind(this));
    workflow.addNode('route_to_handler', this.routeToHandler.bind(this));
    workflow.addNode('handle_next_steps', this.handleNextSteps.bind(this));
    workflow.addNode('handle_first_scan', this.handleFirstScan.bind(this));
    workflow.addNode('handle_more_info', this.handleMoreInfo.bind(this));
    workflow.addNode('handle_specific_scan', this.handleSpecificScan.bind(this));
    workflow.addNode('handle_tool_recommendation', this.handleToolRecommendation.bind(this));
    workflow.addNode('handle_security_analysis', this.handleSecurityAnalysis.bind(this));
    workflow.addNode('handle_general_question', this.handleGeneralQuestion.bind(this));
    workflow.addNode('generate_advanced_response', this.generateAdvancedResponse.bind(this));
    workflow.addNode('update_context', this.updateContext.bind(this));

    // Define the workflow edges and conditional routing
    workflow.addEdge(START, 'analyze_input');
    workflow.addEdge('analyze_input', 'detect_repetition');
    
    // Conditional routing based on repetition detection
    workflow.addConditionalEdges(
      'detect_repetition',
      this.shouldGenerateAdvancedResponse.bind(this),
      {
        'advanced': 'generate_advanced_response',
        'normal': 'classify_question'
      }
    );

    workflow.addEdge('classify_question', 'route_to_handler');
    
    // Conditional routing to specific handlers
    workflow.addConditionalEdges(
      'route_to_handler',
      this.routeToSpecificHandler.bind(this),
      {
        'nextSteps': 'handle_next_steps',
        'firstScan': 'handle_first_scan',
        'moreInfo': 'handle_more_info',
        'specificScan': 'handle_specific_scan',
        'toolRecommendation': 'handle_tool_recommendation',
        'securityAnalysis': 'handle_security_analysis',
        'generalQuestion': 'handle_general_question',
        'default': 'generate_advanced_response'
      }
    );

    // All handlers lead to context update
    workflow.addEdge('handle_next_steps', 'update_context');
    workflow.addEdge('handle_first_scan', 'update_context');
    workflow.addEdge('handle_more_info', 'update_context');
    workflow.addEdge('handle_specific_scan', 'update_context');
    workflow.addEdge('handle_tool_recommendation', 'update_context');
    workflow.addEdge('handle_security_analysis', 'update_context');
    workflow.addEdge('handle_general_question', 'update_context');
    workflow.addEdge('generate_advanced_response', 'update_context');
    workflow.addEdge('update_context', END);

    return workflow;
  }

  // Main entry point for routing responses
  async routeResponse(command, scanResults, conversationHistory, sessionId) {
    try {
      // Prepare initial state
      const initialState = {
        messages: [new HumanMessage(command)],
        scanResults: scanResults,
        sessionContext: { sessionId, timestamp: new Date().toISOString() }
      };

      // Add conversation history to state
      if (conversationHistory && conversationHistory.length > 0) {
        const historyMessages = conversationHistory.map(turn => [
          new HumanMessage(turn.userMessage || turn.content),
          new AIMessage(turn.assistantResponse || turn.content)
        ]).flat();
        initialState.messages = [...historyMessages, ...initialState.messages];
      }

      // Execute the workflow
      const config = { 
        configurable: { thread_id: sessionId },
        recursionLimit: 10
      };

      const result = await this.app.invoke(initialState, config);
      
      // Extract the final response
      const lastMessage = result.messages[result.messages.length - 1];
      return lastMessage.content || 'I apologize, but I encountered an issue generating a response. Please try again.';

    } catch (error) {
      console.error('Error in LangGraph router:', error);
      return 'I encountered an error while processing your request. Please try again.';
    }
  }

  // Node: Analyze input and extract key information
  async analyzeInput(state) {
    const lastMessage = state.messages[state.messages.length - 1];
    const command = lastMessage.content;

    // Extract target information
    const targetInfo = this.extractTargetInfo(command);
    
    // Analyze scan results if available
    let analysis = null;
    if (state.scanResults) {
      analysis = securityIntelligence.analyzeScanResults(state.scanResults, targetInfo.target);
    }

    return {
      targetInfo,
      currentPhase: analysis ? securityIntelligence.determineCurrentPhase(analysis) : 'discovery',
      previousFindings: analysis ? analysis.attackSurface : [],
      analysisResult: analysis
    };
  }

  // Node: Detect if this is a repetitive question
  async detectRepetition(state) {
    const currentMessage = state.messages[state.messages.length - 1].content.toLowerCase();
    const recentMessages = state.messages
      .slice(-6) // Look at last 6 messages
      .filter(msg => msg.constructor.name === 'HumanMessage')
      .map(msg => msg.content.toLowerCase());

    let repetitionCount = 0;
    for (const msg of recentMessages.slice(0, -1)) { // Exclude current message
      if (this.calculateSimilarity(msg, currentMessage) > 0.7) {
        repetitionCount++;
      }
    }

    return { repetitionCount };
  }

  // Node: Classify the type of question
  async classifyQuestion(state) {
    const lastMessage = state.messages[state.messages.length - 1];
    const command = lastMessage.content.toLowerCase();

    let questionType = 'default';
    let maxPriority = 0;

    for (const [type, config] of Object.entries(this.questionPatterns)) {
      if (config.patterns.some(pattern => pattern.test(command))) {
        const priority = config.priority === 'high' ? 3 : config.priority === 'medium' ? 2 : 1;
        if (priority > maxPriority) {
          questionType = type;
          maxPriority = priority;
        }
      }
    }

    return { questionType };
  }

  // Node: Route to appropriate handler
  async routeToHandler(state) {
    // This node doesn't modify state, just used for routing
    return {};
  }

  // Node: Handle next steps questions
  async handleNextSteps(state) {
    const analysis = state.analysisResult || 
                     (state.scanResults && state.targetInfo && state.targetInfo.target ? 
                      securityIntelligence.analyzeScanResults(state.scanResults, state.targetInfo.target) : null);

    if (!analysis) {
      const response = new AIMessage(`I'd be happy to suggest next steps! However, I need to know what you've discovered so far. Could you share:

• What target you're analyzing
• What scans you've already performed
• Any specific findings you'd like to build upon

This will help me provide targeted recommendations for your next steps.`);
      
      return { messages: [response] };
    }

    const nextSteps = analysis.nextSteps.slice(0, 3);
    let response = `Based on your current findings, here are the strategic next steps I recommend:\n\n`;

    nextSteps.forEach((step, index) => {
      response += `**${index + 1}. ${step.action}**\n`;
      response += `• Command: \`${step.command || 'See details below'}\`\n`;
      response += `• Priority: ${step.priority.toUpperCase()}\n`;
      response += `• Rationale: ${step.rationale}\n\n`;
    });

    response += `💡 **Methodology Note**: These recommendations follow the ${state.currentPhase} phase of security assessment. Each step builds upon your previous discoveries to create a comprehensive security picture.`;

    return { messages: [new AIMessage(response)] };
  }

  // Node: Handle first scan questions
  async handleFirstScan(state) {
    const target = state.targetInfo?.target || 'your target';
    
    const response = `Great question! Here's how I recommend starting your security assessment of ${target}:

**🎯 Phase 1: Initial Discovery**

**1. Quick Port Scan**
• Command: \`nmap -T4 -F ${target}\`
• Purpose: Rapidly identify the most common open ports
• Time: ~30 seconds
• Why start here: Gets you immediate visibility into active services

**2. Service Detection**
• Command: \`nmap -sV -T4 ${target}\`
• Purpose: Identify specific service versions
• Time: 1-2 minutes
• Why: Version information reveals potential vulnerabilities

**3. Basic OS Detection**
• Command: \`nmap -O ${target}\`
• Purpose: Identify the operating system
• Time: ~1 minute
• Why: OS knowledge guides further attack vectors

**🔍 What to Look For:**
• Web services (ports 80, 443, 8080)
• Remote access (SSH on 22, RDP on 3389)
• Database services (MySQL 3306, PostgreSQL 5432)
• File sharing (SMB 445, FTP 21)

**⚡ Quick Start Command:**
\`nmap -T4 -F -sV ${target}\`

This combines speed with service detection for immediate actionable intelligence. Would you like me to explain any of these commands in more detail?`;

    return { messages: [new AIMessage(response)] };
  }

  // Node: Handle more info questions
  async handleMoreInfo(state) {
    const analysis = state.analysisResult || 
                     (state.scanResults && state.targetInfo && state.targetInfo.target ? 
                      securityIntelligence.analyzeScanResults(state.scanResults, state.targetInfo.target) : null);

    if (!analysis) {
      const response = `I'd be happy to provide more detailed information! What specific aspect would you like me to elaborate on?

**Available Topics:**
• **Scanning Techniques** - Different types of scans and when to use them
• **Security Assessment Methodology** - Step-by-step approach to security testing
• **Port Analysis** - What different open ports mean for security
• **Vulnerability Assessment** - How to identify and prioritize security issues
• **OSINT Techniques** - Gathering intelligence without direct scanning

Just let me know which topic interests you, or ask about something specific!`;
      
      return { messages: [new AIMessage(response)] };
    }

    // Provide detailed analysis of current findings
    let response = `Here's a detailed breakdown of your current findings:\n\n`;

    // Add detailed port analysis
    if (analysis.attackSurface.length > 0) {
      response += `**🔍 Detailed Port Analysis:**\n\n`;
      
      analysis.attackSurface.forEach(port => {
        const intel = securityIntelligence.portIntelligence[port.port];
        if (intel) {
          response += `**Port ${port.port} - ${intel.service}**\n`;
          response += `• Risk Level: ${intel.risk.toUpperCase()}\n`;
          response += `• Security Implications: ${intel.implications}\n`;
          response += `• Common Attack Vectors: ${this.getAttackVectors(intel.service)}\n`;
          response += `• Recommended Actions: ${this.getRecommendedActions(intel.service)}\n\n`;
        }
      });
    }

    // Add security posture details
    if (analysis.securityPosture) {
      response += `**🛡️ Security Posture Analysis:**\n`;
      response += `• Overall Rating: ${analysis.securityPosture.overallRating}\n`;
      response += `• Security Score: ${analysis.securityPosture.score}/100\n`;
      
      if (analysis.securityPosture.strengths.length > 0) {
        response += `• Strengths: ${analysis.securityPosture.strengths.join(', ')}\n`;
      }
      
      if (analysis.securityPosture.weaknesses.length > 0) {
        response += `• Areas for Improvement: ${analysis.securityPosture.weaknesses.join(', ')}\n`;
      }
    }

    return { messages: [new AIMessage(response)] };
  }

  // Node: Handle specific scan questions
  async handleSpecificScan(state) {
    const lastMessage = state.messages[state.messages.length - 1];
    const command = lastMessage.content.toLowerCase();
    const target = state.targetInfo?.target || '[target]';

    let response = '';

    if (command.includes('service') || command.includes('version')) {
      response = `**🔍 Service Version Detection Scan**

This scan identifies specific software versions running on open ports:

**Command:** \`nmap -sV ${target}\`

**What it does:**
• Probes open ports to determine service/version info
• Uses service fingerprinting techniques
• Identifies software versions that may have known vulnerabilities

**Expected Results:**
• Exact service versions (e.g., "Apache httpd 2.4.41")
• Operating system details
• Service-specific information

**Security Value:**
• Enables vulnerability research for specific versions
• Identifies outdated software requiring updates
• Reveals service configurations

**Time Required:** 2-5 minutes depending on number of open ports`;

    } else if (command.includes('vulnerability') || command.includes('vuln')) {
      response = `**🛡️ Vulnerability Assessment Scan**

This scan checks for known security vulnerabilities:

**Command:** \`nmap --script vuln ${target}\`

**What it does:**
• Runs Nmap's vulnerability detection scripts
• Checks for common CVEs and security issues
• Tests for misconfigurations

**Expected Results:**
• Known CVE vulnerabilities
• SSL/TLS configuration issues
• Common service vulnerabilities
• Security misconfigurations

**Security Value:**
• Identifies immediate security risks
• Provides CVE numbers for research
• Prioritizes patching efforts

**Time Required:** 5-15 minutes depending on services found`;

    } else if (command.includes('comprehensive') || command.includes('complete')) {
      response = `**🎯 Comprehensive Security Scan**

This performs a thorough security assessment:

**Command:** \`nmap -A -T4 ${target}\`

**What it includes:**
• Service version detection (-sV)
• OS detection (-O)
• Script scanning (-sC)
• Traceroute (--traceroute)

**Expected Results:**
• Complete service inventory
• Operating system identification
• Default script results
• Network path information

**Security Value:**
• Complete attack surface mapping
• Comprehensive vulnerability baseline
• Full infrastructure understanding

**Time Required:** 10-30 minutes for thorough analysis`;

    } else {
      response = `**📋 Available Scan Types:**

**1. Quick Scan** - Fast port discovery
   \`nmap -T4 -F ${target}\`

**2. Service Scan** - Identify service versions
   \`nmap -sV ${target}\`

**3. Vulnerability Scan** - Check for known vulnerabilities
   \`nmap --script vuln ${target}\`

**4. OS Detection** - Identify operating system
   \`nmap -O ${target}\`

**5. Comprehensive Scan** - Complete assessment
   \`nmap -A -T4 ${target}\`

Which specific scan type would you like to learn more about?`;
    }

    return { messages: [new AIMessage(response)] };
  }

  // Node: Handle tool recommendation questions
  async handleToolRecommendation(state) {
    const lastMessage = state.messages[state.messages.length - 1];
    const command = lastMessage.content.toLowerCase();
    const analysis = state.analysisResult;
    
    // Check if we have context from previous scans
    const hasScanResults = state.scanResults !== null;
    const hasAnalysis = analysis !== null;
    
    let response = `**🛠️ Tool Recommendations Based on Current Context**\n\n`;
    
    if (hasAnalysis && analysis.attackSurface.length > 0) {
      // We have scan results, provide specific recommendations
      const hasSSH = analysis.attackSurface.some(p => p.port === 22);
      const hasHTTP = analysis.attackSurface.some(p => p.port === 80);
      const hasHTTPS = analysis.attackSurface.some(p => p.port === 443);
      const hasDatabase = analysis.attackSurface.some(p => [3306, 5432, 27017].includes(p.port));
      
      response += `Based on your scan results, here are my specific tool recommendations:\n\n`;
      
      // Priority 1: Service enumeration if not done
      if (!state.scanResults.includes('-sV')) {
        response += `**1. Service Version Detection** (PRIORITY: HIGH)\n`;
        response += `• Tool: **NmapScanner**\n`;
        response += `• Command: \`${state.targetInfo?.target || 'target'} -sV\`\n`;
        response += `• Purpose: Identify exact service versions to search for specific vulnerabilities\n\n`;
      }
      
      // Priority 2: Exploit search for discovered services
      if (hasSSH || hasHTTP || hasHTTPS) {
        response += `**2. Exploit Intelligence Gathering** (PRIORITY: HIGH)\n`;
        response += `• Tool: **MetasploitExploitSearch**\n`;
        
        if (hasSSH) {
          response += `• For SSH (port 22): Search for "ssh" or "openssh"\n`;
        }
        if (hasHTTP || hasHTTPS) {
          response += `• For Web services: Search for "http", "apache", "nginx", or specific version\n`;
        }
        response += `• Purpose: Identify known vulnerabilities in discovered services\n\n`;
      }
      
      // Priority 3: Vulnerability assessment
      response += `**3. Vulnerability Assessment** (PRIORITY: MEDIUM)\n`;
      response += `• Tool: **VulnerabilityAssessment**\n`;
      response += `• Command: \`${state.targetInfo?.target || 'target'}\`\n`;
      response += `• Purpose: Automated scan + exploit correlation for comprehensive analysis\n\n`;
      
      // Priority 4: Auxiliary modules for specific services
      if (hasSSH || hasDatabase) {
        response += `**4. Service-Specific Enumeration** (PRIORITY: MEDIUM)\n`;
        response += `• Tool: **MetasploitAuxiliary**\n`;
        
        if (hasSSH) {
          response += `• SSH enumeration: "auxiliary/scanner/ssh/ssh_version"\n`;
        }
        if (hasDatabase) {
          response += `• Database enumeration: "auxiliary/scanner/mysql/mysql_version"\n`;
        }
        response += `• Purpose: Gather detailed service configuration information\n\n`;
      }
      
    } else {
      // No scan results yet, provide general guidance
      response += `I notice you haven't performed any scans yet. Here's my recommended approach:\n\n`;
      
      response += `**1. Initial Port Discovery** (START HERE)\n`;
      response += `• Tool: **NmapScanner**\n`;
      response += `• Command: \`target -T4 -F\` (fast scan of common ports)\n`;
      response += `• Purpose: Quickly identify open ports and services\n\n`;
      
      response += `**2. Service Enumeration** (AFTER PORT DISCOVERY)\n`;
      response += `• Tool: **NmapScanner**\n`;
      response += `• Command: \`target -sV\` (service version detection)\n`;
      response += `• Purpose: Identify specific service versions\n\n`;
      
      response += `**3. Vulnerability Research** (AFTER SERVICE ENUM)\n`;
      response += `• Tool: **MetasploitExploitSearch**\n`;
      response += `• Usage: Search for exploits based on discovered services\n`;
      response += `• Purpose: Find known vulnerabilities\n\n`;
      
      response += `**4. Comprehensive Assessment** (AUTOMATED)\n`;
      response += `• Tool: **VulnerabilityAssessment**\n`;
      response += `• Usage: Combines scanning with exploit search\n`;
      response += `• Purpose: Get complete vulnerability picture\n\n`;
    }
    
    response += `💡 **Pro Tip**: Start with basic scanning, then progressively gather more detailed information. `;
    response += `Each tool builds upon the previous findings to create a comprehensive security assessment.`;
    
    return { messages: [new AIMessage(response)] };
  }

  // Node: Handle security analysis questions
  async handleSecurityAnalysis(state) {
    const analysis = state.analysisResult || 
                     (state.scanResults && state.targetInfo && state.targetInfo.target ? 
                      securityIntelligence.analyzeScanResults(state.scanResults, state.targetInfo.target) : null);

    if (!analysis) {
      const response = `**🛡️ Security Analysis Framework**

I can provide comprehensive security analysis once you have scan data. Here's what I analyze:

**1. Attack Surface Assessment**
• Open ports and services
• Service version vulnerabilities
• Configuration weaknesses

**2. Risk Prioritization**
• Critical vs. low-risk findings
• Exploitability assessment
• Business impact evaluation

**3. Threat Modeling**
• Potential attack vectors
• Lateral movement opportunities
• Data exposure risks

**4. Remediation Roadmap**
• Immediate actions required
• Long-term security improvements
• Compliance considerations

To get started, please run a scan and I'll provide detailed security analysis of the results!`;
      
      return { messages: [new AIMessage(response)] };
    }

    // Provide comprehensive security analysis
    let response = `**🛡️ Comprehensive Security Analysis**\n\n`;

    // Risk assessment
    response += `**Risk Assessment:**\n`;
    response += `• Overall Risk Level: ${analysis.riskLevel.toUpperCase()}\n`;
    response += `• Critical Findings: ${analysis.criticalFindings.length}\n`;
    response += `• Security Score: ${analysis.securityPosture.score}/100\n\n`;

    // Attack surface analysis
    if (analysis.attackSurface.length > 0) {
      response += `**Attack Surface Analysis:**\n`;
      const highRiskPorts = analysis.attackSurface.filter(port => {
        const intel = securityIntelligence.portIntelligence[port.port];
        return intel && (intel.risk === 'high' || intel.risk === 'critical');
      });

      if (highRiskPorts.length > 0) {
        response += `⚠️ **High-Risk Services:**\n`;
        highRiskPorts.forEach(port => {
          const intel = securityIntelligence.portIntelligence[port.port];
          response += `• Port ${port.port} (${intel.service}): ${intel.implications}\n`;
        });
        response += '\n';
      }
    }

    // Strategic recommendations
    if (analysis.nextSteps.length > 0) {
      response += `**Strategic Security Recommendations:**\n\n`;
      analysis.nextSteps.slice(0, 3).forEach((step, index) => {
        response += `**${index + 1}. ${step.action}**\n`;
        response += `• Priority: ${step.priority.toUpperCase()}\n`;
        response += `• Security Impact: ${this.getSecurityImpact(step.action)}\n`;
        response += `• Implementation: ${step.rationale}\n\n`;
      });
    }

    return { messages: [new AIMessage(response)] };
  }

  // Node: Handle general questions
  async handleGeneralQuestion(state) {
    const lastMessage = state.messages[state.messages.length - 1];
    const command = lastMessage.content.toLowerCase();

    let response = '';

    if (command.includes('help') || command.includes('what can you do')) {
      response = `**🤖 NetViz AI Agent - Your Cybersecurity Assistant**

I'm here to help you with network security analysis and reconnaissance. Here's what I can do:

**🔍 Network Scanning & Analysis:**
• Port scanning with Nmap
• Service version detection
• Vulnerability assessment
• OS fingerprinting

**🕵️ OSINT (Open Source Intelligence):**
• Domain registration lookup (WHOIS)
• DNS reconnaissance
• Subdomain enumeration
• Typosquatting detection

**🛡️ Security Assessment:**
• Risk analysis and scoring
• Attack surface mapping
• Security posture evaluation
• Strategic recommendations

**💬 Interactive Guidance:**
• Step-by-step methodology guidance
• Scan result interpretation
• Next steps recommendations
• Security best practices

**Example Commands:**
• "scan google.com for open ports"
• "analyze the security of example.com"
• "what should I scan next?"
• "explain these scan results"

What would you like to explore today?`;

    } else if (command.includes('how') && command.includes('work')) {
      response = `**🔧 How NetViz AI Agent Works**

**Architecture:**
• Frontend: React-based interface for user interaction
• Backend: Node.js server with AI agent orchestration
• AI Engine: Claude (Anthropic) for intelligent analysis
• Tools: Nmap, OSINT tools, security intelligence engines

**Workflow:**
1. **Input Analysis** - I analyze your request and determine intent
2. **Tool Selection** - Choose appropriate tools (Nmap, WHOIS, etc.)
3. **Execution** - Run scans and gather intelligence
4. **Analysis** - Apply security expertise to interpret results
5. **Guidance** - Provide strategic recommendations and next steps

**Safety Features:**
• Restricted to authorized targets only
• Educational and bug bounty scope limitations
• Built-in rate limiting and security controls

**Intelligence Layer:**
• Real-time correlation with vulnerability databases
• Risk scoring and threat assessment
• Strategic methodology guidance
• Continuous learning from interactions

The goal is to make cybersecurity analysis accessible while maintaining ethical guidelines!`;

    } else if (command.includes('capabilities') || command.includes('features')) {
      response = `**⚡ Core Capabilities**

**🎯 Network Reconnaissance:**
• Quick port discovery scans
• Comprehensive service enumeration
• Operating system detection
• Banner grabbing and fingerprinting

**🔍 Intelligence Gathering:**
• Domain ownership research
• DNS infrastructure mapping
• Certificate analysis
• Subdomain discovery

**🛡️ Security Analysis:**
• Vulnerability correlation
• Risk assessment and scoring
• Attack vector identification
• Security posture evaluation

**📊 Reporting & Visualization:**
• Structured scan result presentation
• Risk-based finding prioritization
• Strategic recommendation generation
• Methodology guidance

**🔄 Workflow Automation:**
• Multi-stage assessment orchestration
• Intelligent tool selection
• Context-aware follow-up suggestions
• Session persistence and memory

**🎓 Educational Features:**
• Command explanation and rationale
• Security concept education
• Best practice recommendations
• Methodology teaching

What specific capability would you like to learn more about?`;

    } else {
      response = `I'd be happy to help! I can assist with:

• **Network scanning** - "scan example.com"
• **Security analysis** - "analyze security of target.com" 
• **OSINT research** - "lookup domain information for example.com"
• **Guidance** - "what should I scan next?"
• **Education** - "explain vulnerability scanning"

What specific question do you have? Feel free to be as detailed as you'd like!`;
    }

    return { messages: [new AIMessage(response)] };
  }

  // Node: Generate advanced response for repetitive questions
  async generateAdvancedResponse(state) {
    const analysis = state.analysisResult || 
                     (state.scanResults && state.targetInfo && state.targetInfo.target ? 
                      securityIntelligence.analyzeScanResults(state.scanResults, state.targetInfo.target) : null);

    if (!analysis) {
      const response = `I notice you're looking for more detailed guidance. Let me provide some advanced insights:

**🎯 Advanced Security Assessment Strategies:**

**1. Layered Reconnaissance Approach**
• Start with passive OSINT gathering
• Progress to active scanning
• Combine multiple data sources

**2. Threat-Centric Analysis**
• Focus on high-value targets first
• Consider attacker motivations
• Map to MITRE ATT&CK framework

**3. Continuous Monitoring**
• Establish baseline security posture
• Monitor for changes over time
• Implement automated alerting

**4. Risk-Based Prioritization**
• Assess business impact
• Consider exploitability
• Factor in threat landscape

Would you like me to elaborate on any of these advanced concepts?`;
      
      return { messages: [new AIMessage(response)] };
    }

    // Generate advanced analysis based on current findings
    const phase = securityIntelligence.determineCurrentPhase(analysis);
    
    let response = `**🔬 Advanced Security Analysis**\n\n`;
    response += `I notice you're seeking deeper insights. Let me provide advanced analysis based on your ${phase} phase findings:\n\n`;

    // Phase-specific advanced insights
    switch (phase) {
      case 'discovery':
        response += `**Advanced Discovery Insights:**\n\n`;
        response += `**Service Correlation Analysis:**\n`;
        analysis.attackSurface.forEach(port => {
          const intel = securityIntelligence.portIntelligence[port.port];
          if (intel) {
            response += `• Port ${port.port}: ${this.getAdvancedPortAnalysis(port, intel)}\n`;
          }
        });
        
        response += `\n**Infrastructure Fingerprinting:**\n`;
        response += `• System Type: ${this.identifySystemType(analysis.attackSurface)}\n`;
        response += `• Likely Purpose: ${this.inferSystemPurpose(analysis.attackSurface)}\n`;
        response += `• Security Posture: ${this.assessInitialPosture(analysis.attackSurface)}\n`;
        break;

      case 'enumeration':
        response += `**Advanced Enumeration Insights:**\n\n`;
        response += `**Version Analysis & Threat Intelligence:**\n`;
        // Add version-specific threat intelligence
        response += `**Attack Vector Mapping:**\n`;
        // Map potential attack paths
        response += `**Privilege Escalation Opportunities:**\n`;
        // Identify potential privilege escalation paths
        break;
    }

    return { messages: [new AIMessage(response)] };
  }

  // Node: Update conversation context
  async updateContext(state) {
    const timestamp = new Date().toISOString();
    const sessionContext = {
      ...state.sessionContext,
      lastUpdate: timestamp,
      messageCount: state.messages.length,
      currentPhase: state.currentPhase
    };

    return { sessionContext };
  }

  // Conditional routing functions
  shouldGenerateAdvancedResponse(state) {
    return state.repetitionCount > 1 ? 'advanced' : 'normal';
  }

  routeToSpecificHandler(state) {
    const route = state.questionType || 'default';
    
    // Improved default routing logic
    if (route === 'default') {
      // If we have scan results, route to moreInfo for analysis
      if (state.scanResults) {
        return 'moreInfo';
      }
      // If no scan results, provide general guidance
      return 'nextSteps';
    }
    return route;
  }

  // Helper functions
  calculateSimilarity(str1, str2) {
    // Improved similarity calculation with semantic patterns
    const normalize = (str) => str.toLowerCase().replace(/[^\w\s]/g, '').trim();
    const norm1 = normalize(str1);
    const norm2 = normalize(str2);
    
    // Exact match
    if (norm1 === norm2) return 1.0;
    
    // Check for semantic similarity patterns
    const nextStepPatterns = [/what.*next/i, /what.*should.*do/i, /then.*what/i, /after.*this/i];
    const isNextStep1 = nextStepPatterns.some(p => p.test(norm1));
    const isNextStep2 = nextStepPatterns.some(p => p.test(norm2));
    if (isNextStep1 && isNextStep2) return 0.9;
    
    const moreInfoPatterns = [/tell.*more/i, /more.*info/i, /explain.*further/i, /elaborate/i];
    const isMoreInfo1 = moreInfoPatterns.some(p => p.test(norm1));
    const isMoreInfo2 = moreInfoPatterns.some(p => p.test(norm2));
    if (isMoreInfo1 && isMoreInfo2) return 0.9;
    
    // Word overlap similarity (improved)
    const words1 = norm1.split(/\s+/).filter(w => w.length > 2); // Filter out short words
    const words2 = norm2.split(/\s+/).filter(w => w.length > 2);
    
    if (words1.length === 0 || words2.length === 0) return 0;
    
    const commonWords = words1.filter(word => words2.includes(word));
    const similarity = commonWords.length / Math.max(words1.length, words2.length);
    
    // Boost similarity for key question words
    const keyWords = ['what', 'how', 'should', 'next', 'scan', 'analyze', 'more'];
    const hasKeyWords = commonWords.some(word => keyWords.includes(word));
    
    return hasKeyWords ? Math.min(similarity + 0.2, 1.0) : similarity;
  }

  extractTargetInfo(command) {
    const domainRegex = /(?:[a-zA-Z0-9](?:[a-zA-Z0-9-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}/g;
    const ipRegex = /(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)/g;
    
    const domains = command.match(domainRegex) || [];
    const ips = command.match(ipRegex) || [];
    
    return {
      target: domains[0] || ips[0] || null,
      domains,
      ips
    };
  }

  getAttackVectors(service) {
    const vectors = {
      'HTTP': 'Web application attacks, XSS, SQL injection',
      'HTTPS': 'SSL/TLS attacks, certificate issues',
      'SSH': 'Brute force, key-based attacks',
      'FTP': 'Credential theft, anonymous access',
      'SMB': 'Lateral movement, ransomware',
      'RDP': 'Brute force, credential stuffing'
    };
    return vectors[service] || 'Service-specific vulnerabilities';
  }

  getRecommendedActions(service) {
    const actions = {
      'HTTP': 'Implement HTTPS, secure headers',
      'HTTPS': 'Check SSL configuration, update certificates',
      'SSH': 'Use key authentication, disable root login',
      'FTP': 'Replace with SFTP, restrict access',
      'SMB': 'Restrict to internal networks, update protocols',
      'RDP': 'Use VPN, implement account lockout'
    };
    return actions[service] || 'Follow security best practices';
  }

  getSecurityImpact(action) {
    if (action.includes('vulnerability')) return 'High - Reduces exploitable attack surface';
    if (action.includes('service')) return 'Medium - Improves service security';
    if (action.includes('comprehensive')) return 'High - Complete security baseline';
    return 'Medium - Enhances overall security posture';
  }

  getAdvancedPortAnalysis(port, intel) {
    return `${intel.service} service indicates ${this.getServiceImplications(intel.service)}`;
  }

  getServiceImplications(service) {
    const implications = {
      'HTTP': 'web application presence, potential for web-based attacks',
      'HTTPS': 'encrypted web services, check for SSL/TLS vulnerabilities',
      'SSH': 'remote administration capability, secure but check for weak credentials',
      'FTP': 'file transfer capability, high risk due to plaintext transmission',
      'SMB': 'file sharing services, common target for lateral movement'
    };
    return implications[service] || 'specialized service requiring further analysis';
  }

  identifySystemType(attackSurface) {
    const ports = attackSurface.map(p => p.port);
    
    if (ports.includes(80) || ports.includes(443)) {
      return 'Web server or web application';
    }
    if (ports.includes(22) && ports.includes(3306)) {
      return 'Database server with SSH access';
    }
    if (ports.includes(445) || ports.includes(139)) {
      return 'Windows file server or domain controller';
    }
    return 'General purpose server or workstation';
  }

  inferSystemPurpose(attackSurface) {
    const ports = attackSurface.map(p => p.port);
    
    if (ports.includes(80) && ports.includes(443)) {
      return 'Public-facing web services';
    }
    if (ports.includes(22) && !ports.includes(80)) {
      return 'Administrative or backend server';
    }
    if (ports.includes(3389)) {
      return 'Remote desktop server or workstation';
    }
    return 'Multi-purpose server or infrastructure component';
  }

  assessInitialPosture(attackSurface) {
    const highRiskPorts = [21, 23, 135, 139, 445];
    const hasHighRisk = attackSurface.some(p => highRiskPorts.includes(p.port));
    
    if (hasHighRisk) {
      return 'Potentially vulnerable - high-risk services detected';
    }
    if (attackSurface.length > 10) {
      return 'Large attack surface - requires comprehensive assessment';
    }
    return 'Moderate risk - standard service configuration';
  }
}

// Export the router instance
const langGraphRouter = new LangGraphRouter();
module.exports = { langGraphRouter }; 