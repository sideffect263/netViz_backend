// Response Router for Intelligent Response Generation
// Prevents repetitive responses and provides context-aware routing

const { securityIntelligence } = require('./securityIntelligenceEngine');

class ResponseRouter {
  constructor() {
    // Response patterns to detect and avoid
    this.repetitivePatterns = [
      /The scan results show that the target.*has.*open port/i,
      /This provides an initial understanding/i,
      /To gather more information.*would recommend/i
    ];

    // Question patterns that require specific handling
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
          /further.*analysis/i
        ],
        handler: 'handleNextStepsQuestion'
      },
      firstScan: {
        patterns: [
          /first.*scan/i,
          /start.*scanning/i,
          /begin.*scan/i,
          /initial.*scan/i,
          /where.*start/i,
          /how.*begin/i
        ],
        handler: 'handleFirstScanQuestion'
      },
      moreInfo: {
        patterns: [
          /tell.*more/i,
          /more.*info/i,
          /additional.*detail/i,
          /explain.*further/i,
          /elaborate/i,
          /what.*mean/i
        ],
        handler: 'handleMoreInfoQuestion'
      },
      specificScan: {
        patterns: [
          /service.*scan/i,
          /vulnerability.*scan/i,
          /os.*detection/i,
          /comprehensive.*scan/i,
          /quick.*scan/i,
          /port.*scan/i
        ],
        handler: 'handleSpecificScanQuestion'
      }
    };

    // Response cache to track recent responses
    this.responseCache = new Map();
    this.CACHE_TTL = 5 * 60 * 1000; // 5 minutes
  }

  // Main routing function
  async routeResponse(command, scanResults, conversationHistory, sessionId) {
    // Check if this is a repetitive question
    if (this.isRepetitiveQuestion(command, conversationHistory)) {
      return this.generateNonRepetitiveResponse(command, scanResults, conversationHistory);
    }

    // Identify question type
    const questionType = this.identifyQuestionType(command);
    
    // Route to appropriate handler
    if (questionType && this[questionType.handler]) {
      return this[questionType.handler](command, scanResults, conversationHistory);
    }

    // Default to security intelligence analysis
    return securityIntelligence.generateContextAwareResponse(
      scanResults, 
      conversationHistory, 
      command
    );
  }

  // Check if the question is repetitive
  isRepetitiveQuestion(command, conversationHistory) {
    if (conversationHistory.length < 2) return false;

    const recentQuestions = conversationHistory
      .slice(-3)
      .filter(turn => turn.userMessage)
      .map(turn => turn.userMessage.toLowerCase());

    const currentQuestion = command.toLowerCase();
    
    // Check for similar questions
    return recentQuestions.some(q => 
      this.calculateSimilarity(q, currentQuestion) > 0.7
    );
  }

  // Calculate similarity between two strings
  calculateSimilarity(str1, str2) {
    const words1 = str1.split(/\s+/);
    const words2 = str2.split(/\s+/);
    
    const commonWords = words1.filter(word => words2.includes(word));
    const similarity = commonWords.length / Math.max(words1.length, words2.length);
    
    return similarity;
  }

  // Generate non-repetitive response for similar questions
  generateNonRepetitiveResponse(command, scanResults, conversationHistory) {
    const lastResponse = conversationHistory[conversationHistory.length - 1]?.assistantResponse || '';
    
    // Check if last response already covered scan results
    if (this.repetitivePatterns.some(pattern => pattern.test(lastResponse))) {
      // Provide advanced analysis instead of repeating
      return this.generateAdvancedAnalysis(scanResults, conversationHistory);
    }

    // Generate contextual next steps
    return this.generateContextualNextSteps(scanResults, conversationHistory);
  }

  // Generate advanced analysis
  generateAdvancedAnalysis(scanResults, conversationHistory) {
    const analysis = securityIntelligence.analyzeScanResults(scanResults);
    const phase = securityIntelligence.determineCurrentPhase(analysis);
    
    let response = `I notice you're looking for more detailed analysis. Let me provide deeper insights:\n\n`;
    
    // Add phase-specific advanced analysis
    switch (phase) {
      case 'discovery':
        response += `**Advanced Discovery Analysis:**\n`;
        response += `Based on the open ports discovered, here's what each tells us about the target:\n\n`;
        
        analysis.attackSurface.forEach(port => {
          const intel = securityIntelligence.portIntelligence[port.port];
          if (intel) {
            response += `• **Port ${port.port} (${intel.service})**: ${intel.implications}\n`;
            response += `  Risk Level: ${intel.risk.toUpperCase()}\n`;
            response += `  Security Consideration: This service ${this.getSecurityContext(intel.risk)}\n\n`;
          }
        });
        
        response += `\n**Strategic Assessment:**\n`;
        response += `The combination of services suggests this is likely ${this.identifySystemType(analysis.attackSurface)}.\n`;
        response += `Priority should be given to ${this.getPriorityTarget(analysis)}.\n`;
        break;
        
      case 'enumeration':
        response += `**Service Enumeration Insights:**\n`;
        response += `We've identified specific service versions. Here's what this means:\n\n`;
        
        // Add version-specific analysis
        analysis.attackSurface.forEach(port => {
          if (port.service && port.service.includes('/')) {
            response += `• **${port.service}**: ${this.getVersionAnalysis(port.service)}\n`;
          }
        });
        break;
    }
    
    // Add actionable recommendations
    response += `\n**Actionable Next Steps:**\n`;
    const nextSteps = analysis.nextSteps.slice(0, 3);
    nextSteps.forEach((step, index) => {
      response += `${index + 1}. ${step.action}\n`;
      response += `   Priority: ${step.priority.toUpperCase()}\n`;
      response += `   Rationale: ${step.rationale}\n\n`;
    });
    
    return response;
  }

  // Identify question type
  identifyQuestionType(command) {
    const lowerCommand = command.toLowerCase();
    
    for (const [type, config] of Object.entries(this.questionPatterns)) {
      if (config.patterns.some(pattern => pattern.test(lowerCommand))) {
        return { type, handler: config.handler };
      }
    }
    
    return null;
  }

  // Handler for "what's next" questions
  handleNextStepsQuestion(command, scanResults, conversationHistory) {
    const analysis = securityIntelligence.analyzeScanResults(scanResults);
    const previousScans = this.extractPreviousScans(conversationHistory);
    
    let response = `Based on what we've discovered so far, here are the logical next steps in our security assessment:\n\n`;
    
    // Provide contextual recommendations
    if (!previousScans.includes('service_scan') && analysis.attackSurface.length > 0) {
      response += `**1. Service Version Detection** 🔍\n`;
      response += `Command: \`nmap -sV ${this.extractTarget(conversationHistory)}\`\n`;
      response += `Why: We found ${analysis.attackSurface.length} open ports but don't know the exact service versions. `;
      response += `This information is crucial for identifying specific vulnerabilities.\n\n`;
    }
    
    if (!previousScans.includes('os_detection')) {
      response += `**2. Operating System Detection** 💻\n`;
      response += `Command: \`nmap -O ${this.extractTarget(conversationHistory)}\`\n`;
      response += `Why: Knowing the OS helps us understand the overall system architecture and OS-specific vulnerabilities.\n\n`;
    }
    
    if (analysis.attackSurface.some(p => [80, 443, 8080, 8443].includes(p.port))) {
      response += `**3. Web Application Analysis** 🌐\n`;
      response += `Why: Web services are often the most vulnerable attack vector. We should analyze the web technologies and potential vulnerabilities.\n\n`;
    }
    
    if (!previousScans.includes('vulnerability_scan') && analysis.criticalFindings.length > 0) {
      response += `**4. Vulnerability Assessment** ⚠️\n`;
      response += `Command: \`nmap --script vuln ${this.extractTarget(conversationHistory)}\`\n`;
      response += `Why: We've identified ${analysis.criticalFindings.length} high-risk services that need immediate vulnerability assessment.\n\n`;
    }
    
    response += `**Pro Tip:** Following a methodical approach ensures we don't miss critical vulnerabilities. `;
    response += `Each scan builds upon the previous findings to create a comprehensive security picture.`;
    
    return response;
  }

  // Handler for first scan questions
  handleFirstScanQuestion(command, scanResults, conversationHistory) {
    const target = this.extractTargetFromCommand(command) || '44.228.249.3';
    
    let response = `Great! Let's start with a strategic approach to scanning ${target}. Here's what I recommend:\n\n`;
    
    response += `**🚀 Quick Discovery Scan (Recommended First Step)**\n`;
    response += `Command: \`nmap -T4 -F ${target}\`\n`;
    response += `Time: ~30 seconds\n`;
    response += `Purpose: Quickly identify the most common open ports (top 100)\n\n`;
    
    response += `**Why start here?**\n`;
    response += `• Fast results to understand what services are exposed\n`;
    response += `• Low network impact and less likely to trigger IDS\n`;
    response += `• Provides immediate actionable intelligence\n\n`;
    
    response += `**Alternative Approaches:**\n`;
    response += `1. **Comprehensive Scan**: \`nmap -A ${target}\` (includes OS detection, version scanning, scripts)\n`;
    response += `2. **Stealthy Scan**: \`nmap -sS -T2 ${target}\` (slower but less detectable)\n`;
    response += `3. **Full Port Scan**: \`nmap -p- ${target}\` (all 65535 ports, very thorough but slow)\n\n`;
    
    response += `**Best Practice:** Start with the quick scan to get immediate results, then progressively dig deeper based on findings.`;
    
    return response;
  }

  // Handler for "more info" questions
  handleMoreInfoQuestion(command, scanResults, conversationHistory) {
    const lastTopic = this.extractLastTopic(conversationHistory);
    
    if (lastTopic === 'scan_results') {
      return this.generateAdvancedAnalysis(scanResults, conversationHistory);
    }
    
    // Provide educational content about the current context
    let response = `Let me provide more detailed information about what we're seeing:\n\n`;
    
    const analysis = securityIntelligence.analyzeScanResults(scanResults);
    
    response += `**Understanding the Results:**\n`;
    response += `• **Open Ports**: These are network endpoints accepting connections\n`;
    response += `• **Services**: Applications listening on these ports\n`;
    response += `• **Risk Assessment**: Based on service type and configuration\n\n`;
    
    response += `**Security Implications:**\n`;
    analysis.attackSurface.forEach(port => {
      const intel = securityIntelligence.portIntelligence[port.port];
      if (intel) {
        response += `\n**${intel.service} (Port ${port.port})**:\n`;
        response += `• Purpose: ${this.getServicePurpose(intel.service)}\n`;
        response += `• Common Attacks: ${this.getCommonAttacks(intel.service)}\n`;
        response += `• Best Practices: ${this.getBestPractices(intel.service)}\n`;
      }
    });
    
    return response;
  }

  // Handler for specific scan type questions
  handleSpecificScanQuestion(command, scanResults, conversationHistory) {
    const scanType = this.extractScanType(command);
    const target = this.extractTarget(conversationHistory);
    
    let response = `Here's how to perform a ${scanType} scan:\n\n`;
    
    const scanConfigs = {
      'service': {
        command: `-sV`,
        description: 'Identifies service versions running on open ports',
        flags: '-sV --version-intensity 7',
        time: '2-5 minutes',
        purpose: 'Critical for vulnerability assessment'
      },
      'vulnerability': {
        command: `--script vuln`,
        description: 'Runs vulnerability detection scripts',
        flags: '--script vuln',
        time: '5-15 minutes',
        purpose: 'Identifies known vulnerabilities'
      },
      'os': {
        command: `-O`,
        description: 'Attempts to identify the operating system',
        flags: '-O --osscan-guess',
        time: '1-3 minutes',
        purpose: 'Helps identify OS-specific vulnerabilities'
      },
      'comprehensive': {
        command: `-A`,
        description: 'Aggressive scan with OS detection, version scanning, script scanning, and traceroute',
        flags: '-A',
        time: '5-10 minutes',
        purpose: 'Complete system profiling'
      },
      'quick': {
        command: `-T4 -F`,
        description: 'Fast scan of the most common 100 ports',
        flags: '-T4 -F',
        time: '30-60 seconds',
        purpose: 'Quick discovery of major services'
      }
    };
    
    const config = scanConfigs[scanType] || scanConfigs['comprehensive'];
    
    response += `**${scanType.toUpperCase()} Scan Configuration:**\n`;
    response += `Command: \`nmap ${config.flags} ${target}\`\n`;
    response += `Description: ${config.description}\n`;
    response += `Estimated Time: ${config.time}\n`;
    response += `Purpose: ${config.purpose}\n\n`;
    
    response += `**When to use this scan:**\n`;
    response += this.getUseCases(scanType);
    
    return response;
  }

  // Helper methods
  extractTarget(conversationHistory) {
    // Look for IP addresses or domains in recent history
    for (let i = conversationHistory.length - 1; i >= 0; i--) {
      const turn = conversationHistory[i];
      if (turn.targets && turn.targets.length > 0) {
        return turn.targets[0];
      }
    }
    return 'target';
  }

  extractTargetFromCommand(command) {
    // Extract IP or domain from command
    const ipMatch = command.match(/\b(?:\d{1,3}\.){3}\d{1,3}\b/);
    if (ipMatch) return ipMatch[0];
    
    const domainMatch = command.match(/\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b/i);
    if (domainMatch) return domainMatch[0];
    
    return null;
  }

  extractPreviousScans(conversationHistory) {
    const scans = [];
    conversationHistory.forEach(turn => {
      if (turn.intent === 'network_scan') {
        if (turn.userMessage.toLowerCase().includes('service')) {
          scans.push('service_scan');
        } else if (turn.userMessage.toLowerCase().includes('vuln')) {
          scans.push('vulnerability_scan');
        } else if (turn.userMessage.toLowerCase().includes('-O')) {
          scans.push('os_detection');
        }
      }
    });
    return scans;
  }

  extractLastTopic(conversationHistory) {
    if (conversationHistory.length === 0) return null;
    
    const lastTurn = conversationHistory[conversationHistory.length - 1];
    if (lastTurn.assistantResponse?.includes('scan results')) {
      return 'scan_results';
    }
    return 'general';
  }

  extractScanType(command) {
    const lower = command.toLowerCase();
    if (lower.includes('service')) return 'service';
    if (lower.includes('vuln')) return 'vulnerability';
    if (lower.includes('os') || lower.includes('operating')) return 'os';
    if (lower.includes('comprehensive') || lower.includes('full')) return 'comprehensive';
    if (lower.includes('quick') || lower.includes('fast')) return 'quick';
    return 'comprehensive';
  }

  getSecurityContext(riskLevel) {
    const contexts = {
      'critical': 'poses an immediate security threat and should be addressed urgently',
      'high': 'represents a significant security risk that should be prioritized',
      'medium': 'requires attention but may not be immediately exploitable',
      'low': 'is generally secure but should be monitored'
    };
    return contexts[riskLevel] || 'requires further analysis';
  }

  identifySystemType(attackSurface) {
    const webPorts = attackSurface.filter(p => [80, 443, 8080, 8443].includes(p.port)).length;
    const dbPorts = attackSurface.filter(p => [3306, 5432, 1433].includes(p.port)).length;
    const mailPorts = attackSurface.filter(p => [25, 110, 143].includes(p.port)).length;
    
    if (webPorts >= 2) return 'a web server infrastructure';
    if (dbPorts > 0) return 'a database server (concerning if internet-facing)';
    if (mailPorts >= 2) return 'a mail server';
    if (attackSurface.some(p => p.port === 22)) return 'a Linux/Unix system';
    if (attackSurface.some(p => p.port === 3389)) return 'a Windows system';
    
    return 'a multi-purpose server';
  }

  getPriorityTarget(analysis) {
    if (analysis.criticalFindings.length > 0) {
      return `the ${analysis.criticalFindings[0].service} service due to its critical risk level`;
    }
    
    const webService = analysis.attackSurface.find(p => [80, 443].includes(p.port));
    if (webService) {
      return 'web services as they often contain application-level vulnerabilities';
    }
    
    return 'service enumeration to better understand the attack surface';
  }

  getVersionAnalysis(service) {
    // Provide version-specific insights
    if (service.includes('Apache')) {
      return 'Apache web server - check for mod_security, directory listing, and known CVEs';
    }
    if (service.includes('nginx')) {
      return 'Nginx web server - generally secure but check for misconfigurations';
    }
    if (service.includes('OpenSSH')) {
      return 'SSH service - ensure strong authentication and no default credentials';
    }
    return 'Version information available - check CVE database for known vulnerabilities';
  }

  getServicePurpose(service) {
    const purposes = {
      'HTTP': 'Serves web content over unencrypted connection',
      'HTTPS': 'Serves web content over encrypted TLS/SSL connection',
      'SSH': 'Provides secure remote shell access',
      'FTP': 'File transfer protocol for uploading/downloading files',
      'SMTP': 'Sends email messages between servers',
      'DNS': 'Resolves domain names to IP addresses',
      'SMB': 'Windows file and printer sharing',
      'RDP': 'Remote desktop access for Windows systems'
    };
    return purposes[service] || 'Provides network services';
  }

  getCommonAttacks(service) {
    const attacks = {
      'HTTP': 'XSS, SQL injection, directory traversal, DDoS',
      'HTTPS': 'SSL/TLS vulnerabilities, certificate issues, same as HTTP',
      'SSH': 'Brute force, key theft, man-in-the-middle',
      'FTP': 'Anonymous access, brute force, bounce attacks',
      'SMTP': 'Open relay, spam, email spoofing',
      'DNS': 'Cache poisoning, DDoS amplification, zone transfer',
      'SMB': 'EternalBlue, ransomware, credential theft',
      'RDP': 'BlueKeep, brute force, session hijacking'
    };
    return attacks[service] || 'Service-specific exploits';
  }

  getBestPractices(service) {
    const practices = {
      'HTTP': 'Implement HTTPS, use security headers, enable HSTS',
      'HTTPS': 'Use strong ciphers, implement perfect forward secrecy',
      'SSH': 'Disable root login, use key-based auth, change default port',
      'FTP': 'Replace with SFTP/FTPS, disable anonymous access',
      'SMTP': 'Implement SPF/DKIM/DMARC, use TLS, prevent open relay',
      'DNS': 'Disable zone transfers, implement DNSSEC',
      'SMB': 'Disable SMBv1, restrict to internal networks only',
      'RDP': 'Use VPN access, enable NLA, apply latest patches'
    };
    return practices[service] || 'Follow security hardening guidelines';
  }

  getUseCases(scanType) {
    const useCases = {
      'service': '• After initial port discovery\n• Before vulnerability assessment\n• When you need exact version numbers',
      'vulnerability': '• After identifying services\n• When assessing security posture\n• For compliance requirements',
      'os': '• Understanding system architecture\n• Identifying OS-specific vulnerabilities\n• Fingerprinting for further exploitation',
      'comprehensive': '• Initial assessment of unknown targets\n• When time is not a constraint\n• For thorough security audits',
      'quick': '• Time-sensitive assessments\n• Initial reconnaissance\n• When you need immediate results'
    };
    return useCases[scanType] || '• General security assessment';
  }

  generateContextualNextSteps(scanResults, conversationHistory) {
    const analysis = securityIntelligence.analyzeScanResults(scanResults);
    const nextSteps = analysis.nextSteps;
    
    let response = `I understand you're looking for different insights. Let me provide a fresh perspective:\n\n`;
    
    response += `**Current Security Status:**\n`;
    response += `• Attack Surface: ${analysis.attackSurface.length} exposed services\n`;
    response += `• Risk Level: ${analysis.riskLevel.toUpperCase()}\n`;
    response += `• Security Posture: ${analysis.securityPosture.overallRating}\n\n`;
    
    response += `**Strategic Recommendations:**\n`;
    nextSteps.forEach((step, index) => {
      response += `\n${index + 1}. **${step.action}**\n`;
      response += `   Why This Matters: ${step.rationale}\n`;
      response += `   Expected Outcome: ${this.getExpectedOutcome(step.action)}\n`;
    });
    
    response += `\n**Alternative Approaches:**\n`;
    response += `• **OSINT Route**: Gather passive intelligence before active scanning\n`;
    response += `• **Targeted Approach**: Focus on specific high-risk services\n`;
    response += `• **Compliance Check**: Verify against security standards\n`;
    
    return response;
  }

  getExpectedOutcome(action) {
    const outcomes = {
      'Perform detailed service enumeration': 'Exact versions for CVE matching',
      'Check for additional ports': 'Discover hidden services',
      'Perform targeted vulnerability scanning': 'Identify exploitable vulnerabilities',
      'Conduct OSINT analysis': 'Gather intelligence without active scanning',
      'Perform OS fingerprinting': 'Understand system architecture',
      'Implement security hardening': 'Reduce attack surface'
    };
    
    return outcomes[action] || 'Enhanced security intelligence';
  }
}

// Export singleton instance
const responseRouter = new ResponseRouter();

module.exports = {
  ResponseRouter,
  responseRouter
}; 