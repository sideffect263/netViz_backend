// Security Intelligence Engine for Enhanced AI Agent Capabilities
// This module provides cybersecurity expertise, strategic thinking, and intelligent recommendations

class SecurityIntelligenceEngine {
  constructor() {
    // Security assessment methodology phases
    this.assessmentPhases = {
      DISCOVERY: 'discovery',
      ENUMERATION: 'enumeration',
      VULNERABILITY_ASSESSMENT: 'vulnerability_assessment',
      EXPLOITATION: 'exploitation',
      POST_EXPLOITATION: 'post_exploitation'
    };

    // Service vulnerability database (simplified for demonstration)
    this.knownVulnerabilities = {
      'Apache': {
        '2.4.49': ['CVE-2021-41773', 'CVE-2021-42013'],
        '2.4.50': ['CVE-2021-42013']
      },
      'nginx': {
        '1.16.1': ['CVE-2019-20372'],
        '1.17.0': ['CVE-2019-20372']
      },
      'OpenSSH': {
        '7.4': ['CVE-2018-15473'],
        '7.6': ['CVE-2018-15473']
      }
    };

    // Common port service mappings with security implications
    this.portIntelligence = {
      21: { service: 'FTP', risk: 'high', implications: 'Unencrypted file transfer, potential for credential theft' },
      22: { service: 'SSH', risk: 'low', implications: 'Secure remote access, check for weak credentials' },
      23: { service: 'Telnet', risk: 'critical', implications: 'Unencrypted remote access, replace with SSH immediately' },
      25: { service: 'SMTP', risk: 'medium', implications: 'Email service, check for open relay' },
      53: { service: 'DNS', risk: 'medium', implications: 'DNS service, check for zone transfers' },
      80: { service: 'HTTP', risk: 'medium', implications: 'Web service, check for HTTPS redirect' },
      110: { service: 'POP3', risk: 'high', implications: 'Unencrypted email retrieval' },
      143: { service: 'IMAP', risk: 'high', implications: 'Unencrypted email access' },
      443: { service: 'HTTPS', risk: 'low', implications: 'Encrypted web service, check SSL/TLS configuration' },
      445: { service: 'SMB', risk: 'high', implications: 'File sharing, common attack vector' },
      1433: { service: 'MSSQL', risk: 'high', implications: 'Database service, should not be internet-facing' },
      3306: { service: 'MySQL', risk: 'high', implications: 'Database service, should not be internet-facing' },
      3389: { service: 'RDP', risk: 'high', implications: 'Remote desktop, common brute-force target' },
      5432: { service: 'PostgreSQL', risk: 'high', implications: 'Database service, should not be internet-facing' },
      8080: { service: 'HTTP-Proxy', risk: 'medium', implications: 'Alternative web port, often used for development' },
      8443: { service: 'HTTPS-Alt', risk: 'low', implications: 'Alternative HTTPS port' }
    };
  }

  // Analyze scan results and provide security insights
  analyzeScanResults(scanData, targetIpOrHostname) {
    const analysis = {
      riskLevel: 'low',
      criticalFindings: [],
      recommendations: [],
      nextSteps: [],
      securityPosture: {},
      attackSurface: [],
      target: targetIpOrHostname
    };

    // Parse scan data based on type
    if (typeof scanData === 'string') {
      // Parse Nmap output
      analysis.attackSurface = this.parseNmapOutput(scanData);
    } else if (scanData.ports) {
      // Direct port data
      analysis.attackSurface = scanData.ports;
    }

    // Analyze each open port
    analysis.attackSurface.forEach(port => {
      const portAnalysis = this.analyzePort(port);
      
      if (portAnalysis.risk === 'critical' || portAnalysis.risk === 'high') {
        analysis.criticalFindings.push(portAnalysis);
        if (portAnalysis.risk === 'critical') {
          analysis.riskLevel = 'critical';
        } else if (analysis.riskLevel !== 'critical') {
          analysis.riskLevel = 'high';
        }
      }

      // Add specific recommendations
      analysis.recommendations.push(...portAnalysis.recommendations);
    });

    // Generate strategic next steps, passing the target
    analysis.nextSteps = this.generateNextSteps(analysis, targetIpOrHostname);

    // Calculate security posture
    analysis.securityPosture = this.calculateSecurityPosture(analysis);

    return analysis;
  }

  // Parse Nmap output to extract port information
  parseNmapOutput(nmapOutput) {
    const ports = [];
    const lines = nmapOutput.split('\n');
    
    // Look for the "Open ports:" section and parse it
    let inPortSection = false;
    
    lines.forEach(line => {
      // Check if we're in the open ports section
      if (line.includes('Open ports:')) {
        inPortSection = true;
        return;
      }
      
      // Parse port lines in the format "  80/tcp - http"
      if (inPortSection && line.trim().match(/^\d+\/\w+\s+-\s+\w+/)) {
        const portMatch = line.trim().match(/^(\d+)\/(tcp|udp)\s+-\s+(.+)$/);
        if (portMatch) {
          ports.push({
            port: parseInt(portMatch[1]),
            protocol: portMatch[2],
            state: 'open',
            service: portMatch[3]
          });
        }
      }
      
      // Also handle standard Nmap output format (e.g., "80/tcp open http Apache httpd 2.4.41")
      const standardMatch = line.match(/^(\d+)\/(tcp|udp)\s+(\w+)\s+(.*)$/);
      if (standardMatch) {
        ports.push({
          port: parseInt(standardMatch[1]),
          protocol: standardMatch[2],
          state: standardMatch[3],
          service: standardMatch[4]
        });
      }
    });

    return ports;
  }

  // Analyze individual port for security implications
  analyzePort(portInfo) {
    const portNum = portInfo.port;
    const service = portInfo.service || '';
    
    const analysis = {
      port: portNum,
      service: service,
      risk: 'low',
      implications: [],
      recommendations: [],
      vulnerabilities: []
    };

    // Check known port intelligence
    if (this.portIntelligence[portNum]) {
      const intel = this.portIntelligence[portNum];
      analysis.risk = intel.risk;
      analysis.implications.push(intel.implications);
      
      // Add specific recommendations based on service
      switch (intel.service) {
        case 'Telnet':
          analysis.recommendations.push({
            priority: 'critical',
            action: 'Disable Telnet immediately and replace with SSH',
            rationale: 'Telnet transmits all data including passwords in plaintext'
          });
          break;
        case 'FTP':
          analysis.recommendations.push({
            priority: 'high',
            action: 'Replace FTP with SFTP or FTPS',
            rationale: 'FTP transmits credentials in plaintext'
          });
          break;
        case 'HTTP':
          if (portNum === 80) {
            analysis.recommendations.push({
              priority: 'medium',
              action: 'Implement HTTPS and redirect all HTTP traffic',
              rationale: 'HTTP traffic is unencrypted and vulnerable to interception'
            });
          }
          break;
        case 'SMB':
          analysis.recommendations.push({
            priority: 'high',
            action: 'Restrict SMB access to internal networks only',
            rationale: 'SMB is frequently targeted for ransomware and lateral movement'
          });
          break;
      }
    }

    // Check for version-specific vulnerabilities
    const versionMatch = service.match(/(\w+)(?:\/|\s+)(\d+\.\d+(?:\.\d+)?)/);
    if (versionMatch) {
      const serviceName = versionMatch[1];
      const version = versionMatch[2];
      
      if (this.knownVulnerabilities[serviceName] && 
          this.knownVulnerabilities[serviceName][version]) {
        analysis.vulnerabilities = this.knownVulnerabilities[serviceName][version];
        analysis.risk = 'critical';
        analysis.recommendations.push({
          priority: 'critical',
          action: `Update ${serviceName} to the latest patched version`,
          rationale: `Known vulnerabilities: ${analysis.vulnerabilities.join(', ')}`
        });
      }
    }

    return analysis;
  }

  // Generate strategic next steps based on current findings
  generateNextSteps(analysis, targetIpOrHostname) {
    const nextSteps = [];
    const currentPhase = this.determineCurrentPhase(analysis);
    const target = targetIpOrHostname || analysis.target || '[target]';

    // Always include a brief summary of what was found
    const openPorts = analysis.attackSurface.length;
    const criticalCount = analysis.criticalFindings.length;
    
    // Phase-based recommendations
    switch (currentPhase) {
      case this.assessmentPhases.DISCOVERY:
        // Just discovered basic ports, need more detail
        nextSteps.push({
          action: 'Perform detailed service enumeration',
          command: `-sV ${target}`,
          rationale: `Found ${openPorts} open ports on ${target}. Need to identify specific service versions to assess vulnerabilities.`,
          priority: 'high'
        });
        
        if (openPorts > 5) {
          nextSteps.push({
            action: 'Check for additional ports',
            command: `-p- ${target}`,
            rationale: `Multiple services detected on ${target}. There may be non-standard ports in use.`,
            priority: 'medium'
          });
        }
        break;

      case this.assessmentPhases.ENUMERATION:
        // Have service info, need vulnerability assessment
        if (criticalCount > 0) {
          nextSteps.push({
            action: 'Perform targeted vulnerability scanning',
            command: `--script vuln -p ${analysis.criticalFindings.map(f => f.port).join(',')} ${target}`,
            rationale: `Identified ${criticalCount} high-risk services on ${target} that need immediate vulnerability assessment.`,
            priority: 'critical'
          });
        }

        // Check for web services
        const webPorts = analysis.attackSurface.filter(p => 
          [80, 443, 8080, 8443].includes(p.port)
        );
        
        if (webPorts.length > 0) {
          nextSteps.push({
            action: 'Perform web application analysis',
            command: `nikto -h ${target} -p ${webPorts.map(p => p.port).join(',')}`,
            rationale: `Found ${webPorts.length} web services on ${target} that may have application-level vulnerabilities.`,
            priority: 'high'
          });
        }

        // OSINT recommendation
        nextSteps.push({
          action: `Conduct OSINT analysis for ${target}`,
          command: `theharvester -d ${target} -b all`,
          rationale: `Gather additional intelligence about ${target} and its infrastructure.`,
          priority: 'medium'
        });
        break;

      case this.assessmentPhases.VULNERABILITY_ASSESSMENT:
        // Have detailed info, provide remediation guidance
        if (analysis.vulnerabilities && analysis.vulnerabilities.length > 0) {
          nextSteps.push({
            action: 'Prioritize vulnerability remediation',
            command: 'Focus on critical vulnerabilities first',
            rationale: `Found ${analysis.vulnerabilities.length} known vulnerabilities that need patching.`,
            priority: 'critical'
          });
        }

        nextSteps.push({
          action: 'Implement security hardening',
          command: 'Apply security best practices to all services',
          rationale: 'Reduce attack surface by hardening configurations.',
          priority: 'high'
        });
        break;
    }

    // Always suggest OS detection if not done
    if (!analysis.osInfo) {
      nextSteps.push({
        action: 'Perform OS fingerprinting',
        command: `-O ${target}`,
        rationale: `Understanding the operating system of ${target} helps identify OS-specific vulnerabilities.`,
        priority: 'medium'
      });
    }

    return nextSteps;
  }

  // Determine current assessment phase based on available data
  determineCurrentPhase(analysis) {
    // Check what information we have
    const hasBasicPorts = analysis.attackSurface.length > 0;
    const hasServiceVersions = analysis.attackSurface.some(p => 
      p.service && p.service.includes('/')
    );
    const hasVulnerabilities = analysis.vulnerabilities && 
      analysis.vulnerabilities.length > 0;

    if (hasVulnerabilities) {
      return this.assessmentPhases.VULNERABILITY_ASSESSMENT;
    } else if (hasServiceVersions) {
      return this.assessmentPhases.ENUMERATION;
    } else if (hasBasicPorts) {
      return this.assessmentPhases.DISCOVERY;
    }

    return this.assessmentPhases.DISCOVERY;
  }

  // Calculate overall security posture
  calculateSecurityPosture(analysis) {
    const posture = {
      score: 100, // Start with perfect score
      strengths: [],
      weaknesses: [],
      overallRating: 'Good'
    };

    // Deduct points for findings
    analysis.criticalFindings.forEach(finding => {
      if (finding.risk === 'critical') {
        posture.score -= 25;
        posture.weaknesses.push(`Critical: ${finding.service} on port ${finding.port}`);
      } else if (finding.risk === 'high') {
        posture.score -= 15;
        posture.weaknesses.push(`High Risk: ${finding.service} on port ${finding.port}`);
      }
    });

    // Check for good practices
    const hasHTTPS = analysis.attackSurface.some(p => p.port === 443);
    const hasSSH = analysis.attackSurface.some(p => p.port === 22);
    const hasTelnet = analysis.attackSurface.some(p => p.port === 23);

    if (hasHTTPS && !analysis.attackSurface.some(p => p.port === 80)) {
      posture.strengths.push('HTTPS-only web presence');
      posture.score += 5;
    }

    if (hasSSH && !hasTelnet) {
      posture.strengths.push('Using SSH for remote access (no Telnet)');
      posture.score += 5;
    }

    // Determine overall rating
    if (posture.score >= 90) {
      posture.overallRating = 'Excellent';
    } else if (posture.score >= 70) {
      posture.overallRating = 'Good';
    } else if (posture.score >= 50) {
      posture.overallRating = 'Fair';
    } else if (posture.score >= 30) {
      posture.overallRating = 'Poor';
    } else {
      posture.overallRating = 'Critical';
    }

    return posture;
  }

  // Generate context-aware response based on conversation history
  generateContextAwareResponse(scanResults, conversationHistory, currentQuestion) {
    const analysis = this.analyzeScanResults(scanResults);
    const previousFindings = this.extractPreviousFindings(conversationHistory);
    
    // Check if this is a follow-up question
    const isFollowUp = this.isFollowUpQuestion(currentQuestion, conversationHistory);
    
    if (isFollowUp) {
      return this.generateFollowUpResponse(analysis, previousFindings, currentQuestion);
    } else {
      return this.generateInitialResponse(analysis);
    }
  }

  // Extract findings from conversation history
  extractPreviousFindings(conversationHistory) {
    const findings = {
      discoveredPorts: [],
      identifiedServices: [],
      knownVulnerabilities: [],
      completedScans: []
    };

    conversationHistory.forEach(turn => {
      // Extract port information from assistant responses
      const portMatches = turn.assistantResponse?.match(/port\s+(\d+)/gi) || [];
      portMatches.forEach(match => {
        const port = parseInt(match.match(/\d+/)[0]);
        if (!findings.discoveredPorts.includes(port)) {
          findings.discoveredPorts.push(port);
        }
      });

      // Track completed scan types
      if (turn.intent === 'network_scan') {
        findings.completedScans.push(turn.intent);
      }
    });

    return findings;
  }

  // Check if current question is a follow-up
  isFollowUpQuestion(question, conversationHistory) {
    const lowerQuestion = question.toLowerCase();
    const followUpIndicators = [
      'next', 'then', 'after that', 'what else',
      'more', 'other', 'additional', 'further'
    ];

    return followUpIndicators.some(indicator => 
      lowerQuestion.includes(indicator)
    ) && conversationHistory.length > 0;
  }

  // Generate response for follow-up questions
  generateFollowUpResponse(analysis, previousFindings, question) {
    const response = {
      summary: '',
      recommendations: [],
      explanation: ''
    };
    const target = analysis.target || '[target]';

    // Build on previous findings
    response.summary = `Based on our previous findings on ${target} and the current scan results, here's what I recommend next:\n\n`;

    // Add specific next steps
    const nextSteps = analysis.nextSteps.slice(0, 3); // Top 3 recommendations
    nextSteps.forEach((step, index) => {
      response.recommendations.push({
        order: index + 1,
        action: step.action,
        command: step.command,
        rationale: step.rationale
      });
    });

    // Add explanation
    response.explanation = `\nThese recommendations follow the standard penetration testing methodology. `;
    response.explanation += `We've completed the ${this.determineCurrentPhase(analysis)} phase `;
    response.explanation += `and should now proceed with more detailed analysis to build a complete security picture.`;

    return this.formatResponse(response);
  }

  // Generate initial response for new scans
  generateInitialResponse(analysis) {
    const response = {
      summary: '',
      findings: [],
      recommendations: [],
      securityPosture: analysis.securityPosture
    };
    const target = analysis.target || '[target]';

    // Summarize findings
    response.summary = `I've completed the scan on ${target} and identified ${analysis.attackSurface.length} open ports. `;
    
    if (analysis.criticalFindings.length > 0) {
      response.summary += `⚠️ Found ${analysis.criticalFindings.length} critical security concerns that need immediate attention.\n\n`;
    } else {
      response.summary += `The initial results look relatively secure, but let's dig deeper.\n\n`;
    }

    // Add key findings
    analysis.attackSurface.forEach(port => {
      response.findings.push({
        port: port.port,
        service: port.service,
        risk: this.portIntelligence[port.port]?.risk || 'unknown',
        implication: this.portIntelligence[port.port]?.implications || 'Requires further analysis'
      });
    });

    // Add top recommendations
    response.recommendations = analysis.recommendations.slice(0, 3);

    return this.formatResponse(response);
  }

  // Format response for output
  formatResponse(response) {
    let formatted = response.summary;
    const target = response.target || (response.analysis ? response.analysis.target : null) || '[target]';

    if (response.findings && response.findings.length > 0) {
      formatted += '**Key Findings:**\n';
      response.findings.forEach(finding => {
        formatted += `• Port ${finding.port} (${finding.service}): ${finding.implication}\n`;
      });
      formatted += '\n';
    }

    if (response.recommendations && response.recommendations.length > 0) {
      formatted += '**Recommended Next Steps:**\n';
      response.recommendations.forEach(rec => {
        if (rec.order) {
          formatted += `${rec.order}. **${rec.action}**\n`;
          let commandString = rec.command || '';
          if (typeof commandString === 'string') {
            // Fix command formatting - ensure proper nmap prefix and no duplication
            commandString = commandString.replace('[target]', target).replace('{TARGET_IP_HERE}', target);
            // If command doesn't start with nmap and contains flags, add nmap prefix
            if (!commandString.startsWith('nmap') && (commandString.startsWith('-') || commandString.includes('--'))) {
              commandString = `nmap ${commandString}`;
            }
          }
          formatted += `   Command: \`${commandString}\`\n`;
          formatted += `   Why: ${rec.rationale}\n\n`;
        } else {
          formatted += `• ${rec.action}: ${rec.rationale}\n`;
        }
      });
    }

    if (response.explanation) {
      formatted += response.explanation;
    }

    if (response.securityPosture) {
      formatted += `\n\n**Security Posture:** ${response.securityPosture.overallRating} (Score: ${response.securityPosture.score}/100)`;
    }

    return formatted;
  }
}

// Export the instance using CommonJS
const securityIntelligence = new SecurityIntelligenceEngine();
module.exports = { securityIntelligence }; 