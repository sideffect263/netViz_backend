// Autonomous Decision Engine for Cybersecurity Agent
// Makes intelligent decisions about target assessment, tool selection, and strategy adaptation

const { threatIntelligence } = require('./threatIntelligenceEngine');
const { securityIntelligence } = require('./securityIntelligenceEngine');

class AutonomousDecisionEngine {
  constructor() {
    // Decision-making parameters
    this.decisionThresholds = {
      HIGH_VALUE_TARGET: 80,
      IMMEDIATE_EXPLOITATION: 90,
      DEEP_ENUMERATION: 70,
      CREDENTIAL_ATTACK: 60,
      RECONNAISSANCE_EXPAND: 50,
      MONITORING_ONLY: 30
    };

    // Assessment phases with decision criteria
    this.assessmentPhases = {
      INITIAL_RECONNAISSANCE: {
        priority: 1,
        description: 'Initial target discovery and profiling',
        tools: ['nmap_discovery', 'shodan_lookup', 'whois'],
        success_criteria: ['open_ports_identified', 'services_enumerated'],
        failure_actions: ['expand_port_range', 'alternative_discovery']
      },
      SERVICE_ENUMERATION: {
        priority: 2,
        description: 'Detailed service version detection and analysis',
        tools: ['nmap_service_scan', 'banner_grabbing', 'ssl_analysis'],
        success_criteria: ['service_versions_identified', 'vulnerability_candidates'],
        failure_actions: ['aggressive_scanning', 'alternative_enumeration']
      },
      VULNERABILITY_ASSESSMENT: {
        priority: 3,
        description: 'Vulnerability identification and validation',
        tools: ['nvd_correlation', 'exploit_db_search', 'metasploit_search'],
        success_criteria: ['exploitable_vulnerabilities', 'attack_vectors_identified'],
        failure_actions: ['credential_attacks', 'web_application_testing']
      },
      EXPLOITATION_VALIDATION: {
        priority: 4,
        description: 'Exploit validation and proof of concept',
        tools: ['metasploit', 'custom_exploits', 'payload_generation'],
        success_criteria: ['successful_exploitation', 'system_access'],
        failure_actions: ['alternative_exploits', 'social_engineering']
      },
      POST_EXPLOITATION: {
        priority: 5,
        description: 'System enumeration and privilege escalation',
        tools: ['privilege_escalation', 'lateral_movement', 'persistence'],
        success_criteria: ['elevated_privileges', 'network_mapping'],
        failure_actions: ['cleanup_traces', 'evidence_gathering']
      }
    };

    // Strategy patterns for different target types
    this.targetStrategies = {
      'web_application': {
        primary_techniques: ['web_app_scanning', 'injection_testing', 'authentication_bypass'],
        tools: ['burpsuite', 'sqlmap', 'nikto', 'dirb'],
        escalation_path: ['service_enumeration', 'vulnerability_assessment', 'web_exploitation']
      },
      'database_server': {
        primary_techniques: ['credential_brute_force', 'sql_injection', 'privilege_escalation'],
        tools: ['hydra', 'sqlmap', 'metasploit'],
        escalation_path: ['credential_attacks', 'database_exploitation', 'system_compromise']
      },
      'admin_server': {
        primary_techniques: ['credential_attacks', 'service_exploitation', 'lateral_movement'],
        tools: ['hydra', 'metasploit', 'empire'],
        escalation_path: ['authentication_bypass', 'privilege_escalation', 'domain_compromise']
      },
      'web_server': {
        primary_techniques: ['web_vulnerability_scanning', 'file_inclusion', 'command_injection'],
        tools: ['nikto', 'dirb', 'metasploit'],
        escalation_path: ['web_exploitation', 'system_access', 'privilege_escalation']
      },
      'general_server': {
        primary_techniques: ['comprehensive_scanning', 'service_exploitation', 'credential_attacks'],
        tools: ['nmap', 'metasploit', 'hydra'],
        escalation_path: ['service_enumeration', 'vulnerability_exploitation', 'system_compromise']
      }
    };

    // Decision history for learning and adaptation
    this.decisionHistory = new Map();
    this.successPatterns = new Map();
    this.failurePatterns = new Map();
  }

  // Main decision-making function
  async makeStrategicDecision(target, currentPhase, scanResults, previousActions = []) {
    try {
      // Gather comprehensive intelligence
      const intelligence = await threatIntelligence.gatherIntelligence(target, scanResults);
      
      // Analyze current situation
      const situationAnalysis = await this.analyzeSituation(target, currentPhase, intelligence, previousActions);
      
      // Generate decision options
      const decisionOptions = await this.generateDecisionOptions(situationAnalysis);
      
      // Select optimal decision
      const selectedDecision = await this.selectOptimalDecision(decisionOptions, situationAnalysis);
      
      // Learn from decision
      this.recordDecision(target, situationAnalysis, selectedDecision);
      
      return {
        decision: selectedDecision,
        intelligence: intelligence,
        situationAnalysis: situationAnalysis,
        confidence: selectedDecision.confidence,
        reasoning: selectedDecision.reasoning,
        alternativeOptions: decisionOptions.filter(opt => opt.id !== selectedDecision.id)
      };
    } catch (error) {
      console.error('Error in strategic decision making:', error);
      return this.generateFallbackDecision(target, currentPhase);
    }
  }

  // Analyze current situation comprehensively
  async analyzeSituation(target, currentPhase, intelligence, previousActions) {
    const analysis = {
      target,
      currentPhase,
      intelligence,
      riskLevel: intelligence.riskScore,
      threatLevel: intelligence.threatLevel,
      targetProfile: intelligence.targetProfile,
      attackSurface: intelligence.attackSurface,
      vulnerabilities: intelligence.vulnerabilities,
      previousActions: previousActions,
      actionHistory: this.getActionHistory(target),
      timeInvestment: this.calculateTimeInvestment(target),
      successProbability: await this.estimateSuccessProbability(intelligence, previousActions),
      resourceRequirements: this.estimateResourceRequirements(intelligence),
      detectionRisk: this.assessDetectionRisk(intelligence, previousActions),
      strategicValue: this.assessStrategicValue(intelligence),
      urgency: this.assessUrgency(intelligence),
      constraints: this.identifyConstraints(intelligence, previousActions)
    };

    // Add situational context
    analysis.situationalFactors = {
      timeOfDay: new Date().getHours(),
      dayOfWeek: new Date().getDay(),
      isWeekend: analysis.timeOfDay === 0 || analysis.timeOfDay === 6,
      targetTimezone: this.inferTargetTimezone(intelligence.targetProfile)
    };

    return analysis;
  }

  // Generate multiple decision options
  async generateDecisionOptions(situationAnalysis) {
    const options = [];
    const { intelligence, currentPhase, targetProfile } = situationAnalysis;

    // Option 1: Aggressive immediate exploitation
    if (intelligence.vulnerabilities.some(v => v.severity === 'critical' && v.weaponized)) {
      options.push({
        id: 'immediate_exploitation',
        type: 'exploitation',
        priority: 1,
        description: 'Immediate exploitation of critical weaponized vulnerabilities',
        actions: this.generateExploitationActions(intelligence.vulnerabilities),
        estimatedTime: 30, // minutes
        successProbability: 0.85,
        riskLevel: 'high',
        detectionProbability: 0.7,
        resourceIntensity: 'medium',
        reasoning: 'Critical vulnerabilities with known exploits detected'
      });
    }

    // Option 2: Systematic enumeration and analysis
    options.push({
      id: 'systematic_enumeration',
      type: 'enumeration',
      priority: 2,
      description: 'Comprehensive service enumeration and vulnerability analysis',
      actions: this.generateEnumerationActions(intelligence, targetProfile.type),
      estimatedTime: 60,
      successProbability: 0.75,
      riskLevel: 'medium',
      detectionProbability: 0.4,
      resourceIntensity: 'low',
      reasoning: 'Thorough analysis required to identify optimal attack vectors'
    });

    // Option 3: Credential-based attacks
    const authServices = intelligence.exposedServices.filter(s => 
      ['ssh', 'rdp', 'ftp', 'mysql', 'postgresql'].includes(s.product?.toLowerCase())
    );
    if (authServices.length > 0) {
      options.push({
        id: 'credential_attacks',
        type: 'credential_attack',
        priority: 3,
        description: 'Targeted credential attacks on authentication services',
        actions: this.generateCredentialAttackActions(authServices),
        estimatedTime: 120,
        successProbability: 0.6,
        riskLevel: 'medium',
        detectionProbability: 0.8,
        resourceIntensity: 'high',
        reasoning: 'Multiple authentication services detected, credential attacks viable'
      });
    }

    // Option 4: Web application focused attack
    const webServices = intelligence.exposedServices.filter(s => 
      ['http', 'https'].includes(s.product?.toLowerCase())
    );
    if (webServices.length > 0) {
      options.push({
        id: 'web_application_attack',
        type: 'web_exploitation',
        priority: 4,
        description: 'Comprehensive web application security testing',
        actions: this.generateWebAttackActions(webServices),
        estimatedTime: 90,
        successProbability: 0.7,
        riskLevel: 'medium',
        detectionProbability: 0.5,
        resourceIntensity: 'medium',
        reasoning: 'Web services detected, application-level vulnerabilities likely'
      });
    }

    // Option 5: Reconnaissance expansion
    if (targetProfile.hostnames.length > 1 || intelligence.riskScore < 50) {
      options.push({
        id: 'reconnaissance_expansion',
        type: 'reconnaissance',
        priority: 5,
        description: 'Expand reconnaissance to identify additional targets',
        actions: this.generateReconnaissanceActions(targetProfile),
        estimatedTime: 45,
        successProbability: 0.8,
        riskLevel: 'low',
        detectionProbability: 0.2,
        resourceIntensity: 'low',
        reasoning: 'Additional targets or low-risk profile suggests expanded reconnaissance'
      });
    }

    // Option 6: Stealth monitoring
    options.push({
      id: 'stealth_monitoring',
      type: 'monitoring',
      priority: 10,
      description: 'Passive monitoring and intelligence gathering',
      actions: this.generateMonitoringActions(intelligence),
      estimatedTime: 1440, // 24 hours
      successProbability: 0.9,
      riskLevel: 'minimal',
      detectionProbability: 0.1,
      resourceIntensity: 'minimal',
      reasoning: 'Low-risk intelligence gathering while waiting for better opportunities'
    });

    return options.sort((a, b) => a.priority - b.priority);
  }

  // Select the optimal decision based on multiple criteria
  async selectOptimalDecision(options, situationAnalysis) {
    let bestOption = null;
    let bestScore = -1;

    for (const option of options) {
      const score = await this.calculateDecisionScore(option, situationAnalysis);
      option.calculatedScore = score;
      option.confidence = this.calculateConfidence(option, situationAnalysis);

      if (score > bestScore) {
        bestScore = score;
        bestOption = option;
      }
    }

    // Add reasoning for selection
    bestOption.reasoning += ` Selected with score ${bestScore.toFixed(2)} based on risk/reward analysis.`;
    
    return bestOption;
  }

  // Calculate decision score based on multiple factors
  async calculateDecisionScore(option, situationAnalysis) {
    let score = 0;

    // Success probability weight (40%)
    score += option.successProbability * 40;

    // Strategic value weight (25%)
    score += situationAnalysis.strategicValue * 0.25 * 25;

    // Time efficiency weight (15%)
    const timeEfficiency = Math.max(0, (180 - option.estimatedTime) / 180);
    score += timeEfficiency * 15;

    // Risk adjustment weight (10%)
    const riskPenalty = this.getRiskPenalty(option.riskLevel, option.detectionProbability);
    score -= riskPenalty * 10;

    // Resource efficiency weight (10%)
    const resourceEfficiency = this.getResourceEfficiency(option.resourceIntensity);
    score += resourceEfficiency * 10;

    // Historical success pattern bonus
    const historicalBonus = this.getHistoricalSuccessBonus(option.type, situationAnalysis.targetProfile.type);
    score += historicalBonus;

    // Urgency factor
    score += situationAnalysis.urgency * 5;

    return Math.max(0, Math.min(100, score));
  }

  // Generate specific action sequences for different decision types
  generateExploitationActions(vulnerabilities) {
    const criticalVulns = vulnerabilities.filter(v => v.severity === 'critical' && v.weaponized);
    return criticalVulns.map(vuln => ({
      tool: 'metasploit',
      technique: 'exploit_validation',
      target: vuln.cveId,
      parameters: {
        payload: 'reverse_shell',
        timeout: 300,
        attempts: 3
      },
      successCriteria: ['shell_access', 'command_execution'],
      fallbackActions: ['alternative_payload', 'manual_exploitation']
    }));
  }

  generateEnumerationActions(intelligence, targetType) {
    const strategy = this.targetStrategies[targetType] || this.targetStrategies['general_server'];
    return [
      {
        tool: 'nmap',
        technique: 'service_version_detection',
        parameters: { flags: '-sV -sC', timeout: 600 },
        successCriteria: ['service_versions_identified'],
        priority: 1
      },
      {
        tool: 'custom_scripts',
        technique: 'banner_analysis',
        parameters: { services: intelligence.exposedServices },
        successCriteria: ['detailed_service_info'],
        priority: 2
      },
      ...strategy.tools.map((tool, index) => ({
        tool,
        technique: strategy.primary_techniques[index] || 'reconnaissance',
        parameters: { target_type: targetType },
        priority: index + 3
      }))
    ];
  }

  generateCredentialAttackActions(authServices) {
    return authServices.map(service => ({
      tool: 'hydra',
      technique: 'credential_brute_force',
      target: `${service.product}:${service.port}`,
      parameters: {
        userlist: 'common_users',
        passlist: 'common_passwords',
        threads: 16,
        timeout: 30
      },
      successCriteria: ['valid_credentials'],
      fallbackActions: ['targeted_wordlist', 'credential_stuffing']
    }));
  }

  generateWebAttackActions(webServices) {
    return [
      {
        tool: 'burpsuite',
        technique: 'web_application_scan',
        parameters: { depth: 'comprehensive', timeout: 1800 },
        successCriteria: ['vulnerability_identified'],
        priority: 1
      },
      {
        tool: 'sqlmap',
        technique: 'sql_injection_testing',
        parameters: { level: 3, risk: 2 },
        successCriteria: ['sql_injection_confirmed'],
        priority: 2
      },
      {
        tool: 'dirb',
        technique: 'directory_enumeration',
        parameters: { wordlist: 'comprehensive' },
        successCriteria: ['hidden_directories'],
        priority: 3
      }
    ];
  }

  generateReconnaissanceActions(targetProfile) {
    return [
      {
        tool: 'subdomain_enum',
        technique: 'subdomain_discovery',
        parameters: { domain: targetProfile.target },
        successCriteria: ['additional_subdomains'],
        priority: 1
      },
      {
        tool: 'certificate_transparency',
        technique: 'cert_log_analysis',
        parameters: { domain: targetProfile.target },
        successCriteria: ['certificate_domains'],
        priority: 2
      },
      {
        tool: 'dns_brute_force',
        technique: 'dns_enumeration',
        parameters: { wordlist: 'comprehensive' },
        successCriteria: ['dns_records'],
        priority: 3
      }
    ];
  }

  generateMonitoringActions(intelligence) {
    return [
      {
        tool: 'passive_monitor',
        technique: 'service_monitoring',
        parameters: { 
          interval: 3600,
          services: intelligence.exposedServices.map(s => s.port)
        },
        successCriteria: ['change_detection'],
        priority: 1
      },
      {
        tool: 'threat_intel_monitor',
        technique: 'vulnerability_tracking',
        parameters: { 
          services: intelligence.exposedServices,
          check_interval: 86400 // 24 hours
        },
        successCriteria: ['new_vulnerabilities'],
        priority: 2
      }
    ];
  }

  // Calculate confidence in decision
  calculateConfidence(option, situationAnalysis) {
    let confidence = option.successProbability;
    
    // Adjust based on intelligence quality
    if (situationAnalysis.intelligence.vulnerabilities.length > 0) {
      confidence += 0.1;
    }
    
    // Adjust based on target familiarity
    const historicalData = this.getActionHistory(situationAnalysis.target);
    if (historicalData.length > 0) {
      confidence += 0.15;
    }
    
    // Adjust based on resource availability
    if (option.resourceIntensity === 'low') {
      confidence += 0.1;
    }
    
    return Math.min(0.95, confidence);
  }

  // Estimate success probability based on intelligence and history
  async estimateSuccessProbability(intelligence, previousActions) {
    let baseProbability = 0.5;
    
    // Adjust based on vulnerability severity
    const criticalVulns = intelligence.vulnerabilities.filter(v => v.severity === 'critical');
    baseProbability += criticalVulns.length * 0.15;
    
    // Adjust based on service exposure
    const criticalServices = intelligence.exposedServices.filter(s => s.criticality?.priority === 'critical');
    baseProbability += criticalServices.length * 0.1;
    
    // Adjust based on target type
    const targetTypeModifiers = {
      'honeypot': -0.8,
      'web_application': 0.2,
      'database_server': 0.15,
      'admin_server': 0.1
    };
    baseProbability += targetTypeModifiers[intelligence.targetProfile.type] || 0;
    
    // Adjust based on previous action success
    const successfulActions = previousActions.filter(a => a.success);
    const failedActions = previousActions.filter(a => !a.success);
    
    if (previousActions.length > 0) {
      const successRate = successfulActions.length / previousActions.length;
      baseProbability = (baseProbability + successRate) / 2;
    }
    
    return Math.max(0.1, Math.min(0.95, baseProbability));
  }

  // Utility methods for decision scoring
  getRiskPenalty(riskLevel, detectionProbability) {
    const riskMultipliers = {
      'minimal': 0.1,
      'low': 0.2,
      'medium': 0.5,
      'high': 0.8,
      'critical': 1.0
    };
    return (riskMultipliers[riskLevel] || 0.5) * detectionProbability;
  }

  getResourceEfficiency(resourceIntensity) {
    const efficiencyScores = {
      'minimal': 1.0,
      'low': 0.8,
      'medium': 0.6,
      'high': 0.4,
      'critical': 0.2
    };
    return efficiencyScores[resourceIntensity] || 0.6;
  }

  getHistoricalSuccessBonus(actionType, targetType) {
    const key = `${actionType}_${targetType}`;
    const pattern = this.successPatterns.get(key);
    return pattern ? Math.min(5, pattern.successRate * 10) : 0;
  }

  // Learning and adaptation methods
  recordDecision(target, situationAnalysis, decision) {
    const historyKey = target;
    if (!this.decisionHistory.has(historyKey)) {
      this.decisionHistory.set(historyKey, []);
    }
    
    this.decisionHistory.get(historyKey).push({
      timestamp: new Date().toISOString(),
      situation: situationAnalysis,
      decision: decision,
      expectedOutcome: decision.successProbability
    });
  }

  updateDecisionOutcome(target, decisionId, success, actualResults) {
    const history = this.decisionHistory.get(target);
    if (history) {
      const decision = history.find(d => d.decision.id === decisionId);
      if (decision) {
        decision.actualSuccess = success;
        decision.actualResults = actualResults;
        
        // Update success patterns
        this.updateSuccessPatterns(decision);
      }
    }
  }

  updateSuccessPatterns(decisionRecord) {
    const { decision, situation, actualSuccess } = decisionRecord;
    const key = `${decision.type}_${situation.targetProfile.type}`;
    
    if (!this.successPatterns.has(key)) {
      this.successPatterns.set(key, { attempts: 0, successes: 0, successRate: 0 });
    }
    
    const pattern = this.successPatterns.get(key);
    pattern.attempts++;
    if (actualSuccess) {
      pattern.successes++;
    }
    pattern.successRate = pattern.successes / pattern.attempts;
  }

  // Utility methods
  getActionHistory(target) {
    return this.decisionHistory.get(target) || [];
  }

  calculateTimeInvestment(target) {
    const history = this.getActionHistory(target);
    return history.reduce((total, action) => total + (action.decision.estimatedTime || 0), 0);
  }

  estimateResourceRequirements(intelligence) {
    // Simple estimation based on target complexity
    const baseRequirement = intelligence.attackSurface.totalPorts * 2;
    const vulnerabilityRequirement = intelligence.vulnerabilities.length * 5;
    const serviceRequirement = intelligence.exposedServices.length * 3;
    
    return baseRequirement + vulnerabilityRequirement + serviceRequirement;
  }

  assessDetectionRisk(intelligence, previousActions) {
    let risk = 0.2; // Base risk
    
    // Increase risk based on previous action volume
    risk += previousActions.length * 0.05;
    
    // Adjust based on target type
    const typeRisks = {
      'honeypot': 0.9,
      'admin_server': 0.7,
      'database_server': 0.6,
      'web_application': 0.4,
      'web_server': 0.3
    };
    risk += typeRisks[intelligence.targetProfile.type] || 0.5;
    
    return Math.min(0.95, risk);
  }

  assessStrategicValue(intelligence) {
    let value = 0.5;
    
    // High value for critical vulnerabilities
    value += intelligence.vulnerabilities.filter(v => v.severity === 'critical').length * 0.15;
    
    // High value for critical services
    value += intelligence.exposedServices.filter(s => s.criticality?.priority === 'critical').length * 0.1;
    
    // Adjust based on organization type
    if (intelligence.targetProfile.organization !== 'Unknown') {
      value += 0.2;
    }
    
    return Math.min(1.0, value);
  }

  assessUrgency(intelligence) {
    let urgency = 0.5;
    
    // High urgency for weaponized vulnerabilities
    const weaponizedVulns = intelligence.vulnerabilities.filter(v => v.weaponized);
    urgency += weaponizedVulns.length * 0.2;
    
    // High urgency for recently published vulnerabilities
    const recentVulns = intelligence.vulnerabilities.filter(v => {
      const publishDate = new Date(v.publishedDate);
      const daysSincePublished = (Date.now() - publishDate) / (1000 * 60 * 60 * 24);
      return daysSincePublished < 30;
    });
    urgency += recentVulns.length * 0.15;
    
    return Math.min(1.0, urgency);
  }

  identifyConstraints(intelligence, previousActions) {
    const constraints = [];
    
    // Time constraints
    const timeInvested = this.calculateTimeInvestment(intelligence.target);
    if (timeInvested > 480) { // 8 hours
      constraints.push('time_limit_approaching');
    }
    
    // Detection constraints
    if (previousActions.length > 10) {
      constraints.push('high_activity_detected');
    }
    
    // Resource constraints
    const resourceUsage = this.estimateResourceRequirements(intelligence);
    if (resourceUsage > 100) {
      constraints.push('resource_intensive');
    }
    
    return constraints;
  }

  inferTargetTimezone(targetProfile) {
    // Simple timezone inference based on geolocation
    const timezoneMap = {
      'United States': 'America/New_York',
      'United Kingdom': 'Europe/London',
      'Germany': 'Europe/Berlin',
      'Japan': 'Asia/Tokyo',
      'Australia': 'Australia/Sydney'
    };
    return timezoneMap[targetProfile.geolocation?.country] || 'UTC';
  }

  generateFallbackDecision(target, currentPhase) {
    return {
      decision: {
        id: 'fallback_reconnaissance',
        type: 'reconnaissance',
        priority: 5,
        description: 'Fallback reconnaissance due to decision engine error',
        actions: [{
          tool: 'nmap',
          technique: 'basic_scan',
          parameters: { flags: '-T4 -F' }
        }],
        confidence: 0.3,
        reasoning: 'Fallback decision due to analysis error'
      },
      intelligence: null,
      situationAnalysis: { target, currentPhase, error: true }
    };
  }
}

// Singleton instance
const autonomousDecision = new AutonomousDecisionEngine();

module.exports = {
  AutonomousDecisionEngine,
  autonomousDecision
}; 