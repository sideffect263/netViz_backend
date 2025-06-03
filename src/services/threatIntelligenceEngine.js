// Threat Intelligence Engine for Autonomous Cybersecurity Agent
// Integrates NIST NVD, Shodan, and other threat intelligence sources

const axios = require('axios');

class ThreatIntelligenceEngine {
  constructor() {
    this.nvidApiKey = process.env.NVD_API_KEY;
    this.shodanApiKey = process.env.SHODAN_API_KEY;
    
    // Cache for API responses to reduce calls
    this.cache = new Map();
    this.CACHE_TTL = 24 * 60 * 60 * 1000; // 24 hours
    
    // Intelligence scores for decision making
    this.intelligenceScores = {
      HIGH_VALUE_TARGET: 100,
      KNOWN_VULNERABILITY: 90,
      EXPOSED_SERVICE: 80,
      SUSPICIOUS_PATTERN: 70,
      RECONNAISSANCE_TARGET: 60,
      STANDARD_SERVICE: 40,
      HARDENED_TARGET: 20
    };

    // Service criticality mapping
    this.serviceCriticality = {
      'ssh': { priority: 'high', attack_vectors: ['brute_force', 'key_theft', 'privilege_escalation'] },
      'http': { priority: 'high', attack_vectors: ['web_app_attacks', 'injection', 'xss'] },
      'https': { priority: 'medium', attack_vectors: ['ssl_attacks', 'web_app_attacks'] },
      'ftp': { priority: 'critical', attack_vectors: ['credential_theft', 'file_access'] },
      'smb': { priority: 'critical', attack_vectors: ['lateral_movement', 'ransomware'] },
      'rdp': { priority: 'critical', attack_vectors: ['brute_force', 'credential_stuffing'] },
      'mysql': { priority: 'critical', attack_vectors: ['sql_injection', 'data_exfiltration'] },
      'postgresql': { priority: 'critical', attack_vectors: ['sql_injection', 'privilege_escalation'] },
      'mssql': { priority: 'critical', attack_vectors: ['sql_injection', 'command_injection'] }
    };
  }

  // Main intelligence gathering function
  async gatherIntelligence(target, scanResults) {
    const intelligence = {
      target,
      timestamp: new Date().toISOString(),
      riskScore: 0,
      vulnerabilities: [],
      exposedServices: [],
      threatLevel: 'low',
      strategicRecommendations: [],
      targetProfile: {},
      attackSurface: {},
      nextActions: []
    };

    try {
      // Parallel intelligence gathering
      const [shodanData, vulnerabilityData, serviceAnalysis] = await Promise.all([
        this.getShodanIntelligence(target),
        this.getVulnerabilityIntelligence(scanResults),
        this.analyzeServiceExposure(scanResults)
      ]);

      // Correlate and analyze intelligence
      intelligence.targetProfile = await this.buildTargetProfile(target, shodanData);
      intelligence.vulnerabilities = vulnerabilityData;
      intelligence.exposedServices = serviceAnalysis.services;
      intelligence.attackSurface = serviceAnalysis.attackSurface;
      
      // Calculate risk score and threat level
      intelligence.riskScore = this.calculateRiskScore(intelligence);
      intelligence.threatLevel = this.determineThreatLevel(intelligence.riskScore);
      
      // Generate strategic recommendations
      intelligence.strategicRecommendations = await this.generateStrategicRecommendations(intelligence);
      intelligence.nextActions = await this.generateNextActions(intelligence);

      return intelligence;
    } catch (error) {
      console.error('Error gathering threat intelligence:', error);
      return intelligence; // Return partial intelligence even on error
    }
  }

  // Shodan API integration for target intelligence
  async getShodanIntelligence(target) {
    if (!this.shodanApiKey) {
      console.warn('Shodan API key not configured');
      return null;
    }

    const cacheKey = `shodan_${target}`;
    if (this.isValidCache(cacheKey)) {
      return this.cache.get(cacheKey).data;
    }

    try {
      // Check if target is IP or domain
      const isIP = /^\d+\.\d+\.\d+\.\d+$/.test(target);
      const endpoint = isIP ? 'host' : 'dns/resolve';
      const queryParam = isIP ? target : `hostnames=${target}`;

      const response = await axios.get(
        `https://api.shodan.io/shodan/${endpoint}/${isIP ? target : ''}?${isIP ? '' : queryParam}&key=${this.shodanApiKey}`,
        { timeout: 10000 }
      );

      const shodanData = {
        ip: response.data.ip_str || target,
        org: response.data.org || 'Unknown',
        isp: response.data.isp || 'Unknown',
        country: response.data.country_name || 'Unknown',
        city: response.data.city || 'Unknown',
        hostnames: response.data.hostnames || [],
        ports: response.data.ports || [],
        vulns: response.data.vulns || [],
        tags: response.data.tags || [],
        services: this.parseShodanServices(response.data.data || []),
        lastUpdate: response.data.last_update,
        asn: response.data.asn
      };

      this.setCache(cacheKey, shodanData);
      return shodanData;
    } catch (error) {
      console.error(`Shodan API error for ${target}:`, error.message);
      return null;
    }
  }

  // Parse Shodan service data
  parseShodanServices(serviceData) {
    return serviceData.map(service => ({
      port: service.port,
      protocol: service.transport || 'tcp',
      service: service.product || 'unknown',
      version: service.version || 'unknown',
      banner: service.banner || '',
      vulns: service.vulns || [],
      cpe: service.cpe || [],
      ssl: service.ssl || null,
      http: service.http || null
    }));
  }

  // NIST NVD integration for vulnerability intelligence
  async getVulnerabilityIntelligence(scanResults) {
    if (!this.nvidApiKey) {
      console.warn('NVD API key not configured');
      return [];
    }

    const vulnerabilities = [];
    const services = this.extractServicesFromScan(scanResults);

    for (const service of services) {
      const vulns = await this.searchNVDVulnerabilities(service);
      vulnerabilities.push(...vulns);
    }

    return this.prioritizeVulnerabilities(vulnerabilities);
  }

  // Search NVD for vulnerabilities
  async searchNVDVulnerabilities(service) {
    const cacheKey = `nvd_${service.product}_${service.version}`;
    if (this.isValidCache(cacheKey)) {
      return this.cache.get(cacheKey).data;
    }

    try {
      const searchTerms = this.buildNVDSearchTerms(service);
      const response = await axios.get('https://services.nvd.nist.gov/rest/json/cves/2.0', {
        params: {
          keywordSearch: searchTerms,
          resultsPerPage: 20,
          startIndex: 0
        },
        headers: {
          'apiKey': this.nvidApiKey
        },
        timeout: 15000
      });

      const vulnerabilities = response.data.vulnerabilities.map(vuln => {
        const cveData = vuln.cve;
        return {
          cveId: cveData.id,
          description: cveData.descriptions[0]?.value || 'No description',
          severity: this.extractSeverity(vuln),
          score: this.extractCVSSScore(vuln),
          vector: this.extractAttackVector(vuln),
          publishedDate: cveData.published,
          lastModified: cveData.lastModified,
          references: cveData.references || [],
          affectedService: service,
          exploitability: this.assessExploitability(vuln),
          weaponized: this.checkWeaponization(cveData.id)
        };
      });

      this.setCache(cacheKey, vulnerabilities);
      return vulnerabilities;
    } catch (error) {
      console.error(`NVD API error for ${service.product}:`, error.message);
      return [];
    }
  }

  // Build NVD search terms from service information
  buildNVDSearchTerms(service) {
    const terms = [];
    if (service.product && service.product !== 'unknown') {
      terms.push(service.product);
    }
    if (service.version && service.version !== 'unknown') {
      terms.push(service.version);
    }
    return terms.join(' ');
  }

  // Extract services from scan results
  extractServicesFromScan(scanResults) {
    const services = [];
    
    if (typeof scanResults === 'string') {
      // Parse nmap output
      const lines = scanResults.split('\n');
      lines.forEach(line => {
        const serviceMatch = line.match(/(\d+)\/tcp.*?(\w+).*?(.+)$/);
        if (serviceMatch) {
          const [, port, protocol, serviceInfo] = serviceMatch;
          const productMatch = serviceInfo.match(/^(\w+(?:\s+\w+)?)\s+(.+)$/);
          
          services.push({
            port: parseInt(port),
            protocol,
            product: productMatch ? productMatch[1] : serviceInfo,
            version: productMatch ? productMatch[2] : 'unknown',
            banner: serviceInfo
          });
        }
      });
    }

    return services;
  }

  // Analyze service exposure and attack surface
  async analyzeServiceExposure(scanResults) {
    const services = this.extractServicesFromScan(scanResults);
    const analysis = {
      services: [],
      attackSurface: {
        totalPorts: 0,
        criticalServices: 0,
        webServices: 0,
        databaseServices: 0,
        remoteAccessServices: 0,
        exposureScore: 0
      }
    };

    services.forEach(service => {
      const serviceAnalysis = {
        ...service,
        criticality: this.assessServiceCriticality(service),
        attackVectors: this.getServiceAttackVectors(service),
        riskScore: this.calculateServiceRisk(service),
        recommendations: this.getServiceRecommendations(service)
      };

      analysis.services.push(serviceAnalysis);
      
      // Update attack surface metrics
      analysis.attackSurface.totalPorts++;
      if (serviceAnalysis.criticality.priority === 'critical') {
        analysis.attackSurface.criticalServices++;
      }
      if (['http', 'https'].includes(service.product?.toLowerCase())) {
        analysis.attackSurface.webServices++;
      }
      if (['mysql', 'postgresql', 'mssql'].includes(service.product?.toLowerCase())) {
        analysis.attackSurface.databaseServices++;
      }
      if (['ssh', 'rdp', 'telnet'].includes(service.product?.toLowerCase())) {
        analysis.attackSurface.remoteAccessServices++;
      }
    });

    analysis.attackSurface.exposureScore = this.calculateExposureScore(analysis.attackSurface);
    return analysis;
  }

  // Build comprehensive target profile
  async buildTargetProfile(target, shodanData) {
    const profile = {
      target,
      type: 'unknown',
      organization: 'unknown',
      infrastructure: {},
      geolocation: {},
      hostnames: [],
      businessContext: {},
      threatIntelligence: {}
    };

    if (shodanData) {
      profile.organization = shodanData.org;
      profile.infrastructure = {
        isp: shodanData.isp,
        asn: shodanData.asn,
        services: shodanData.services
      };
      profile.geolocation = {
        country: shodanData.country,
        city: shodanData.city
      };
      profile.hostnames = shodanData.hostnames;
      profile.threatIntelligence = {
        knownVulns: shodanData.vulns,
        tags: shodanData.tags,
        lastUpdate: shodanData.lastUpdate
      };
      
      // Infer target type
      profile.type = this.inferTargetType(shodanData);
    }

    return profile;
  }

  // Infer target type from intelligence data
  inferTargetType(shodanData) {
    const services = shodanData.services || [];
    const tags = shodanData.tags || [];
    
    if (tags.includes('honeypot')) return 'honeypot';
    if (tags.includes('cdn')) return 'cdn';
    if (tags.includes('cloud')) return 'cloud_service';
    
    const webServices = services.filter(s => [80, 443, 8080, 8443].includes(s.port));
    const dbServices = services.filter(s => [3306, 5432, 1433].includes(s.port));
    const remoteServices = services.filter(s => [22, 3389, 23].includes(s.port));
    
    if (webServices.length > 0 && dbServices.length > 0) return 'web_application';
    if (dbServices.length > 0) return 'database_server';
    if (webServices.length > 0) return 'web_server';
    if (remoteServices.length > 0) return 'admin_server';
    
    return 'general_server';
  }

  // Calculate overall risk score
  calculateRiskScore(intelligence) {
    let score = 0;
    
    // Vulnerability scoring
    intelligence.vulnerabilities.forEach(vuln => {
      score += vuln.score || 0;
      if (vuln.exploitability === 'high') score += 20;
      if (vuln.weaponized) score += 30;
    });
    
    // Service exposure scoring
    intelligence.exposedServices.forEach(service => {
      score += service.riskScore || 0;
    });
    
    // Attack surface scoring
    score += intelligence.attackSurface.exposureScore || 0;
    
    // Target type scoring
    const typeModifiers = {
      'honeypot': -50, // Reduce score for honeypots
      'web_application': 30,
      'database_server': 40,
      'admin_server': 35
    };
    score += typeModifiers[intelligence.targetProfile.type] || 0;
    
    return Math.min(Math.max(score, 0), 100); // Clamp between 0-100
  }

  // Determine threat level from risk score
  determineThreatLevel(riskScore) {
    if (riskScore >= 80) return 'critical';
    if (riskScore >= 60) return 'high';
    if (riskScore >= 40) return 'medium';
    if (riskScore >= 20) return 'low';
    return 'minimal';
  }

  // Generate strategic recommendations
  async generateStrategicRecommendations(intelligence) {
    const recommendations = [];
    
    // High-value target recommendations
    if (intelligence.riskScore >= 70) {
      recommendations.push({
        priority: 'critical',
        category: 'targeting',
        action: 'Priority Target Assessment',
        description: 'High-value target identified. Prioritize comprehensive assessment.',
        techniques: ['deep_enumeration', 'vulnerability_validation', 'exploit_development']
      });
    }
    
    // Vulnerability-based recommendations
    const criticalVulns = intelligence.vulnerabilities.filter(v => v.severity === 'critical');
    if (criticalVulns.length > 0) {
      recommendations.push({
        priority: 'critical',
        category: 'exploitation',
        action: 'Critical Vulnerability Exploitation',
        description: `${criticalVulns.length} critical vulnerabilities detected. Immediate exploitation recommended.`,
        techniques: ['exploit_validation', 'payload_customization', 'privilege_escalation'],
        cves: criticalVulns.map(v => v.cveId)
      });
    }
    
    // Service-specific recommendations
    const criticalServices = intelligence.exposedServices.filter(s => s.criticality.priority === 'critical');
    if (criticalServices.length > 0) {
      recommendations.push({
        priority: 'high',
        category: 'service_exploitation',
        action: 'Critical Service Assessment',
        description: `${criticalServices.length} critical services exposed. Detailed analysis required.`,
        techniques: ['service_enumeration', 'credential_attacks', 'service_exploitation'],
        services: criticalServices.map(s => `${s.product}:${s.port}`)
      });
    }
    
    // Reconnaissance recommendations
    if (intelligence.targetProfile.hostnames.length > 1) {
      recommendations.push({
        priority: 'medium',
        category: 'reconnaissance',
        action: 'Expanded Target Mapping',
        description: 'Multiple hostnames detected. Expand reconnaissance scope.',
        techniques: ['subdomain_enumeration', 'dns_bruteforcing', 'certificate_transparency'],
        targets: intelligence.targetProfile.hostnames
      });
    }
    
    return recommendations;
  }

  // Generate next autonomous actions
  async generateNextActions(intelligence) {
    const actions = [];
    
    // Immediate high-priority actions
    if (intelligence.threatLevel === 'critical') {
      actions.push({
        phase: 'immediate',
        action: 'vulnerability_validation',
        priority: 1,
        description: 'Validate critical vulnerabilities for immediate exploitation',
        tools: ['metasploit', 'custom_exploits'],
        parameters: {
          targets: intelligence.vulnerabilities.filter(v => v.severity === 'critical'),
          timeout: 300
        }
      });
    }
    
    // Service enumeration actions
    const webServices = intelligence.exposedServices.filter(s => ['http', 'https'].includes(s.product?.toLowerCase()));
    if (webServices.length > 0) {
      actions.push({
        phase: 'enumeration',
        action: 'web_application_analysis',
        priority: 2,
        description: 'Deep analysis of web applications',
        tools: ['burpsuite', 'dirb', 'nikto'],
        parameters: {
          urls: webServices.map(s => `${s.product}://${intelligence.target}:${s.port}`),
          depth: 'deep'
        }
      });
    }
    
    // Database service actions
    const dbServices = intelligence.exposedServices.filter(s => 
      ['mysql', 'postgresql', 'mssql'].includes(s.product?.toLowerCase())
    );
    if (dbServices.length > 0) {
      actions.push({
        phase: 'enumeration',
        action: 'database_enumeration',
        priority: 3,
        description: 'Database service enumeration and attack',
        tools: ['sqlmap', 'metasploit'],
        parameters: {
          services: dbServices,
          techniques: ['credential_brute_force', 'sql_injection', 'privilege_escalation']
        }
      });
    }
    
    // Credential attacks
    const authServices = intelligence.exposedServices.filter(s => 
      ['ssh', 'rdp', 'ftp'].includes(s.product?.toLowerCase())
    );
    if (authServices.length > 0) {
      actions.push({
        phase: 'access',
        action: 'credential_attacks',
        priority: 4,
        description: 'Credential-based attacks on authentication services',
        tools: ['hydra', 'medusa', 'metasploit'],
        parameters: {
          services: authServices,
          wordlists: ['common_passwords', 'targeted_wordlist'],
          techniques: ['brute_force', 'credential_stuffing']
        }
      });
    }
    
    // Continuous monitoring
    actions.push({
      phase: 'monitoring',
      action: 'target_monitoring',
      priority: 10,
      description: 'Continuous target monitoring for changes',
      tools: ['custom_monitor'],
      parameters: {
        interval: 3600, // 1 hour
        changes_to_track: ['new_services', 'vulnerability_patches', 'configuration_changes']
      }
    });
    
    return actions.sort((a, b) => a.priority - b.priority);
  }

  // Utility methods for scoring and assessment
  assessServiceCriticality(service) {
    const productLower = service.product?.toLowerCase() || '';
    return this.serviceCriticality[productLower] || { priority: 'low', attack_vectors: ['reconnaissance'] };
  }

  getServiceAttackVectors(service) {
    const criticality = this.assessServiceCriticality(service);
    return criticality.attack_vectors;
  }

  calculateServiceRisk(service) {
    const criticality = this.assessServiceCriticality(service);
    const priorityScores = { critical: 30, high: 20, medium: 10, low: 5 };
    return priorityScores[criticality.priority] || 0;
  }

  getServiceRecommendations(service) {
    const recommendations = [];
    const productLower = service.product?.toLowerCase() || '';
    
    const serviceRecommendations = {
      'ssh': ['Use key-based authentication', 'Disable root login', 'Change default port'],
      'http': ['Implement HTTPS', 'Use security headers', 'Regular security testing'],
      'ftp': ['Replace with SFTP', 'Disable if unnecessary', 'Strong authentication'],
      'smb': ['Restrict to internal networks', 'Update to latest version', 'Strong authentication'],
      'mysql': ['Remove from internet exposure', 'Strong passwords', 'Regular updates'],
      'rdp': ['Use VPN access only', 'Strong passwords', 'Account lockout policies']
    };
    
    return serviceRecommendations[productLower] || ['Follow security best practices'];
  }

  calculateExposureScore(attackSurface) {
    let score = 0;
    score += attackSurface.totalPorts * 2;
    score += attackSurface.criticalServices * 15;
    score += attackSurface.webServices * 5;
    score += attackSurface.databaseServices * 20;
    score += attackSurface.remoteAccessServices * 10;
    return Math.min(score, 100);
  }

  // Extract vulnerability severity and scoring
  extractSeverity(vuln) {
    const metrics = vuln.cve?.metrics;
    if (metrics?.cvssMetricV31?.[0]?.cvssData?.baseSeverity) {
      return metrics.cvssMetricV31[0].cvssData.baseSeverity.toLowerCase();
    }
    if (metrics?.cvssMetricV30?.[0]?.cvssData?.baseSeverity) {
      return metrics.cvssMetricV30[0].cvssData.baseSeverity.toLowerCase();
    }
    return 'unknown';
  }

  extractCVSSScore(vuln) {
    const metrics = vuln.cve?.metrics;
    if (metrics?.cvssMetricV31?.[0]?.cvssData?.baseScore) {
      return metrics.cvssMetricV31[0].cvssData.baseScore;
    }
    if (metrics?.cvssMetricV30?.[0]?.cvssData?.baseScore) {
      return metrics.cvssMetricV30[0].cvssData.baseScore;
    }
    return 0;
  }

  extractAttackVector(vuln) {
    const metrics = vuln.cve?.metrics;
    if (metrics?.cvssMetricV31?.[0]?.cvssData?.attackVector) {
      return metrics.cvssMetricV31[0].cvssData.attackVector;
    }
    return 'unknown';
  }

  assessExploitability(vuln) {
    const score = this.extractCVSSScore(vuln);
    const vector = this.extractAttackVector(vuln);
    
    if (score >= 9.0 && vector === 'NETWORK') return 'high';
    if (score >= 7.0 && vector === 'NETWORK') return 'medium';
    if (score >= 4.0) return 'low';
    return 'minimal';
  }

  checkWeaponization(cveId) {
    // Simple check - in real implementation, check against exploit databases
    const knownWeaponized = [
      'CVE-2021-44228', // Log4j
      'CVE-2017-0144', // EternalBlue
      'CVE-2019-0708', // BlueKeep
    ];
    return knownWeaponized.includes(cveId);
  }

  prioritizeVulnerabilities(vulnerabilities) {
    return vulnerabilities.sort((a, b) => {
      // Sort by exploitability, then score, then weaponization
      const aScore = (a.score || 0) + (a.exploitability === 'high' ? 20 : 0) + (a.weaponized ? 30 : 0);
      const bScore = (b.score || 0) + (b.exploitability === 'high' ? 20 : 0) + (b.weaponized ? 30 : 0);
      return bScore - aScore;
    });
  }

  // Cache management
  setCache(key, data) {
    this.cache.set(key, {
      data,
      timestamp: Date.now()
    });
  }

  isValidCache(key) {
    const cached = this.cache.get(key);
    return cached && (Date.now() - cached.timestamp) < this.CACHE_TTL;
  }

  // Clean up expired cache entries
  cleanupCache() {
    const now = Date.now();
    for (const [key, value] of this.cache.entries()) {
      if (now - value.timestamp > this.CACHE_TTL) {
        this.cache.delete(key);
      }
    }
  }
}

// Singleton instance
const threatIntelligence = new ThreatIntelligenceEngine();

// Schedule cache cleanup
setInterval(() => {
  threatIntelligence.cleanupCache();
}, 60 * 60 * 1000); // Every hour

module.exports = {
  ThreatIntelligenceEngine,
  threatIntelligence
}; 