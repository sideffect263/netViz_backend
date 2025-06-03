const fs = require('fs');
const path = require('path');

class TargetIntelligenceService {
  constructor() {
    this.targetCache = new Map();
    this.sessionTargets = new Map(); // Track targets per session
    this.cacheTTL = 24 * 60 * 60 * 1000; // 24 hours
    this.dataPath = path.join(__dirname, '../../data/target_intelligence.json');
    
    // Load existing data on startup
    this.loadPersistedData();
    
    // Cleanup expired data every hour
    setInterval(() => this.cleanupExpiredData(), 60 * 60 * 1000);
  }

  // Load target intelligence data from file
  loadPersistedData() {
    try {
      if (fs.existsSync(this.dataPath)) {
        const data = JSON.parse(fs.readFileSync(this.dataPath, 'utf8'));
        if (data.targets) {
          this.targetCache = new Map(Object.entries(data.targets));
        }
        console.log(`Loaded ${this.targetCache.size} target intelligence records`);
      }
    } catch (error) {
      console.error('Error loading target intelligence data:', error);
    }
  }

  // Persist target intelligence data to file
  persistData() {
    try {
      const dataDir = path.dirname(this.dataPath);
      if (!fs.existsSync(dataDir)) {
        fs.mkdirSync(dataDir, { recursive: true });
      }
      
      const data = {
        targets: Object.fromEntries(this.targetCache),
        lastUpdated: new Date().toISOString()
      };
      
      fs.writeFileSync(this.dataPath, JSON.stringify(data, null, 2));
    } catch (error) {
      console.error('Error persisting target intelligence data:', error);
    }
  }

  // Add or update target intelligence
  updateTarget(sessionId, targetId, targetData) {
    const now = Date.now();
    const existingTarget = this.targetCache.get(targetId) || {
      target: targetId,
      type: this.detectTargetType(targetId),
      status: 'discovered',
      firstSeen: new Date().toISOString(),
      lastActivity: new Date().toISOString(),
      services: [],
      vulnerabilities: [],
      exploitAttempts: [],
      riskScore: 0,
      phase: 'reconnaissance',
      sessions: new Set(),
      intelligence: {
        organization: null,
        geolocation: null,
        technologies: [],
        certificates: []
      },
      metadata: {
        created: now,
        updated: now
      }
    };

    // Merge new data
    const updatedTarget = {
      ...existingTarget,
      ...targetData,
      lastActivity: new Date().toISOString(),
      metadata: {
        ...existingTarget.metadata,
        updated: now
      }
    };

    // Add session tracking
    if (!updatedTarget.sessions) {
      updatedTarget.sessions = new Set();
    }
    updatedTarget.sessions.add(sessionId);

    // Update services intelligently (avoid duplicates)
    if (targetData.services) {
      const existingPorts = new Set(existingTarget.services.map(s => s.port));
      const newServices = targetData.services.filter(s => !existingPorts.has(s.port));
      updatedTarget.services = [...existingTarget.services, ...newServices];
    }

    // Update exploit attempts
    if (targetData.exploitAttempts) {
      updatedTarget.exploitAttempts = [
        ...existingTarget.exploitAttempts,
        ...targetData.exploitAttempts
      ];
    }

    // Recalculate risk score
    updatedTarget.riskScore = this.calculateRiskScore(updatedTarget);

    this.targetCache.set(targetId, updatedTarget);
    
    // Track targets for this session
    if (!this.sessionTargets.has(sessionId)) {
      this.sessionTargets.set(sessionId, new Set());
    }
    this.sessionTargets.get(sessionId).add(targetId);

    // Persist changes
    this.persistData();

    return updatedTarget;
  }

  // Get target intelligence for a specific target
  getTarget(targetId) {
    return this.targetCache.get(targetId);
  }

  // Get all targets for a session
  getSessionTargets(sessionId) {
    const sessionTargetIds = this.sessionTargets.get(sessionId) || new Set();
    return Array.from(sessionTargetIds)
      .map(targetId => this.targetCache.get(targetId))
      .filter(Boolean)
      .sort((a, b) => b.riskScore - a.riskScore);
  }

  // Get all targets across all sessions
  getAllTargets() {
    return Array.from(this.targetCache.values())
      .sort((a, b) => b.riskScore - a.riskScore);
  }

  // Track scanning activity
  trackScanActivity(sessionId, targetId, scanData) {
    const target = this.getTarget(targetId) || {};
    
    // Parse services from scan data
    const services = this.parseServicesFromScanData(scanData);
    
    const updateData = {
      status: 'analyzed',
      phase: 'enumeration',
      services: services,
      lastScanData: scanData,
      lastScanTime: new Date().toISOString()
    };

    return this.updateTarget(sessionId, targetId, updateData);
  }

  // Track exploitation attempts
  trackExploitAttempt(sessionId, targetId, exploitData) {
    const target = this.getTarget(targetId) || {};
    
    const exploitAttempt = {
      timestamp: new Date().toISOString(),
      type: 'exploit',
      description: exploitData.description || 'Exploitation attempt',
      status: exploitData.status || 'attempted',
      tool: exploitData.tool || 'unknown',
      sessionId: sessionId
    };

    const updateData = {
      phase: 'exploitation',
      exploitAttempts: [exploitAttempt]
    };

    return this.updateTarget(sessionId, targetId, updateData);
  }

  // Parse services from Nmap scan data
  parseServicesFromScanData(scanData) {
    const services = [];
    const portMatches = scanData.match(/(\d+)\/tcp\s+open\s+([^\s\n]+)/gi);
    
    if (portMatches) {
      portMatches.forEach(match => {
        const portServiceMatch = match.match(/(\d+)\/tcp\s+open\s+([^\s\n]+)/i);
        if (portServiceMatch) {
          const port = portServiceMatch[1];
          const service = portServiceMatch[2];
          
          services.push({
            port,
            service,
            status: 'discovered',
            riskLevel: this.assessServiceRisk(service, port),
            lastChecked: new Date().toISOString(),
            exploitAttempts: []
          });
        }
      });
    }
    
    return services;
  }

  // Assess risk level for a service
  assessServiceRisk(service, port) {
    const highRiskServices = ['ssh', 'rdp', 'telnet', 'ftp', 'mysql', 'postgresql', 'smb'];
    const mediumRiskServices = ['http', 'https', 'smtp', 'dns', 'snmp'];
    const highRiskPorts = ['22', '3389', '23', '21', '3306', '5432', '445'];
    
    if (highRiskServices.includes(service.toLowerCase()) || highRiskPorts.includes(port)) {
      return 'high';
    }
    if (mediumRiskServices.includes(service.toLowerCase())) {
      return 'medium';
    }
    return 'low';
  }

  // Calculate overall risk score for a target
  calculateRiskScore(targetData) {
    let score = 0;
    
    // Base score for having open services
    score += targetData.services.length * 5;
    
    // Risk multiplier based on service types
    targetData.services.forEach(service => {
      switch (service.riskLevel) {
        case 'high': score += 25; break;
        case 'medium': score += 15; break;
        case 'low': score += 5; break;
      }
    });
    
    // Exploitation attempts increase score
    score += targetData.exploitAttempts.length * 10;
    
    // Vulnerability count
    score += targetData.vulnerabilities.length * 15;
    
    return Math.min(100, score);
  }

  // Detect target type (IP or domain)
  detectTargetType(target) {
    const ipRegex = /^(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$/;
    return ipRegex.test(target) ? 'ip' : 'domain';
  }

  // Cleanup expired data
  cleanupExpiredData() {
    const now = Date.now();
    let cleanedCount = 0;
    
    for (const [targetId, target] of this.targetCache.entries()) {
      if (target.metadata && (now - target.metadata.updated) > this.cacheTTL) {
        this.targetCache.delete(targetId);
        cleanedCount++;
      }
    }
    
    if (cleanedCount > 0) {
      console.log(`Cleaned up ${cleanedCount} expired target intelligence records`);
      this.persistData();
    }
  }

  // Get intelligence summary for a session
  getSessionIntelligenceSummary(sessionId) {
    const targets = this.getSessionTargets(sessionId);
    
    return {
      totalTargets: targets.length,
      highRiskTargets: targets.filter(t => t.riskScore >= 70).length,
      totalServices: targets.reduce((sum, t) => sum + t.services.length, 0),
      criticalServices: targets.reduce((sum, t) => 
        sum + t.services.filter(s => s.riskLevel === 'high').length, 0
      ),
      exploitAttempts: targets.reduce((sum, t) => sum + t.exploitAttempts.length, 0),
      averageRiskScore: targets.length > 0 
        ? Math.round(targets.reduce((sum, t) => sum + t.riskScore, 0) / targets.length)
        : 0,
      mostRecentActivity: targets.length > 0
        ? new Date(Math.max(...targets.map(t => new Date(t.lastActivity).getTime())))
        : null
    };
  }

  // Generate suggested next steps based on discovered services
  generateSuggestedActions(sessionId) {
    const targets = this.getSessionTargets(sessionId);
    const suggestions = [];
    
    targets.forEach(target => {
      target.services.forEach(service => {
        switch (service.service.toLowerCase()) {
          case 'http':
          case 'https':
            suggestions.push({
              target: target.target,
              action: 'web_application_scan',
              description: `Perform web application vulnerability scan on ${service.port}/${service.service}`,
              priority: service.riskLevel === 'high' ? 'high' : 'medium',
              tools: ['nikto', 'dirb', 'burpsuite']
            });
            break;
          case 'ssh':
            suggestions.push({
              target: target.target,
              action: 'ssh_enumeration',
              description: `SSH enumeration and authentication testing on port ${service.port}`,
              priority: 'high',
              tools: ['hydra', 'metasploit']
            });
            break;
          case 'mysql':
          case 'postgresql':
            suggestions.push({
              target: target.target,
              action: 'database_enumeration',
              description: `Database enumeration and SQL injection testing on ${service.service}`,
              priority: 'high',
              tools: ['sqlmap', 'metasploit']
            });
            break;
        }
      });
    });
    
    return suggestions.slice(0, 5); // Return top 5 suggestions
  }
}

// Singleton instance
const targetIntelligenceService = new TargetIntelligenceService();

module.exports = { targetIntelligenceService }; 