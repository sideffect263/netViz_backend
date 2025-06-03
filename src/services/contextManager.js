// Context Manager for AI Agent Session Persistence
class ContextManager {
  constructor() {
    this.sessionContexts = new Map();
    this.CONTEXT_TTL = 60 * 60 * 1000; // 1 hour
    this.MAX_CONTEXT_ENTRIES = 50; // Limit memory usage
  }

  // Initialize or get context for a session
  getSessionContext(sessionId) {
    if (!this.sessionContexts.has(sessionId)) {
      this.sessionContexts.set(sessionId, {
        conversationHistory: [],
        userPreferences: {},
        frequentTargets: new Set(),
        lastActivity: Date.now(),
        sessionStartTime: Date.now(),
        totalInteractions: 0,
        commonIntents: new Map(),
        securityContext: {
          lastScanTargets: [],
          preferredScanTypes: [],
          securityLevel: 'standard'
        }
      });
    }
    
    const context = this.sessionContexts.get(sessionId);
    context.lastActivity = Date.now();
    return context;
  }

  // Add a conversation turn to context
  addConversationTurn(sessionId, userMessage, assistantResponse, analysis) {
    const context = this.getSessionContext(sessionId);
    
    // Add to conversation history
    context.conversationHistory.push({
      timestamp: Date.now(),
      userMessage,
      assistantResponse,
      intent: analysis?.intent,
      confidence: analysis?.confidence,
      toolsUsed: analysis?.suggestedTools || [],
      targets: analysis?.targets || []
    });

    // Limit history size
    if (context.conversationHistory.length > this.MAX_CONTEXT_ENTRIES) {
      context.conversationHistory = context.conversationHistory.slice(-this.MAX_CONTEXT_ENTRIES);
    }

    // Update statistics
    context.totalInteractions++;
    
    // Track common intents
    if (analysis?.intent) {
      const intentCount = context.commonIntents.get(analysis.intent) || 0;
      context.commonIntents.set(analysis.intent, intentCount + 1);
    }

    // Track frequent targets
    if (analysis?.targets) {
      analysis.targets.forEach(target => {
        context.frequentTargets.add(target);
      });
    }

    // Update security context
    if (analysis?.targets && analysis.targets.length > 0) {
      context.securityContext.lastScanTargets = [
        ...analysis.targets,
        ...context.securityContext.lastScanTargets.slice(0, 9) // Keep last 10
      ].slice(0, 10);
    }

    if (analysis?.intent && analysis.intent.includes('scan')) {
      const scanType = this.extractScanType(analysis);
      if (scanType) {
        context.securityContext.preferredScanTypes.unshift(scanType);
        context.securityContext.preferredScanTypes = 
          [...new Set(context.securityContext.preferredScanTypes)].slice(0, 5);
      }
    }
  }

  // Extract scan type from analysis
  extractScanType(analysis) {
    if (analysis.flags?.includes('-F')) return 'quick';
    if (analysis.flags?.includes('-sV')) return 'service';
    if (analysis.complexity === 'high') return 'comprehensive';
    if (analysis.intent === 'vulnerability_scan') return 'vulnerability';
    return 'standard';
  }

  // Get contextual insights for the current session
  getContextualInsights(sessionId) {
    const context = this.getSessionContext(sessionId);
    
    const insights = {
      sessionDuration: Date.now() - context.sessionStartTime,
      totalInteractions: context.totalInteractions,
      mostCommonIntent: this.getMostCommonIntent(context),
      frequentTargets: Array.from(context.frequentTargets).slice(0, 5),
      preferredScanTypes: context.securityContext.preferredScanTypes,
      recentActivity: this.getRecentActivity(context),
      conversationFlow: this.analyzeConversationFlow(context)
    };

    return insights;
  }

  // Get most common intent
  getMostCommonIntent(context) {
    if (context.commonIntents.size === 0) return null;
    
    let maxCount = 0;
    let mostCommon = null;
    
    for (const [intent, count] of context.commonIntents.entries()) {
      if (count > maxCount) {
        maxCount = count;
        mostCommon = intent;
      }
    }
    
    return { intent: mostCommon, count: maxCount };
  }

  // Get recent activity summary
  getRecentActivity(context) {
    const recentTurns = context.conversationHistory.slice(-5);
    return recentTurns.map(turn => ({
      intent: turn.intent,
      targets: turn.targets,
      toolsUsed: turn.toolsUsed,
      timestamp: turn.timestamp
    }));
  }

  // Analyze conversation flow patterns
  analyzeConversationFlow(context) {
    if (context.conversationHistory.length < 2) return null;
    
    const patterns = {
      followUpQuestions: 0,
      toolUsageProgression: [],
      targetConsistency: this.analyzeTargetConsistency(context),
      intentProgression: []
    };

    // Analyze follow-up patterns
    for (let i = 1; i < context.conversationHistory.length; i++) {
      const current = context.conversationHistory[i];
      const previous = context.conversationHistory[i - 1];
      
      if (current.intent === 'follow_up_question' || 
          (current.targets.length > 0 && 
           current.targets.some(t => previous.targets.includes(t)))) {
        patterns.followUpQuestions++;
      }
      
      patterns.intentProgression.push({
        from: previous.intent,
        to: current.intent,
        timestamp: current.timestamp
      });
    }

    return patterns;
  }

  // Analyze target consistency
  analyzeTargetConsistency(context) {
    const allTargets = context.conversationHistory
      .flatMap(turn => turn.targets)
      .filter(target => target);
    
    if (allTargets.length === 0) return null;
    
    const targetCounts = {};
    allTargets.forEach(target => {
      targetCounts[target] = (targetCounts[target] || 0) + 1;
    });
    
    const repeatedTargets = Object.entries(targetCounts)
      .filter(([_, count]) => count > 1)
      .map(([target, count]) => ({ target, count }));
    
    return {
      totalUniqueTargets: Object.keys(targetCounts).length,
      repeatedTargets,
      focusedAnalysis: repeatedTargets.length > 0
    };
  }

  // Generate context-aware suggestions
  generateContextualSuggestions(sessionId, currentAnalysis) {
    const context = this.getSessionContext(sessionId);
    const insights = this.getContextualInsights(sessionId);
    const suggestions = [];

    // Suggest based on frequent targets
    if (insights.frequentTargets.length > 0 && currentAnalysis.targets.length === 0) {
      suggestions.push({
        type: 'target_suggestion',
        message: `You've previously analyzed: ${insights.frequentTargets.join(', ')}. Would you like to continue with any of these?`,
        targets: insights.frequentTargets
      });
    }

    // Suggest based on preferred scan types
    if (currentAnalysis.intent === 'network_scan' && insights.preferredScanTypes.length > 0) {
      const preferredType = insights.preferredScanTypes[0];
      suggestions.push({
        type: 'scan_type_suggestion',
        message: `Based on your previous preferences, you often use ${preferredType} scans. Would you like me to use similar parameters?`,
        scanType: preferredType
      });
    }

    // Suggest follow-up analysis
    if (context.conversationHistory.length > 0) {
      const lastTurn = context.conversationHistory[context.conversationHistory.length - 1];
      if (lastTurn.toolsUsed.includes('NmapScanner') && !lastTurn.toolsUsed.includes('OSINTOverview')) {
        suggestions.push({
          type: 'follow_up_suggestion',
          message: 'Would you like me to perform additional OSINT analysis on the same targets?',
          suggestedTools: ['OSINTOverview'],
          targets: lastTurn.targets
        });
      }
    }

    return suggestions;
  }

  // Clean up expired contexts
  cleanupExpiredContexts() {
    const now = Date.now();
    const expiredSessions = [];
    
    for (const [sessionId, context] of this.sessionContexts.entries()) {
      if (now - context.lastActivity > this.CONTEXT_TTL) {
        expiredSessions.push(sessionId);
      }
    }
    
    expiredSessions.forEach(sessionId => {
      this.sessionContexts.delete(sessionId);
      console.log(`Cleaned up expired context for session: ${sessionId}`);
    });
    
    return expiredSessions.length;
  }

  // Get session statistics
  getSessionStats(sessionId) {
    const context = this.getSessionContext(sessionId);
    const insights = this.getContextualInsights(sessionId);
    
    return {
      sessionId,
      startTime: new Date(context.sessionStartTime).toISOString(),
      duration: insights.sessionDuration,
      totalInteractions: insights.totalInteractions,
      mostCommonIntent: insights.mostCommonIntent,
      uniqueTargetsAnalyzed: insights.frequentTargets.length,
      preferredScanTypes: insights.preferredScanTypes,
      lastActivity: new Date(context.lastActivity).toISOString()
    };
  }

  // Export context for persistence (if needed)
  exportContext(sessionId) {
    const context = this.sessionContexts.get(sessionId);
    if (!context) return null;
    
    return {
      sessionId,
      ...context,
      exportedAt: Date.now()
    };
  }

  // Import context from persistence (if needed)
  importContext(sessionId, contextData) {
    if (contextData && contextData.sessionId === sessionId) {
      this.sessionContexts.set(sessionId, {
        ...contextData,
        lastActivity: Date.now() // Update activity time
      });
      return true;
    }
    return false;
  }
}

// Singleton instance
const contextManager = new ContextManager();

// Schedule periodic cleanup
setInterval(() => {
  const cleaned = contextManager.cleanupExpiredContexts();
  if (cleaned > 0) {
    console.log(`Context cleanup: removed ${cleaned} expired sessions`);
  }
}, 15 * 60 * 1000); // Every 15 minutes

module.exports = {
  ContextManager,
  contextManager
}; 