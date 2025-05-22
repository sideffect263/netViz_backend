const autoHackerService = require('../services/autoHackerService');
const { v4: uuidv4 } = require('uuid');
const path = require('path');

// Define MCP configuration
const MCP_CONFIG = {
  nmap: {
    command: 'node',
    args: [
      path.resolve(process.cwd(), '../nmap-mcp/build/index.js'),
      'nmap'
    ]
  }
};

// Track active scans in memory (in production, use a persistent store like Redis)
const activeScanStore = new Map();

/**
 * Start a new autonomous scan
 */
exports.startScan = async (req, res) => {
  try {
    const { target, scanDepth = 'medium', aiMode = 'defensive' } = req.body;
    console.log(`[API] Starting new scan - Target: ${target}, Depth: ${scanDepth}, AI Mode: ${aiMode}`);

    // Validate input
    if (!target) {
      console.log('[API] Invalid request - Missing target');
      return res.status(400).json({ error: 'Target domain or IP is required' });
    }

    // Create a unique scan ID
    const scanId = uuidv4();
    console.log(`[API] Generated scan ID: ${scanId}`);
    
    // Initialize scan in storage
    const scanData = {
      id: scanId,
      target,
      scanDepth,
      aiMode,
      startTime: new Date(),
      status: 'initializing',
      progress: 0,
      results: null,
      completedStages: [],
      currentStage: 'preparation',
      error: null,
      stageResults: {},
      aiInsights: {}
    };
    
    activeScanStore.set(scanId, scanData);
    console.log(`[API] Scan initialized in storage`);
    
    // Start the scan process asynchronously
    autoHackerService.executeScan(scanId, target, scanDepth, aiMode, activeScanStore)
      .catch(error => {
        console.error(`[API] Error in scan ${scanId}:`, error);
        if (activeScanStore.has(scanId)) {
          const scan = activeScanStore.get(scanId);
          scan.status = 'failed';
          scan.error = error.message;
          activeScanStore.set(scanId, scan);
        }
      });
    
    // Return immediately with the scan ID
    console.log(`[API] Scan ${scanId} initiated successfully`);
    return res.status(202).json({ 
      message: 'Scan initiated successfully', 
      scanId, 
      status: 'initializing' 
    });
  } catch (error) {
    console.error('[API] Error starting scan:', error);
    return res.status(500).json({ error: 'Failed to start scan' });
  }
};

/**
 * Get the status of an ongoing scan
 */
exports.getScanStatus = (req, res) => {
  try {
    const { scanId } = req.params;
    console.log(`[API] Getting status for scan: ${scanId}`);
    
    if (!activeScanStore.has(scanId)) {
      console.log(`[API] Scan ${scanId} not found`);
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    const scan = activeScanStore.get(scanId);
    console.log(`[API] Scan ${scanId} status: ${scan.status}, progress: ${scan.progress}%, stage: ${scan.currentStage}`);
    
    return res.status(200).json({
      scanId,
      status: scan.status,
      progress: scan.progress,
      currentStage: scan.currentStage,
      completedStages: scan.completedStages,
      stageResults: scan.stageResults || {},
      aiInsights: scan.aiInsights || {},
      startTime: scan.startTime,
      endTime: scan.endTime || null
    });
  } catch (error) {
    console.error('[API] Error getting scan status:', error);
    return res.status(500).json({ error: 'Failed to retrieve scan status' });
  }
};

/**
 * Get the results of a completed scan
 */
exports.getScanResults = (req, res) => {
  try {
    const { scanId } = req.params;
    console.log(`[API] Getting results for scan: ${scanId}`);
    
    if (!activeScanStore.has(scanId)) {
      console.log(`[API] Scan ${scanId} not found`);
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    const scan = activeScanStore.get(scanId);
    
    if (scan.status !== 'completed' && scan.status !== 'failed') {
      console.log(`[API] Scan ${scanId} still in progress (${scan.status})`);
      return res.status(400).json({ 
        error: 'Scan is still in progress', 
        status: scan.status,
        progress: scan.progress 
      });
    }
    
    console.log(`[API] Returning results for scan ${scanId}`);
    return res.status(200).json({
      scanId,
      target: scan.target,
      scanDepth: scan.scanDepth,
      aiMode: scan.aiMode,
      status: scan.status,
      startTime: scan.startTime,
      endTime: scan.endTime,
      results: scan.results,
      error: scan.error
    });
  } catch (error) {
    console.error('[API] Error getting scan results:', error);
    return res.status(500).json({ error: 'Failed to retrieve scan results' });
  }
};

/**
 * Get history of scans
 */
exports.getScanHistory = (req, res) => {
  try {
    console.log('[API] Getting scan history');
    // Convert the Map to an array of scan objects
    const scans = Array.from(activeScanStore.values()).map(scan => ({
      id: scan.id,
      target: scan.target,
      status: scan.status,
      progress: scan.progress,
      startTime: scan.startTime,
      endTime: scan.endTime || null,
      scanDepth: scan.scanDepth,
      aiMode: scan.aiMode
    }));
    
    // Sort by start time, most recent first
    scans.sort((a, b) => new Date(b.startTime) - new Date(a.startTime));
    
    console.log(`[API] Returning ${scans.length} scans in history`);
    return res.status(200).json(scans);
  } catch (error) {
    console.error('[API] Error getting scan history:', error);
    return res.status(500).json({ error: 'Failed to retrieve scan history' });
  }
};

/**
 * Cancel a running scan
 */
exports.cancelScan = (req, res) => {
  try {
    const { scanId } = req.params;
    console.log(`[API] Attempting to cancel scan: ${scanId}`);
    
    if (!activeScanStore.has(scanId)) {
      console.log(`[API] Scan ${scanId} not found`);
      return res.status(404).json({ error: 'Scan not found' });
    }
    
    const scan = activeScanStore.get(scanId);
    
    if (scan.status === 'completed' || scan.status === 'failed') {
      console.log(`[API] Cannot cancel scan ${scanId} - already ${scan.status}`);
      return res.status(400).json({ error: 'Cannot cancel a scan that has already completed or failed' });
    }
    
    // Update scan status
    scan.status = 'cancelled';
    scan.endTime = new Date();
    activeScanStore.set(scanId, scan);
    
    // Attempt to stop any running processes
    autoHackerService.cancelScan(scanId);
    console.log(`[API] Scan ${scanId} cancelled successfully`);
    
    return res.status(200).json({ message: 'Scan cancelled successfully' });
  } catch (error) {
    console.error('[API] Error cancelling scan:', error);
    return res.status(500).json({ error: 'Failed to cancel scan' });
  }
}; 