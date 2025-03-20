const express = require('express');
const router = express.Router();
const os = require('os');

// Server start time to calculate uptime
const serverStartTime = Date.now();

// Request counters for each endpoint
let requestCounts = {
    dns: 0,
    network: 0,
    security: 0,
    tech: 0,
    shodan: 0,
    health: 0,
    total: 0
};

// Store response times (last 100)
const responseTimes = [];
const MAX_RESPONSE_TIMES = 100;

// Track response times per endpoint
const endpointResponseTimes = {
    dns: [],
    network: [],
    security: [],
    tech: [],
    shodan: [],
    health: []
};
const MAX_ENDPOINT_TIMES = 50;

// Store historical data for charts
const historicalData = {
    requests: [],
    responseTime: [],
    timestamp: []
};

// Record request middleware
const recordRequest = (endpoint) => (req, res, next) => {
    const startTime = Date.now();
    
    // Record response time after the request is complete
    res.on('finish', () => {
        const duration = Date.now() - startTime;
        
        responseTimes.push(duration);
        if (responseTimes.length > MAX_RESPONSE_TIMES) {
            responseTimes.shift();
        }
        
        // Record endpoint-specific response time
        if (endpointResponseTimes[endpoint]) {
            endpointResponseTimes[endpoint].push(duration);
            if (endpointResponseTimes[endpoint].length > MAX_ENDPOINT_TIMES) {
                endpointResponseTimes[endpoint].shift();
            }
        }
        
        // Increment request counter
        requestCounts[endpoint]++;
        requestCounts.total++;
        
        // Every minute, store historical data
        const now = new Date();
        if (now.getSeconds() === 0) {
            historicalData.requests.push(requestCounts.total);
            historicalData.responseTime.push(calculateAverageResponseTime());
            historicalData.timestamp.push(now.toISOString());
            
            // Keep only the last 24 hours of data
            if (historicalData.timestamp.length > 1440) { // 60 minutes * 24 hours
                historicalData.requests.shift();
                historicalData.responseTime.shift();
                historicalData.timestamp.shift();
            }
        }
    });
    
    next();
};

// Calculate average response time
const calculateAverageResponseTime = () => {
    if (responseTimes.length === 0) return 0;
    const sum = responseTimes.reduce((a, b) => a + b, 0);
    return Math.round(sum / responseTimes.length);
};

// Calculate average response time for a specific endpoint
const calculateEndpointResponseTime = (endpoint) => {
    if (!endpointResponseTimes[endpoint] || endpointResponseTimes[endpoint].length === 0) return 0;
    const sum = endpointResponseTimes[endpoint].reduce((a, b) => a + b, 0);
    return Math.round(sum / endpointResponseTimes[endpoint].length);
};

// Get server metrics
router.get('/', (req, res) => {
    const uptime = Date.now() - serverStartTime;
    
    // Get system information
    const totalMem = os.totalmem();
    const freeMem = os.freemem();
    const memUsage = Math.round(((totalMem - freeMem) / totalMem) * 100);
    const cpuLoad = os.loadavg()[0]; // 1 minute load average
    
    // Calculate endpoint statistics
    const endpointStats = {};
    for (const endpoint in endpointResponseTimes) {
        endpointStats[endpoint] = {
            status: 'up',
            avgResponseTime: calculateEndpointResponseTime(endpoint),
            requestCount: requestCounts[endpoint],
            responseTimeHistory: endpointResponseTimes[endpoint].slice(-10)
        };
    }
    
    res.json({
        status: 'healthy',
        uptime: Math.floor(uptime / 1000), // in seconds
        memory: {
            total: totalMem,
            free: freeMem,
            used: totalMem - freeMem,
            usagePercent: memUsage
        },
        cpu: {
            load: cpuLoad,
            cores: os.cpus().length
        },
        requests: requestCounts,
        responseTime: {
            current: calculateAverageResponseTime(),
            history: responseTimes.slice(-10) // last 10 response times
        },
        endpoints: endpointStats,
        historicalData: {
            requests: historicalData.requests.slice(-24), // Last 24 data points
            responseTime: historicalData.responseTime.slice(-24),
            timestamp: historicalData.timestamp.slice(-24)
        }
    });
});

// Reset metrics (for testing)
router.post('/reset', (req, res) => {
    requestCounts = {
        dns: 0,
        network: 0,
        security: 0,
        tech: 0,
        shodan: 0,
        health: 0,
        total: 0
    };
    
    responseTimes.length = 0;
    
    for (const endpoint in endpointResponseTimes) {
        endpointResponseTimes[endpoint] = [];
    }
    
    res.json({ message: 'Metrics reset successfully' });
});

module.exports = {
    router,
    recordRequest
}; 