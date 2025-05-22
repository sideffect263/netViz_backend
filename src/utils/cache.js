/**
 * Simple in-memory cache implementation for storing recent scan results
 */

// Cache configuration
const MAX_CACHE_SIZE = 100; // Maximum number of items to store in cache

// Cache storage
const cache = new Map();
const cacheTimestamps = new Map();
const cacheExpirations = new Map();

// Cache metrics
let hits = 0;
let misses = 0;

/**
 * Get appropriate TTL based on data type
 * @param {string} key - Cache key
 * @param {number} defaultTTL - Default TTL to use if no specific rule matches
 * @returns {number} - TTL in milliseconds
 */
const getTTL = (key, defaultTTL = 30 * 60 * 1000) => {
  // Different TTLs based on data type to reduce API calls
  if (key.startsWith('dns:') || key.startsWith('ptr:')) {
    return 3 * 60 * 60 * 1000; // 3 hours for DNS records
  } else if (key.startsWith('ssl:') || key.startsWith('headers:')) {
    return 2 * 60 * 60 * 1000; // 2 hours for security checks
  } else if (key.startsWith('tech:')) {
    return 12 * 60 * 60 * 1000; // 12 hours for tech detection
  } else if (key.startsWith('shodan:')) {
    return 24 * 60 * 60 * 1000; // 24 hours for Shodan data (to avoid hitting API limits)
  }
  return defaultTTL; // Default TTL for everything else
};

/**
 * Store a value in the cache with the specified key
 * @param {string} key - Cache key
 * @param {any} value - Value to store
 * @param {number} ttl - Time to live in milliseconds (optional, uses smart defaults)
 */
const set = (key, value, ttl) => {
  // Use smart TTL if not explicitly provided
  if (!ttl) {
    ttl = getTTL(key);
  }
  
  // Clear any existing timeout for this key
  if (cacheExpirations.has(key)) {
    clearTimeout(cacheExpirations.get(key));
    cacheExpirations.delete(key);
  }
  
  // Enforce cache size limits
  if (cache.size >= MAX_CACHE_SIZE && !cache.has(key)) {
    // Find and remove oldest entry if we're at capacity
    let oldestKey = null;
    let oldestTime = Date.now();
    
    for (const [existingKey, timestamp] of cacheTimestamps.entries()) {
      if (timestamp < oldestTime) {
        oldestTime = timestamp;
        oldestKey = existingKey;
      }
    }
    
    if (oldestKey) {
      cache.delete(oldestKey);
      cacheTimestamps.delete(oldestKey);
      if (cacheExpirations.has(oldestKey)) {
        clearTimeout(cacheExpirations.get(oldestKey));
        cacheExpirations.delete(oldestKey);
      }
    }
  }
  
  // Store value and timestamp
  cache.set(key, value);
  cacheTimestamps.set(key, Date.now());
  
  // Set expiration timeout
  const expTimeout = setTimeout(() => {
    if (cache.has(key)) {
      cache.delete(key);
      cacheTimestamps.delete(key);
      cacheExpirations.delete(key);
    }
  }, ttl);
  
  cacheExpirations.set(key, expTimeout);
};

/**
 * Retrieve a value from the cache
 * @param {string} key - Cache key
 * @returns {any|null} - The cached value or null if not found
 */
const get = (key) => {
  if (cache.has(key)) {
    // Update timestamp on access to implement LRU behavior
    cacheTimestamps.set(key, Date.now());
    hits++;
    return cache.get(key);
  }
  misses++;
  return null;
};

/**
 * Check if a key exists in the cache
 * @param {string} key - Cache key
 * @returns {boolean} - True if the key exists
 */
const has = (key) => {
  return cache.has(key);
};

/**
 * Remove a specific key from the cache
 * @param {string} key - Cache key
 */
const invalidate = (key) => {
  cache.delete(key);
  cacheTimestamps.delete(key);
  
  if (cacheExpirations.has(key)) {
    clearTimeout(cacheExpirations.get(key));
    cacheExpirations.delete(key);
  }
};

/**
 * Clear the entire cache
 */
const clear = () => {
  // Clear all timeouts
  for (const timeout of cacheExpirations.values()) {
    clearTimeout(timeout);
  }
  
  cache.clear();
  cacheTimestamps.clear();
  cacheExpirations.clear();
  
  console.log('Cache cleared');
};

/**
 * Get cache statistics
 * @returns {Object} - Cache stats including size and hit rate
 */
const getStats = () => {
  const total = hits + misses;
  const hitRate = total > 0 ? (hits / total) * 100 : 0;
  
  return {
    size: cache.size,
    hits,
    misses,
    hitRate: `${hitRate.toFixed(2)}%`,
    keys: Array.from(cache.keys()),
    oldestKey: getOldestKey()
  };
};

/**
 * Get the oldest key in the cache
 * @returns {string|null} - Oldest key or null if cache is empty
 */
const getOldestKey = () => {
  if (cache.size === 0) {
    return null;
  }
  
  let oldestKey = null;
  let oldestTime = Date.now();
  
  for (const [key, timestamp] of cacheTimestamps.entries()) {
    if (timestamp < oldestTime) {
      oldestTime = timestamp;
      oldestKey = key;
    }
  }
  
  return oldestKey;
};

module.exports = {
  set,
  get,
  has,
  invalidate,
  clear,
  getStats
}; 