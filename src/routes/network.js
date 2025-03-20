const express = require('express');
const router = express.Router();
const axios = require('axios');
const cheerio = require('cheerio');
const { performance } = require('perf_hooks');
const dns = require('dns').promises;

// Proxy endpoint for network requests analysis
router.post('/analyze', async (req, res) => {
  try {
    const { url } = req.body;
    
    if (!url || !url.match(/^https?:\/\/[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+/)) {
      return res.status(400).json({ error: 'Invalid URL format' });
    }
    
    // Track request performance
    const startTime = performance.now();
    
    const response = await axios.get(url, {
      headers: {
        'User-Agent': 'NetScan360/1.0'
      },
      timeout: 15000 // 15 second timeout
    });
    
    const endTime = performance.now();
    const responseTime = endTime - startTime;
    
    const $ = cheerio.load(response.data);
    
    // Extract resources from HTML
    const resources = {
      scripts: [],
      styles: [],
      images: [],
      iframes: [],
      links: [],
      fonts: []
    };
    
    // Find scripts
    $('script').each((i, el) => {
      const src = $(el).attr('src');
      if (src) {
        resources.scripts.push({
          src,
          async: $(el).attr('async') !== undefined,
          defer: $(el).attr('defer') !== undefined,
          type: $(el).attr('type') || 'text/javascript'
        });
      }
    });
    
    // Find styles
    $('link[rel="stylesheet"]').each((i, el) => {
      const href = $(el).attr('href');
      if (href) resources.styles.push({
        href,
        media: $(el).attr('media') || 'all'
      });
    });
    
    // Find images
    $('img').each((i, el) => {
      const src = $(el).attr('src');
      if (src) resources.images.push({
        src,
        width: $(el).attr('width'),
        height: $(el).attr('height'),
        alt: $(el).attr('alt'),
        loading: $(el).attr('loading') // eager or lazy
      });
    });
    
    // Find iframes
    $('iframe').each((i, el) => {
      const src = $(el).attr('src');
      if (src) resources.iframes.push({
        src,
        title: $(el).attr('title')
      });
    });
    
    // Find links
    $('a').each((i, el) => {
      const href = $(el).attr('href');
      if (href && href.startsWith('http')) resources.links.push(href);
    });
    
    // Find fonts
    $('link[rel="preload"][as="font"]').each((i, el) => {
      const href = $(el).attr('href');
      if (href) resources.fonts.push({
        href,
        type: $(el).attr('type')
      });
    });
    
    // Extract domain from URL
    const urlObj = new URL(url);
    const baseDomain = urlObj.hostname;
    
    // Identify external domains
    const externalDomains = new Set();
    const resourceByDomain = {};
    
    // Helper to process and categorize a resource URL
    const processResourceDomain = (resourceUrl, type) => {
      try {
        let fullUrl = resourceUrl;
        if (!resourceUrl.startsWith('http')) {
          fullUrl = new URL(resourceUrl, url).href;
        }
        
        const resourceUrlObj = new URL(fullUrl);
        const resourceDomain = resourceUrlObj.hostname;
        
        // Track external domains
        if (resourceDomain !== baseDomain) {
          externalDomains.add(resourceDomain);
          
          // Group resources by domain
          if (!resourceByDomain[resourceDomain]) {
            resourceByDomain[resourceDomain] = [];
          }
          
          resourceByDomain[resourceDomain].push({
            type,
            url: fullUrl,
            path: resourceUrlObj.pathname
          });
        }
        
        return {
          url: fullUrl,
          domain: resourceDomain,
          isExternal: resourceDomain !== baseDomain
        };
      } catch (e) {
        return {
          url: resourceUrl,
          isExternal: false,
          error: e.message
        };
      }
    };
    
    // Process all resource types
    const processedResources = {
      scripts: resources.scripts.map(script => ({
        ...script,
        ...processResourceDomain(script.src, 'script')
      })),
      styles: resources.styles.map(style => ({
        ...style,
        ...processResourceDomain(style.href, 'style')
      })),
      images: resources.images.map(image => ({
        ...image,
        ...processResourceDomain(image.src, 'image')
      })),
      iframes: resources.iframes.map(iframe => ({
        ...iframe,
        ...processResourceDomain(iframe.src, 'iframe')
      })),
      fonts: resources.fonts.map(font => ({
        ...font,
        ...processResourceDomain(font.href, 'font')
      }))
    };
    
    // Check for CDN usage
    const headers = response.headers;
    const cdn = await detectCDN(headers, baseDomain);
    
    // Calculate stats
    const totalResources = 
      processedResources.scripts.length + 
      processedResources.styles.length + 
      processedResources.images.length + 
      processedResources.iframes.length +
      processedResources.fonts.length;
    
    // Connection information
    const connectionInfo = {
      protocol: urlObj.protocol,
      responseTime: Math.round(responseTime),
      contentType: headers['content-type'],
      contentLength: headers['content-length'],
      server: headers['server'],
      statusCode: response.status
    };
    
    res.json({
      url,
      baseUrl: `${urlObj.protocol}//${urlObj.hostname}`,
      baseDomain,
      resources: processedResources,
      stats: {
        totalResources,
        externalDomains: Array.from(externalDomains),
        externalDomainsCount: externalDomains.size,
        resourceBreakdown: {
          scripts: processedResources.scripts.length,
          styles: processedResources.styles.length,
          images: processedResources.images.length,
          iframes: processedResources.iframes.length,
          fonts: processedResources.fonts.length
        }
      },
      resourceByDomain,
      cdn,
      connectionInfo,
      headers: response.headers
    });
  } catch (error) {
    console.error('Network analysis error:', error);
    res.status(500).json({ 
      error: 'Failed to analyze network', 
      message: error.message 
    });
  }
});

// Helper function to detect CDN from headers and DNS
async function detectCDN(headers, domain) {
  const headerKeys = Object.keys(headers).map(h => h.toLowerCase());
  const server = headers['server']?.toLowerCase() || '';
  
  // Try to get CNAME records for domain
  let cnameRecords = [];
  try {
    cnameRecords = await dns.resolveCname(domain);
  } catch (e) {
    // No CNAME records or lookup failed
  }
  
  // First check headers for known CDN signatures
  if (headerKeys.includes('cf-ray') || server.includes('cloudflare')) {
    return {
      name: 'Cloudflare',
      headers: {
        'cf-ray': headers['cf-ray'] || 'Unknown',
        'server': headers['server'] || 'Unknown'
      }
    };
  }
  
  if (headerKeys.includes('x-azure-ref') || server.includes('microsoft')) {
    return {
      name: 'Azure CDN',
      headers: {
        'x-azure-ref': headers['x-azure-ref'] || 'Unknown',
        'server': headers['server'] || 'Unknown'
      }
    };
  }
  
  if (headerKeys.includes('x-amz-cf-id') || domain.includes('cloudfront.net') || 
      cnameRecords.some(cname => cname.includes('cloudfront.net'))) {
    return {
      name: 'Amazon CloudFront',
      headers: {
        'x-amz-cf-id': headers['x-amz-cf-id'] || 'Unknown',
        'server': headers['server'] || 'Unknown'
      }
    };
  }
  
  if (server.includes('gws') || cnameRecords.some(cname => 
      cname.includes('googleusercontent.com') || cname.includes('googlevideo.com'))) {
    return {
      name: 'Google Cloud CDN',
      headers: {
        'server': headers['server'] || 'Unknown'
      }
    };
  }
  
  if (headerKeys.includes('x-fastly-request-id') || server.includes('fastly')) {
    return {
      name: 'Fastly',
      headers: {
        'x-fastly-request-id': headers['x-fastly-request-id'] || 'Unknown',
        'server': headers['server'] || 'Unknown'
      }
    };
  }
  
  if (cnameRecords.some(cname => cname.includes('akamaitechnologies.com') || 
      cname.includes('akamaiedge.net'))) {
    return {
      name: 'Akamai',
      headers: {
        'server': headers['server'] || 'Unknown'
      }
    };
  }
  
  return {
    name: 'Unknown',
    headers: {
      'server': headers['server'] || 'Unknown'
    },
    cnameRecords
  };
}

// New route for domain dependency analysis
router.post('/domain-analysis', async (req, res) => {
  try {
    const { url } = req.body;
    
    if (!url || !url.match(/^https?:\/\/[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+/)) {
      return res.status(400).json({ error: 'Invalid URL format' });
    }
    
    // First get basic network analysis
    const urlObj = new URL(url);
    const baseDomain = urlObj.hostname;
    
    const response = await axios.get(url, {
      headers: {
        'User-Agent': 'NetScan360/1.0'
      },
      timeout: 15000
    });
    
    const $ = cheerio.load(response.data);
    
    // Extract all links (internal and external)
    const allLinks = new Set();
    $('a').each((i, el) => {
      const href = $(el).attr('href');
      if (href) {
        try {
          // Handle relative links
          let fullUrl;
          if (href.startsWith('http')) {
            fullUrl = href;
          } else if (href.startsWith('/')) {
            fullUrl = `${urlObj.protocol}//${urlObj.hostname}${href}`;
          } else {
            fullUrl = new URL(href, url).href;
          }
          allLinks.add(fullUrl);
        } catch (e) {
          // Invalid URL, skip
        }
      }
    });
    
    // Create domain relationship map
    const domainMap = {};
    domainMap[baseDomain] = {
      isBaseDomain: true,
      links: [],
      resources: []
    };
    
    // Process all links
    for (const link of allLinks) {
      try {
        const linkUrl = new URL(link);
        const linkDomain = linkUrl.hostname;
        
        if (!domainMap[linkDomain]) {
          domainMap[linkDomain] = {
            isBaseDomain: linkDomain === baseDomain,
            links: [],
            resources: []
          };
        }
        
        // Add link to domain map
        domainMap[linkDomain].links.push({
          url: link,
          path: linkUrl.pathname
        });
        
        // If external, add relationship to base domain
        if (linkDomain !== baseDomain) {
          if (!domainMap[baseDomain].externalDomains) {
            domainMap[baseDomain].externalDomains = [];
          }
          
          if (!domainMap[baseDomain].externalDomains.includes(linkDomain)) {
            domainMap[baseDomain].externalDomains.push(linkDomain);
          }
        }
      } catch (e) {
        // Skip invalid URLs
      }
    }
    
    // Extract resources
    const resources = {
      scripts: [],
      styles: [],
      images: [],
      iframes: []
    };
    
    // Find scripts
    $('script').each((i, el) => {
      const src = $(el).attr('src');
      if (src) resources.scripts.push(src);
    });
    
    // Find styles
    $('link[rel="stylesheet"]').each((i, el) => {
      const href = $(el).attr('href');
      if (href) resources.styles.push(href);
    });
    
    // Find images
    $('img').each((i, el) => {
      const src = $(el).attr('src');
      if (src) resources.images.push(src);
    });
    
    // Find iframes
    $('iframe').each((i, el) => {
      const src = $(el).attr('src');
      if (src) resources.iframes.push(src);
    });
    
    // Add resources to domain map
    const processResource = (resource, type) => {
      try {
        let fullUrl = resource;
        if (!resource.startsWith('http')) {
          fullUrl = new URL(resource, url).href;
        }
        
        const resourceUrl = new URL(fullUrl);
        const resourceDomain = resourceUrl.hostname;
        
        if (!domainMap[resourceDomain]) {
          domainMap[resourceDomain] = {
            isBaseDomain: resourceDomain === baseDomain,
            links: [],
            resources: []
          };
        }
        
        domainMap[resourceDomain].resources.push({
          type,
          url: fullUrl,
          path: resourceUrl.pathname
        });
        
        // If external, add relationship to base domain
        if (resourceDomain !== baseDomain) {
          if (!domainMap[baseDomain].externalDomains) {
            domainMap[baseDomain].externalDomains = [];
          }
          
          if (!domainMap[baseDomain].externalDomains.includes(resourceDomain)) {
            domainMap[baseDomain].externalDomains.push(resourceDomain);
          }
        }
      } catch (e) {
        // Skip invalid URLs
      }
    };
    
    // Process all resources
    resources.scripts.forEach(src => processResource(src, 'script'));
    resources.styles.forEach(href => processResource(href, 'style'));
    resources.images.forEach(src => processResource(src, 'image'));
    resources.iframes.forEach(src => processResource(src, 'iframe'));
    
    // Generate network graph for visualization
    const networkGraph = {
      nodes: [],
      edges: []
    };
    
    // Add nodes (domains)
    Object.keys(domainMap).forEach(domain => {
      networkGraph.nodes.push({
        id: domain,
        label: domain,
        isBaseDomain: domain === baseDomain
      });
    });
    
    // Add edges (connections between domains)
    Object.keys(domainMap).forEach(domain => {
      if (domainMap[domain].externalDomains) {
        domainMap[domain].externalDomains.forEach(target => {
          networkGraph.edges.push({
            from: domain,
            to: target,
            resourceCount: domainMap[target].resources.length
          });
        });
      }
    });
    
    res.json({
      url,
      baseDomain,
      domainMap,
      networkGraph,
      domains: {
        total: Object.keys(domainMap).length,
        external: Object.keys(domainMap).length - 1
      }
    });
  } catch (error) {
    console.error('Domain analysis error:', error);
    res.status(500).json({ 
      error: 'Failed to analyze domain dependencies', 
      message: error.message 
    });
  }
});

// New route for resource metrics and performance assessment
router.post('/performance', async (req, res) => {
  try {
    const { url } = req.body;
    
    if (!url || !url.match(/^https?:\/\/[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+/)) {
      return res.status(400).json({ error: 'Invalid URL format' });
    }
    
    // Start timer for overall performance
    const startTime = performance.now();
    
    // Fetch main page
    const response = await axios.get(url, {
      headers: {
        'User-Agent': 'NetScan360/1.0'
      },
      timeout: 15000
    });
    
    const mainPageEndTime = performance.now();
    const mainPageLoadTime = mainPageEndTime - startTime;
    
    const $ = cheerio.load(response.data);
    const urlObj = new URL(url);
    const baseDomain = urlObj.hostname;
    
    // Extract resources
    const resourceUrls = [];
    
    // Scripts
    $('script').each((i, el) => {
      const src = $(el).attr('src');
      if (src) {
        try {
          let fullUrl = src;
          if (!src.startsWith('http')) {
            fullUrl = new URL(src, url).href;
          }
          resourceUrls.push({
            url: fullUrl,
            type: 'script',
            async: $(el).attr('async') !== undefined,
            defer: $(el).attr('defer') !== undefined
          });
        } catch (e) {}
      }
    });
    
    // Styles
    $('link[rel="stylesheet"]').each((i, el) => {
      const href = $(el).attr('href');
      if (href) {
        try {
          let fullUrl = href;
          if (!href.startsWith('http')) {
            fullUrl = new URL(href, url).href;
          }
          resourceUrls.push({
            url: fullUrl,
            type: 'stylesheet'
          });
        } catch (e) {}
      }
    });
    
    // Images
    $('img').each((i, el) => {
      const src = $(el).attr('src');
      if (src) {
        try {
          let fullUrl = src;
          if (!src.startsWith('http')) {
            fullUrl = new URL(src, url).href;
          }
          resourceUrls.push({
            url: fullUrl,
            type: 'image',
            width: $(el).attr('width'),
            height: $(el).attr('height'),
            loading: $(el).attr('loading')
          });
        } catch (e) {}
      }
    });
    
    // Gather metrics for each resource (limited to first 20 resources)
    const resourcesForAnalysis = resourceUrls.slice(0, 20);
    const resourceMetrics = [];
    
    // Request each resource and track metrics
    for (const resource of resourcesForAnalysis) {
      try {
        const resourceStartTime = performance.now();
        const resourceResponse = await axios.get(resource.url, {
          headers: {
            'User-Agent': 'NetScan360/1.0'
          },
          timeout: 10000,
          // Only get headers to avoid unnecessary data transfer
          method: 'HEAD'
        });
        const resourceEndTime = performance.now();
        
        // Get domain info
        const resourceUrl = new URL(resource.url);
        const resourceDomain = resourceUrl.hostname;
        
        resourceMetrics.push({
          ...resource,
          domain: resourceDomain,
          isExternal: resourceDomain !== baseDomain,
          responseTime: Math.round(resourceEndTime - resourceStartTime),
          statusCode: resourceResponse.status,
          contentType: resourceResponse.headers['content-type'],
          contentLength: parseInt(resourceResponse.headers['content-length'] || '0', 10),
          cacheControl: resourceResponse.headers['cache-control'],
          headers: {
            etag: resourceResponse.headers['etag'],
            lastModified: resourceResponse.headers['last-modified']
          }
        });
      } catch (error) {
        resourceMetrics.push({
          ...resource,
          error: error.message,
          failed: true
        });
      }
    }
    
    // Calculate performance metrics
    const totalResourceSize = resourceMetrics
      .filter(r => !r.failed)
      .reduce((sum, r) => sum + (r.contentLength || 0), 0);
    
    const totalRequestTime = resourceMetrics
      .filter(r => !r.failed)
      .reduce((sum, r) => sum + r.responseTime, 0);
    
    const externalResourceCount = resourceMetrics
      .filter(r => r.isExternal && !r.failed)
      .length;
    
    const externalResourceSize = resourceMetrics
      .filter(r => r.isExternal && !r.failed)
      .reduce((sum, r) => sum + (r.contentLength || 0), 0);
    
    // Group resources by type
    const resourcesByType = {
      script: resourceMetrics.filter(r => r.type === 'script'),
      stylesheet: resourceMetrics.filter(r => r.type === 'stylesheet'),
      image: resourceMetrics.filter(r => r.type === 'image')
    };
    
    // Group resources by domain
    const resourcesByDomain = {};
    resourceMetrics.forEach(resource => {
      if (!resource.failed && resource.domain) {
        if (!resourcesByDomain[resource.domain]) {
          resourcesByDomain[resource.domain] = [];
        }
        resourcesByDomain[resource.domain].push(resource);
      }
    });
    
    // Generate performance score
    const performanceScoreFactors = {
      mainPageLoadTime: mainPageLoadTime < 1000 ? 100 : 
                        mainPageLoadTime < 2000 ? 80 :
                        mainPageLoadTime < 3000 ? 60 :
                        mainPageLoadTime < 5000 ? 40 : 20,
      
      resourceCount: resourceUrls.length < 20 ? 100 :
                    resourceUrls.length < 40 ? 80 :
                    resourceUrls.length < 60 ? 60 :
                    resourceUrls.length < 100 ? 40 : 20,
                    
      totalResourceSize: totalResourceSize < 1000000 ? 100 :  // 1MB
                        totalResourceSize < 2000000 ? 80 :   // 2MB
                        totalResourceSize < 4000000 ? 60 :   // 4MB
                        totalResourceSize < 8000000 ? 40 : 20, // 8MB
                        
      externalDomainRatio: externalResourceCount / resourceMetrics.length < 0.2 ? 100 :
                          externalResourceCount / resourceMetrics.length < 0.4 ? 80 :
                          externalResourceCount / resourceMetrics.length < 0.6 ? 60 :
                          externalResourceCount / resourceMetrics.length < 0.8 ? 40 : 20,
                          
      failedResourceRatio: resourceMetrics.filter(r => r.failed).length / resourceMetrics.length < 0.05 ? 100 :
                          resourceMetrics.filter(r => r.failed).length / resourceMetrics.length < 0.1 ? 80 :
                          resourceMetrics.filter(r => r.failed).length / resourceMetrics.length < 0.2 ? 60 :
                          resourceMetrics.filter(r => r.failed).length / resourceMetrics.length < 0.3 ? 40 : 20
    };
    
    const performanceScore = Math.round(
      (performanceScoreFactors.mainPageLoadTime * 0.3) +
      (performanceScoreFactors.resourceCount * 0.2) +
      (performanceScoreFactors.totalResourceSize * 0.2) +
      (performanceScoreFactors.externalDomainRatio * 0.15) +
      (performanceScoreFactors.failedResourceRatio * 0.15)
    );
    
    // End timer for complete analysis
    const endTime = performance.now();
    const totalAnalysisTime = endTime - startTime;
    
    res.json({
      url,
      baseDomain,
      performance: {
        mainPageLoadTime: Math.round(mainPageLoadTime),
        totalAnalysisTime: Math.round(totalAnalysisTime),
        totalResourceSize,
        totalRequestTime,
        resourceCount: resourceUrls.length,
        analyzedResourceCount: resourceMetrics.length,
        externalResourceCount,
        externalResourceSize,
        failedResourceCount: resourceMetrics.filter(r => r.failed).length,
        score: performanceScore,
        scoreFactors: performanceScoreFactors
      },
      resourceMetrics: resourceMetrics.sort((a, b) => 
        (b.contentLength || 0) - (a.contentLength || 0)
      ),
      resourcesByType,
      resourcesByDomain,
      recommendations: generatePerformanceRecommendations(resourceMetrics, performanceScoreFactors)
    });
  } catch (error) {
    console.error('Performance analysis error:', error);
    res.status(500).json({ 
      error: 'Failed to analyze performance', 
      message: error.message 
    });
  }
});

// Helper function to generate performance recommendations
function generatePerformanceRecommendations(resources, scoreFactors) {
  const recommendations = [];
  
  // Check main page load time
  if (scoreFactors.mainPageLoadTime < 80) {
    recommendations.push({
      type: 'critical',
      title: 'Slow Main Page Load Time',
      description: 'Your main page takes too long to load. Consider optimizing server response time and reducing render-blocking resources.'
    });
  }
  
  // Check resource count
  if (scoreFactors.resourceCount < 80) {
    recommendations.push({
      type: 'warning',
      title: 'Too Many Resources',
      description: 'Your page loads too many resources. Consider bundling files, using image sprites, or lazy loading non-critical resources.'
    });
  }
  
  // Check resource size
  if (scoreFactors.totalResourceSize < 80) {
    recommendations.push({
      type: 'warning',
      title: 'Large Page Size',
      description: 'Your page size is too large. Consider compressing images, minifying CSS/JS, and removing unused code.'
    });
  }
  
  // Check for large images
  const largeImages = resources.filter(r => 
    r.type === 'image' && r.contentLength && r.contentLength > 200000
  );
  
  if (largeImages.length > 0) {
    recommendations.push({
      type: 'info',
      title: 'Large Images Detected',
      description: `Found ${largeImages.length} large images (>200KB). Consider optimizing these images.`,
      items: largeImages.map(img => ({
        url: img.url,
        size: img.contentLength
      }))
    });
  }
  
  // Check for non-async scripts
  const nonAsyncScripts = resources.filter(r => 
    r.type === 'script' && !r.async && !r.defer
  );
  
  if (nonAsyncScripts.length > 3) {
    recommendations.push({
      type: 'info',
      title: 'Render-Blocking Scripts',
      description: `Found ${nonAsyncScripts.length} scripts without async or defer attributes. These can block page rendering.`,
      items: nonAsyncScripts.map(script => ({
        url: script.url
      }))
    });
  }
  
  // Check external resource ratio
  if (scoreFactors.externalDomainRatio < 60) {
    recommendations.push({
      type: 'warning',
      title: 'High External Domain Dependency',
      description: 'Your page depends on too many external domains, which can lead to performance and reliability issues. Consider self-hosting critical resources.'
    });
  }
  
  // Check for failed resources
  const failedResources = resources.filter(r => r.failed);
  if (failedResources.length > 0) {
    recommendations.push({
      type: 'critical',
      title: 'Failed Resource Requests',
      description: `Found ${failedResources.length} resources that failed to load. This can significantly impact user experience.`,
      items: failedResources.map(res => ({
        url: res.url,
        error: res.error
      }))
    });
  }
  
  return recommendations;
}

// Route for Content Security Policy (CSP) analysis and generation
router.post('/csp-analysis', async (req, res) => {
  try {
    const { url } = req.body;
    
    if (!url || !url.match(/^https?:\/\/[a-zA-Z0-9][a-zA-Z0-9-]{1,61}[a-zA-Z0-9](?:\.[a-zA-Z]{2,})+/)) {
      return res.status(400).json({ error: 'Invalid URL format' });
    }
    
    // Fetch the page
    const response = await axios.get(url, {
      headers: {
        'User-Agent': 'NetScan360/1.0'
      },
      timeout: 15000
    });
    
    const $ = cheerio.load(response.data);
    const urlObj = new URL(url);
    const baseDomain = urlObj.hostname;
    
    // Check if CSP is already implemented
    const headers = response.headers;
    const existingCSP = headers['content-security-policy'] || '';
    const existingCSPReport = headers['content-security-policy-report-only'] || '';
    
    // Collect all resources and their domains
    const domains = {
      script: new Set(),
      style: new Set(),
      img: new Set(),
      font: new Set(),
      frame: new Set(),
      connect: new Set(),
      media: new Set()
    };
    
    // Extract domain from a URL
    const extractDomain = (resourceUrl) => {
      try {
        let fullUrl = resourceUrl;
        if (!resourceUrl.startsWith('http')) {
          fullUrl = new URL(resourceUrl, url).href;
        }
        const parsedUrl = new URL(fullUrl);
        return parsedUrl.hostname;
      } catch (e) {
        return null;
      }
    };
    
    // Find scripts
    $('script').each((i, el) => {
      const src = $(el).attr('src');
      if (src) {
        const domain = extractDomain(src);
        if (domain && domain !== baseDomain) {
          domains.script.add(domain);
        }
      }
    });
    
    // Find styles
    $('link[rel="stylesheet"]').each((i, el) => {
      const href = $(el).attr('href');
      if (href) {
        const domain = extractDomain(href);
        if (domain && domain !== baseDomain) {
          domains.style.add(domain);
        }
      }
    });
    
    // Find images
    $('img').each((i, el) => {
      const src = $(el).attr('src');
      if (src) {
        const domain = extractDomain(src);
        if (domain && domain !== baseDomain) {
          domains.img.add(domain);
        }
      }
    });
    
    // Find fonts
    $('link[rel="preload"][as="font"]').each((i, el) => {
      const href = $(el).attr('href');
      if (href) {
        const domain = extractDomain(href);
        if (domain && domain !== baseDomain) {
          domains.font.add(domain);
        }
      }
    });
    
    // Find iframes
    $('iframe').each((i, el) => {
      const src = $(el).attr('src');
      if (src) {
        const domain = extractDomain(src);
        if (domain && domain !== baseDomain) {
          domains.frame.add(domain);
        }
      }
    });
    
    // Find potential connect endpoints (fetch, XMLHttpRequest)
    $('script:not([src])').each((i, el) => {
      const content = $(el).html() || '';
      // Very basic regex to find URLs in script content
      const urlRegex = /https?:\/\/[^\s"']+/g;
      const matches = content.match(urlRegex) || [];
      
      matches.forEach(match => {
        const domain = extractDomain(match);
        if (domain && domain !== baseDomain) {
          domains.connect.add(domain);
        }
      });
    });
    
    // Find video/audio
    $('video source, audio source').each((i, el) => {
      const src = $(el).attr('src');
      if (src) {
        const domain = extractDomain(src);
        if (domain && domain !== baseDomain) {
          domains.media.add(domain);
        }
      }
    });
    
    // Generate CSP directives
    const generateDirective = (name, domains, includeBase = true) => {
      const values = [];
      
      if (includeBase) {
        values.push("'self'");
      }
      
      domains.forEach(domain => {
        values.push(domain);
      });
      
      if (values.length > 0) {
        return `${name}-src ${values.join(' ')}`;
      }
      return null;
    };
    
    const cspDirectives = [
      // Include default-src as fallback
      generateDirective('default', new Set()),
      generateDirective('script', domains.script),
      generateDirective('style', domains.style),
      generateDirective('img', domains.img),
      generateDirective('font', domains.font),
      generateDirective('frame', domains.frame),
      generateDirective('connect', domains.connect),
      generateDirective('media', domains.media),
      // Block inline scripts by default for security
      "script-src-attr 'none'",
      // Restrict object sources
      "object-src 'none'",
      // Set base-uri restriction
      "base-uri 'self'",
      // Set form action restriction
      "form-action 'self'",
      // Upgrade insecure requests
      "upgrade-insecure-requests"
    ].filter(Boolean);
    
    // Generate recommended CSP header
    const recommendedCSP = cspDirectives.join('; ');
    
    // Parse existing CSP if present
    const parseCSP = (cspString) => {
      if (!cspString) return {};
      
      const directives = {};
      cspString.split(';').forEach(directive => {
        const parts = directive.trim().split(/\s+/);
        if (parts.length > 0) {
          const name = parts[0];
          const values = parts.slice(1);
          directives[name] = values;
        }
      });
      
      return directives;
    };
    
    // Generate CSP analysis
    const analysis = {
      hasCSP: !!existingCSP,
      hasReportOnlyCSP: !!existingCSPReport,
      existingCSP: parseCSP(existingCSP),
      existingCSPReport: parseCSP(existingCSPReport),
      recommendedCSP,
      domains: {
        script: Array.from(domains.script),
        style: Array.from(domains.style),
        img: Array.from(domains.img),
        font: Array.from(domains.font),
        frame: Array.from(domains.frame),
        connect: Array.from(domains.connect),
        media: Array.from(domains.media)
      },
      violations: []
    };
    
    // Compare with external domains found in the scan results
    const addViolation = (type, domain) => {
      analysis.violations.push({
        type,
        domain,
        directive: `${type}-src`,
        recommendation: `Add '${domain}' to the ${type}-src directive`
      });
    };
    
    // Check for potential violations or improvements
    if (!existingCSP) {
      analysis.violations.push({
        type: 'critical',
        directive: 'general',
        domain: null,
        recommendation: 'Implement a Content Security Policy to improve security'
      });
    } else {
      // Check if CSP has unsafe-inline for scripts
      const scriptSrc = analysis.existingCSP['script-src'] || analysis.existingCSP['default-src'] || [];
      if (scriptSrc.includes("'unsafe-inline'")) {
        analysis.violations.push({
          type: 'warning',
          directive: 'script-src',
          domain: null,
          recommendation: "Remove 'unsafe-inline' from script-src and use nonces or hashes instead"
        });
      }
      
      // Check if CSP is missing key directives
      ['default-src', 'script-src', 'object-src'].forEach(directive => {
        if (!analysis.existingCSP[directive]) {
          analysis.violations.push({
            type: 'warning',
            directive,
            domain: null,
            recommendation: `Add ${directive} directive to your CSP`
          });
        }
      });
    }
    
    res.json({
      url,
      baseDomain,
      cspAnalysis: analysis,
      securityScore: analysis.hasCSP ? (analysis.violations.length > 5 ? 'Low' : analysis.violations.length > 2 ? 'Medium' : 'High') : 'Very Low'
    });
  } catch (error) {
    console.error('CSP analysis error:', error);
    res.status(500).json({ 
      error: 'Failed to analyze CSP', 
      message: error.message 
    });
  }
});

module.exports = router; 