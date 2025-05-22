/**
 * Test script for verifying the autoHackerService with MCP integration
 */
const autoHackerService = require('./src/services/autoHackerService');

// Target to scan (use a safe target for testing)
const target = '127.0.0.1';
const scanId = 'test-scan-001';
const scanDepth = 'basic';

/**
 * Test the port scanning function
 */
async function testPortScan() {
  console.log(`Testing port scan on ${target} with depth: ${scanDepth}`);
  
  try {
    const result = await autoHackerService.runPortScan(scanId, target, scanDepth);
    console.log('Port scan test completed successfully!');
    console.log('Results:', JSON.stringify(result, null, 2));
    return true;
  } catch (error) {
    console.error('ERROR:', error.message);
    return false;
  }
}

/**
 * Test the service detection function
 */
async function testServiceDetection() {
  console.log(`Testing service detection on ${target} with depth: ${scanDepth}`);
  
  try {
    const result = await autoHackerService.runServiceDetection(scanId, target, scanDepth);
    console.log('Service detection test completed successfully!');
    console.log('Results:', JSON.stringify(result, null, 2));
    return true;
  } catch (error) {
    console.error('ERROR:', error.message);
    return false;
  }
}

/**
 * Test the vulnerability scanning function
 */
async function testVulnerabilityScan() {
  console.log(`Testing vulnerability scan on ${target} with depth: ${scanDepth}`);
  
  try {
    const result = await autoHackerService.runVulnerabilityScan(scanId, target, scanDepth);
    console.log('Vulnerability scan test completed successfully!');
    console.log('Results:', JSON.stringify(result, null, 2));
    return true;
  } catch (error) {
    console.error('ERROR:', error.message);
    return false;
  }
}

// Run the tests
async function runTests() {
  try {
    const portScanSuccess = await testPortScan();
    console.log('\n-----------------------------------\n');
    
    const serviceDetectionSuccess = await testServiceDetection();
    console.log('\n-----------------------------------\n');
    
    const vulnerabilityScanSuccess = await testVulnerabilityScan();
    console.log('\n-----------------------------------\n');
    
    const allTestsPassed = portScanSuccess && serviceDetectionSuccess && vulnerabilityScanSuccess;
    
    if (allTestsPassed) {
      console.log('✅ All tests passed!');
      return 0;
    } else {
      console.log('❌ Some tests failed!');
      return 1;
    }
  } catch (error) {
    console.error('Test execution error:', error);
    return 1;
  }
}

runTests()
  .then(exitCode => process.exit(exitCode))
  .catch(error => {
    console.error('Fatal error:', error);
    process.exit(1);
  }); 