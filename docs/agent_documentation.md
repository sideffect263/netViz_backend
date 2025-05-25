# NetViz AI Agent Documentation

## Purpose and Overview

NetViz AI Agent is an intelligent assistant that helps with network scanning, analysis, and security tasks. It combines the power of AI with network tools like Nmap to provide useful insights in a conversational interface.

## Scan Capabilities

### Quick Scan

**Description**: Fast scan of common ports using optimized parameters
**Technical Details**: Uses Nmap with -T4 -F flags to quickly identify the most common open ports on a target
**Best For**: Initial reconnaissance or when time is limited
**Example Command**: "run a quick scan on example.com"
**Expected Output**: A list of the most commonly open ports (like 80, 443, 22) and their statuses

### Service Scan

**Description**: Detailed scan that identifies running services on open ports
**Technical Details**: Uses Nmap with -sV flag to detect service versions running on the target system
**Best For**: Understanding what services are running on a target system
**Example Command**: "scan for services on 192.168.1.1"
**Expected Output**: Port numbers, states (open/closed), and service identification with version information

### Full Port Scan

**Description**: Comprehensive scan of all 65535 ports
**Technical Details**: Scans the entire port range for complete coverage
**Best For**: Thorough security audits and comprehensive host analysis
**Example Command**: "run a comprehensive port scan on example.com"
**Expected Output**: Complete listing of all open ports, even uncommon ones not found in standard scans
**Note**: Takes significantly longer than a Quick Scan

### Vulnerability Scan

**Description**: Identifies potential security vulnerabilities on the target
**Technical Details**: Combines service detection with vulnerability assessment
**Best For**: Security audits and penetration testing preparations
**Example Command**: "check for vulnerabilities on example.com"
**Expected Output**: List of potential security issues based on detected services and configurations

## General Capabilities

- Network scanning and enumeration of hosts, ports, and services
- Service identification and version detection
- OS detection and fingerprinting
- Security vulnerability assessment
- Intelligent analysis of scan results
- Conversational interface for network security tasks
- Explanation of technical findings in plain language
- Results visualization with summary, detailed views, and raw data access

## Technical Architecture

NetViz uses a client-server architecture where the React frontend communicates with a Node.js backend. The backend integrates with Nmap through a custom MCP (Model Context Protocol) client that securely manages scan operations. LangChain orchestrates the AI agent's reasoning and tool usage.

### Agent Architecture

The NetViz AI Agent uses LangChain.js for orchestration, Anthropic Claude for AI capabilities, and a WebSocket-based real-time communication system. It features a dual-pane interface showing both the chat and the agent's thinking process for transparency.

## Key Components

- **AI Agent**: Powered by Anthropic's Claude model through LangChain, providing natural language understanding and generation
- **WebSocket Connection**: Real-time communication channel that streams thinking process and results to the UI
- **Nmap Integration**: Security scanner utility accessed through a Model Context Protocol (MCP) client
- **Visualization Components**: React-based UI components that render scan results in a user-friendly format
- **Command History**: System that tracks and allows reuse of previous commands
- **Dark Mode**: User interface feature for comfortable viewing in different lighting conditions
- **Progress Tracking**: Visual indicators showing scan progress and estimated completion time

## Command Structure

Users can interact with the agent using natural language commands. The system understands various formats, but some examples include:

- "scan [target] for open ports"
- "run a quick scan on [target]"
- "check if port [number] is open on [target]"
- "scan for services on [target]"
- "run a comprehensive port scan on [target]"
- "check for vulnerabilities on [target]"
- "scan network range [CIDR]"

## Limitations

- Cannot perform intrusive scans without proper authorization
- Network scan capabilities are limited to what Nmap provides
- Requires proper network connectivity to scan targets
- Large scans may take significant time to complete
- Must have proper permissions to scan target hosts
- Always follow responsible security practices and legal requirements when scanning

## Best Practices

- Always ensure you have permission to scan target systems
- Start with quick scans before running more intensive scans
- Use specific scan types for specific needs to optimize time and resources
- Interpret results carefully, as open ports don't automatically indicate vulnerabilities
- Consider network conditions when interpreting scan results

When answering questions about capabilities, features, or functionality, use this documentation to provide accurate, specific information about the NetViz AI Agent.
