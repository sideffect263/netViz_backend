// Custom callback handler to stream thinking process via WebSockets
// Implementing our own handler without extending BaseCallbackHandler
class WebSocketCallbackHandler {
  constructor(sessionId, sendEventToSocket) {
    this.sessionId = sessionId;
    this.sendEventToSocket = sendEventToSocket;
  }

  // Required to register this as a callback handler with LangChain
  get name() {
    return 'WebSocketCallbackHandler';
  }

  // Required for the interface
  async handleLLMStart(llm, prompts) {
    this.sendEventToSocket({
      type: 'llm_start',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      content: 'Starting to think...'
    });
  }

  async handleLLMNewToken(token) {
    this.sendEventToSocket({
      type: 'llm_token',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      content: token
    });
  }

  async handleLLMEnd(output) {
    this.sendEventToSocket({
      type: 'llm_end',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      content: 'Finished thinking'
    });
  }

  async handleToolStart(tool, input) {
    // For Nmap scans, add a progress message
    if (tool.name === 'NmapScanner') {
      this.sendEventToSocket({
        type: 'progress_update',
        sessionId: this.sessionId,
        timestamp: new Date().toISOString(),
        message: 'Starting network scan. This may take some time depending on the scan parameters. The system will automatically reduce scan intensity if needed.'
      });
    }
    
    this.sendEventToSocket({
      type: 'tool_start',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      toolName: tool.name,
      input: input
    });
  }

  async handleToolEnd(output) {
    this.sendEventToSocket({
      type: 'tool_end',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      output: output
    });
  }

  async handleAgentAction(action) {
    this.sendEventToSocket({
      type: 'agent_action',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      tool: action.tool,
      toolInput: action.toolInput,
      log: action.log
    });
  }

  async handleAgentEnd(action) {
    this.sendEventToSocket({
      type: 'agent_end',
      sessionId: this.sessionId,
      timestamp: new Date().toISOString(),
      output: action.returnValues?.output,
      log: action.log
    });
  }

  // Additional handlers to match the interface
  async handleChainStart(chain) {}
  async handleChainEnd(outputs) {}
  async handleChainError(error) {}
  async handleToolError(error) {}
  async handleText(text) {}
  async handleLLMError(error) {}
}

module.exports = {
  WebSocketCallbackHandler
}; 