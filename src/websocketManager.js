const WebSocket = require('ws');

class WebSocketManager {
  constructor() {
    this.wss = null;
    this.sessions = new Map(); // Map sessionId -> WebSocket connection
    this.initialized = false;
  }

  // Initialize WebSocket server with existing HTTP server
  initialize(server) {
    if (this.initialized) {
      console.log('WebSocket server already initialized');
      return;
    }

    this.wss = new WebSocket.Server({ server });
    console.log('WebSocket server initialized');

    this.wss.on('connection', (ws) => {
      console.log('New WebSocket connection established');
      
      // Wait for the client to send a sessionId
      ws.on('message', (message) => {
        try {
          const data = JSON.parse(message);
          
          // If this is a session registration message
          if (data.type === 'register' && data.sessionId) {
            const sessionId = data.sessionId;
            console.log(`Registering session: ${sessionId}`);
            
            // Store the connection with its sessionId
            this.sessions.set(sessionId, ws);
            
            // Send confirmation
            ws.send(JSON.stringify({
              type: 'registration_successful',
              sessionId: sessionId,
              timestamp: new Date().toISOString()
            }));
          }
        } catch (error) {
          console.error('Error processing WebSocket message:', error);
        }
      });

      // Handle connection close
      ws.on('close', () => {
        console.log('WebSocket connection closed');
        
        // Remove the session from our sessions map
        for (const [sessionId, connection] of this.sessions.entries()) {
          if (connection === ws) {
            console.log(`Removing session: ${sessionId}`);
            this.sessions.delete(sessionId);
            break;
          }
        }
      });

      // Handle errors
      ws.on('error', (error) => {
        console.error('WebSocket error:', error);
      });
    });

    this.initialized = true;
  }

  // Send event to a specific session
  sendEventToSession(sessionId, eventData) {
    const ws = this.sessions.get(sessionId);
    
    if (ws && ws.readyState === WebSocket.OPEN) {
      try {
        ws.send(JSON.stringify(eventData));
        return true;
      } catch (error) {
        console.error(`Error sending event to session ${sessionId}:`, error);
        return false;
      }
    } else {
      console.warn(`Cannot send event to session ${sessionId}: Connection not found or not open`);
      return false;
    }
  }

  // Broadcast event to all connected clients
  broadcastEvent(eventData) {
    let successCount = 0;
    
    this.wss.clients.forEach((client) => {
      if (client.readyState === WebSocket.OPEN) {
        try {
          client.send(JSON.stringify(eventData));
          successCount++;
        } catch (error) {
          console.error('Error broadcasting event:', error);
        }
      }
    });
    
    return successCount;
  }

  // Get count of active connections
  getConnectionCount() {
    return this.wss ? this.wss.clients.size : 0;
  }

  // Get count of registered sessions
  getSessionCount() {
    return this.sessions.size;
  }
}

// Create singleton instance
const websocketManager = new WebSocketManager();

module.exports = websocketManager; 