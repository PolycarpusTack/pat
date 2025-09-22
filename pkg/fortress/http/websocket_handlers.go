package http

import (
	"context"
	"encoding/json"
	"net/http"
	"time"

	"github.com/gorilla/websocket"
	"go.uber.org/zap"
)

// WebSocketHandlers contains WebSocket-related HTTP handlers
type WebSocketHandlers struct {
	server *FortressHTTPServer
}

// NewWebSocketHandlers creates new WebSocket handlers
func NewWebSocketHandlers(server *FortressHTTPServer) *WebSocketHandlers {
	return &WebSocketHandlers{server: server}
}

// handleWebSocket handles WebSocket connections for real-time updates
func (h *WebSocketHandlers) HandleWebSocket(w http.ResponseWriter, r *http.Request) {
	// Upgrade HTTP connection to WebSocket
    upgrader := websocket.Upgrader{
        ReadBufferSize:  1024,
        WriteBufferSize: 1024,
        CheckOrigin: func(r *http.Request) bool {
            // Allow only same-origin dev hosts or configured CORS origin
            origin := r.Header.Get("Origin")
            if origin == "" {
                return true // No origin header (direct connection)
            }
            if origin == "http://localhost:8025" || origin == "http://127.0.0.1:8025" {
                return true
            }
            if h.server.config.CORSOrigin != "" && origin == h.server.config.CORSOrigin {
                return true
            }
            h.server.logger.Warn("Blocked WebSocket origin",
                zap.String("origin", origin),
                zap.String("allowed", h.server.config.CORSOrigin))
            return false
        },
    }

    conn, err := upgrader.Upgrade(w, r, nil)
    if err != nil {
        h.server.logger.Error("WebSocket upgrade failed", zap.Error(err))
        return
    }
    // Register connection
    h.server.wsMu.Lock()
    h.server.wsConns[conn] = struct{}{}
    h.server.wsMu.Unlock()
    defer func() {
        h.server.wsMu.Lock()
        delete(h.server.wsConns, conn)
        h.server.wsMu.Unlock()
        conn.Close()
    }()

	h.server.logger.Info("WebSocket connection established",
		zap.String("remote_addr", r.RemoteAddr),
		zap.String("user_agent", r.UserAgent()),
	)

	// Create WebSocket client context
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Handle WebSocket messages
	go h.handleWebSocketMessages(ctx, conn)

	// Send periodic updates
	ticker := time.NewTicker(5 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			// Send real-time statistics
			stats := h.getRealtimeStats()
            if err := conn.WriteJSON(stats); err != nil {
                h.server.logger.Error("WebSocket write error", zap.Error(err))
                return
            }

		case <-ctx.Done():
			return
		}
	}
}

// handleWebSocketMessages handles incoming WebSocket messages from clients
func (h *WebSocketHandlers) handleWebSocketMessages(ctx context.Context, conn *websocket.Conn) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			_, message, err := conn.ReadMessage()
			if err != nil {
				if websocket.IsUnexpectedCloseError(err, websocket.CloseGoingAway, websocket.CloseAbnormalClosure) {
					h.server.logger.Error("WebSocket read error", zap.Error(err))
				}
				return
			}

			h.server.logger.Debug("Received WebSocket message",
				zap.ByteString("message", message),
			)

			// Process WebSocket commands (e.g., subscribe to specific events)
			h.processWebSocketCommand(conn, message)
		}
	}
}

// processWebSocketCommand processes incoming WebSocket commands
func (h *WebSocketHandlers) processWebSocketCommand(conn *websocket.Conn, message []byte) {
	// Parse command (basic JSON structure expected)
	var command map[string]interface{}
	if err := json.Unmarshal(message, &command); err != nil {
		h.server.logger.Error("Invalid WebSocket command", zap.Error(err))
		return
	}

	// Handle different command types
	if cmdType, ok := command["type"].(string); ok {
		switch cmdType {
		case "ping":
			h.sendWebSocketResponse(conn, map[string]interface{}{
				"type":      "pong",
				"timestamp": time.Now().UTC(),
			})
		case "subscribe":
			// Handle subscription to real-time events
			h.server.logger.Info("Client subscribed to real-time events")
		case "get_stats":
			stats := h.getRealtimeStats()
			h.sendWebSocketResponse(conn, stats)
		default:
			h.server.logger.Warn("Unknown WebSocket command", zap.String("type", cmdType))
		}
	}
}

// sendWebSocketResponse sends a response back to the WebSocket client
func (h *WebSocketHandlers) sendWebSocketResponse(conn *websocket.Conn, data interface{}) {
	if err := conn.WriteJSON(data); err != nil {
		h.server.logger.Error("Failed to send WebSocket response", zap.Error(err))
	}
}

// getRealtimeStats returns real-time statistics for WebSocket clients
func (h *WebSocketHandlers) getRealtimeStats() map[string]interface{} {
	uptime := time.Since(h.server.startTime)

	// Calculate uptime percentage (simplified - in production would track actual downtime)
	uptimePercent := 99.9 // Default assumption

	// Get rate limiting stats
	rateLimitStats := map[string]interface{}{"enabled": false}
	if h.server.rateLimiter != nil {
		rateLimitStats = h.server.rateLimiter.GetStats()
	}

	return map[string]interface{}{
		"type":      "stats_update",
		"timestamp": time.Now().UTC(),
		"fortress": map[string]interface{}{
			"version": "2.0.0",
			"status":  "operational",
			"uptime":  uptime.String(),
			"uptime_seconds": int64(uptime.Seconds()),
			"messages": map[string]interface{}{
				"total": h.server.store.Count(),
			},
			"performance": map[string]interface{}{
				"uptime_percent": uptimePercent,
			},
			"rate_limiting": rateLimitStats,
			"security": map[string]interface{}{
				"auth_enabled": h.server.config.EnableAuth,
				"tls_enabled":  h.server.config.EnableTLS,
			},
		},
	}
}
