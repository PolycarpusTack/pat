package http

import (
	"net/http"
	"strconv"
	"time"

	"github.com/gorilla/mux"
	"github.com/pat-fortress/pkg/fortress/legacy"
	"go.uber.org/zap"
)

// MessageHandlers contains HTTP handlers for message operations
type MessageHandlers struct {
	server *FortressHTTPServer
}

// NewMessageHandlers creates new message handlers
func NewMessageHandlers(server *FortressHTTPServer) *MessageHandlers {
	return &MessageHandlers{server: server}
}

// handleMessages handles the messages list endpoint (MailHog v1 compatibility)
func (h *MessageHandlers) HandleMessages(w http.ResponseWriter, r *http.Request) {
	// Parse query parameters
	start := 0
	limit := 50

	if startStr := r.URL.Query().Get("start"); startStr != "" {
		if parsed, err := strconv.Atoi(startStr); err == nil {
			start = parsed
		}
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	// Get messages from store
	messages, err := h.server.store.List(start, limit)
	if err != nil {
		h.server.logger.Error("Failed to list messages",
			zap.Error(err),
			zap.Int("start", start),
			zap.Int("limit", limit))
		http.Error(w, "Failed to retrieve messages", http.StatusInternalServerError)
		return
	}

	// Get total count
	total := h.server.store.Count()

	// Create response in MailHog format
	response := map[string]interface{}{
		"total":    total,
		"count":    len(*messages),
		"start":    start,
		"messages": messages,
	}

	h.server.writeJSON(w, response)
}

// handleMessage handles single message operations (MailHog v1 compatibility)
func (h *MessageHandlers) HandleMessage(w http.ResponseWriter, r *http.Request) {
	vars := mux.Vars(r)
	id := legacy.MessageID(vars["id"])

	switch r.Method {
	case "GET":
		message, err := h.server.store.Load(id)
		if err != nil {
			if err == legacy.ErrMessageNotFound {
				http.Error(w, "Message not found", http.StatusNotFound)
			} else {
				h.server.logger.Error("Failed to load message", zap.Error(err))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
			return
		}

		h.server.writeJSON(w, message)

	case "DELETE":
		// Delete message
		err := h.server.store.DeleteOne(id)
		if err != nil {
			if err == legacy.ErrMessageNotFound {
				http.Error(w, "Message not found", http.StatusNotFound)
			} else {
				h.server.logger.Error("Failed to delete message", zap.Error(err))
				http.Error(w, "Internal server error", http.StatusInternalServerError)
			}
			return
		}

		w.WriteHeader(http.StatusOK)

		// Broadcast deletion event
		h.server.PublishEvent("message_deleted", map[string]interface{}{"id": string(id)})
	}
}

// handleDeleteAll handles delete all messages endpoint
func (h *MessageHandlers) HandleDeleteAll(w http.ResponseWriter, r *http.Request) {
	if r.Method != "DELETE" {
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
		return
	}

	// Capture count before purge
	preCount := h.server.store.Count()

	err := h.server.store.DeleteAll()
	if err != nil {
		h.server.logger.Error("Failed to delete all messages", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	w.WriteHeader(http.StatusOK)

	// Broadcast purge event with count
	h.server.PublishEvent("messages_purged", map[string]interface{}{"count": preCount})
}

// handleMessagesV2 handles the enhanced messages endpoint (MailHog v2 compatibility)
func (h *MessageHandlers) HandleMessagesV2(w http.ResponseWriter, r *http.Request) {
	// Enhanced version with additional filtering capabilities
	h.HandleMessages(w, r) // For now, use v1 implementation
}

// handleMessageV2 handles single message operations (MailHog v2 compatibility)
func (h *MessageHandlers) HandleMessageV2(w http.ResponseWriter, r *http.Request) {
	// Enhanced version with additional metadata
	h.HandleMessage(w, r) // For now, use v1 implementation
}

// handleSearch handles message search endpoint
func (h *MessageHandlers) HandleSearch(w http.ResponseWriter, r *http.Request) {
	kind := r.URL.Query().Get("kind")
	query := r.URL.Query().Get("query")

	if kind == "" || query == "" {
		http.Error(w, "Missing kind or query parameter", http.StatusBadRequest)
		return
	}

	start := 0
	limit := 50

	if startStr := r.URL.Query().Get("start"); startStr != "" {
		if parsed, err := strconv.Atoi(startStr); err == nil {
			start = parsed
		}
	}

	if limitStr := r.URL.Query().Get("limit"); limitStr != "" {
		if parsed, err := strconv.Atoi(limitStr); err == nil && parsed > 0 && parsed <= 1000 {
			limit = parsed
		}
	}

	messages, err := h.server.store.Search(kind, query, start, limit)
	if err != nil {
		h.server.logger.Error("Failed to search messages",
			zap.Error(err),
			zap.String("kind", kind),
			zap.String("query", query),
		)
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	response := map[string]interface{}{
		"total":    len(*messages),
		"count":    len(*messages),
		"start":    start,
		"messages": messages,
		"kind":     kind,
		"query":    query,
	}

	h.server.writeJSON(w, response)
}

// handleMessageStats provides detailed message statistics
func (h *MessageHandlers) HandleMessageStats(w http.ResponseWriter, r *http.Request) {
    total := h.server.store.Count()

    stats := map[string]interface{}{
        // Align keys with UI expectations
        "total":          total,
        "today":          0,
        "avg_size":       0,
        "unique_senders": 0,
        "timestamp":      time.Now().UTC(),
    }

    h.server.writeJSON(w, stats)
}

// handleExport provides message export functionality
func (h *MessageHandlers) HandleExport(w http.ResponseWriter, r *http.Request) {
	format := r.URL.Query().Get("format")
	if format == "" {
		format = "json"
	}

	messages, err := h.server.store.List(0, h.server.store.Count())
	if err != nil {
		h.server.logger.Error("Failed to export messages", zap.Error(err))
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}

	switch format {
	case "json":
		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("Content-Disposition", "attachment; filename=messages.json")
		h.server.writeJSON(w, map[string]interface{}{
			"messages": messages,
			"exported": time.Now().UTC(),
			"total":    len(*messages),
		})

	default:
		http.Error(w, "Unsupported export format", http.StatusBadRequest)
	}
}
