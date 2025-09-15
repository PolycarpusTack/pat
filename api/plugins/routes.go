package plugins

import (
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/gin-gonic/gin"
	"github.com/pkg/errors"
)

// PluginHandler handles HTTP requests for plugin operations
type PluginHandler struct {
	manager  *Manager
	registry *Registry
	security *SecurityScanner
	logger   Logger
}

// NewPluginHandler creates a new plugin handler
func NewPluginHandler(manager *Manager, registry *Registry, security *SecurityScanner, logger Logger) *PluginHandler {
	return &PluginHandler{
		manager:  manager,
		registry: registry,
		security: security,
		logger:   logger,
	}
}

// RegisterRoutes registers plugin API routes
func (h *PluginHandler) RegisterRoutes(router *gin.RouterGroup) {
	plugins := router.Group("/plugins")
	{
		// Plugin registry operations
		plugins.GET("", h.ListPlugins)
		plugins.POST("", h.RegisterPlugin)
		plugins.GET("/:id", h.GetPlugin)
		plugins.PUT("/:id", h.UpdatePlugin)
		plugins.DELETE("/:id", h.DeletePlugin)
		plugins.POST("/:id/publish", h.PublishPlugin)
		plugins.POST("/:id/approve", h.ApprovePlugin)
		plugins.POST("/:id/reject", h.RejectPlugin)
		plugins.POST("/:id/suspend", h.SuspendPlugin)

		// Plugin code operations
		plugins.GET("/:id/code/:version", h.GetPluginCode)
		plugins.POST("/:id/scan", h.ScanPlugin)

		// Plugin installation operations
		plugins.POST("/:id/install", h.InstallPlugin)
		plugins.DELETE("/:id/uninstall", h.UninstallPlugin)
		plugins.GET("/installed", h.GetInstalledPlugins)
		plugins.PUT("/installed/:id/config", h.UpdatePluginConfig)
		plugins.POST("/installed/:id/enable", h.EnablePlugin)
		plugins.POST("/installed/:id/disable", h.DisablePlugin)

		// Plugin execution operations
		plugins.GET("/instances", h.GetPluginInstances)
		plugins.GET("/instances/:id", h.GetPluginInstance)
		plugins.GET("/instances/:id/stats", h.GetPluginStats)
		plugins.POST("/instances/:id/reload", h.ReloadPlugin)

		// Plugin marketplace operations
		plugins.GET("/marketplace", h.GetMarketplace)
		plugins.GET("/marketplace/categories", h.GetCategories)
		plugins.GET("/marketplace/search", h.SearchPlugins)
		plugins.GET("/marketplace/:id/reviews", h.GetPluginReviews)
		plugins.POST("/marketplace/:id/reviews", h.CreatePluginReview)

		// Plugin development operations
		plugins.POST("/validate", h.ValidatePlugin)
		plugins.POST("/test", h.TestPlugin)
		plugins.GET("/sdk/docs", h.GetSDKDocs)
		plugins.GET("/hooks", h.GetAvailableHooks)
	}
}

// ListPlugins lists available plugins
func (h *PluginHandler) ListPlugins(c *gin.Context) {
	// Parse query parameters
	filter := &PluginFilter{
		Category: c.Query("category"),
		Author:   c.Query("author"),
		Status:   PluginStatus(c.Query("status")),
		Limit:    50,
		Offset:   0,
	}

	if limit := c.Query("limit"); limit != "" {
		if l, err := strconv.Atoi(limit); err == nil {
			filter.Limit = l
		}
	}

	if offset := c.Query("offset"); offset != "" {
		if o, err := strconv.Atoi(offset); err == nil {
			filter.Offset = o
		}
	}

	// Get plugins
	plugins, err := h.registry.ListPlugins(c.Request.Context(), filter)
	if err != nil {
		h.logger.Error("Failed to list plugins", map[string]interface{}{
			"error": err.Error(),
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to list plugins"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"plugins": plugins,
		"total":   len(plugins),
		"limit":   filter.Limit,
		"offset":  filter.Offset,
	})
}

// RegisterPlugin registers a new plugin
func (h *PluginHandler) RegisterPlugin(c *gin.Context) {
	var request struct {
		Metadata *PluginMetadata `json:"metadata" binding:"required"`
		Code     string          `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Get user info from context (assuming auth middleware sets this)
	userID := c.GetString("user_id")
	if userID == "" {
		c.JSON(http.StatusUnauthorized, gin.H{"error": "Authentication required"})
		return
	}

	// Set author
	request.Metadata.Author = userID

	// Register plugin
	err := h.registry.RegisterPlugin(c.Request.Context(), request.Metadata, request.Code)
	if err != nil {
		h.logger.Error("Failed to register plugin", map[string]interface{}{
			"user_id": userID,
			"error":   err.Error(),
		})
		
		if errors.Cause(err).Error() == "plugin metadata validation failed" ||
		   errors.Cause(err).Error() == "plugin code validation failed" {
			c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
			return
		}
		
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to register plugin"})
		return
	}

	h.logger.Info("Plugin registered successfully", map[string]interface{}{
		"plugin_id": request.Metadata.ID,
		"user_id":   userID,
	})

	c.JSON(http.StatusCreated, gin.H{
		"message":   "Plugin registered successfully",
		"plugin_id": request.Metadata.ID,
	})
}

// GetPlugin retrieves a specific plugin
func (h *PluginHandler) GetPlugin(c *gin.Context) {
	pluginID := c.Param("id")

	plugin, err := h.registry.GetPlugin(c.Request.Context(), pluginID)
	if err != nil {
		h.logger.Error("Failed to get plugin", map[string]interface{}{
			"plugin_id": pluginID,
			"error":     err.Error(),
		})
		c.JSON(http.StatusNotFound, gin.H{"error": "Plugin not found"})
		return
	}

	c.JSON(http.StatusOK, plugin)
}

// InstallPlugin installs a plugin for the current tenant
func (h *PluginHandler) InstallPlugin(c *gin.Context) {
	pluginID := c.Param("id")
	tenantID := c.GetString("tenant_id")

	var request struct {
		Version string                 `json:"version" binding:"required"`
		Config  map[string]interface{} `json:"config"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Install plugin
	err := h.registry.InstallPlugin(c.Request.Context(), tenantID, pluginID, request.Version, request.Config)
	if err != nil {
		h.logger.Error("Failed to install plugin", map[string]interface{}{
			"tenant_id": tenantID,
			"plugin_id": pluginID,
			"version":   request.Version,
			"error":     err.Error(),
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	// Load plugin into manager
	err = h.manager.LoadPlugin(c.Request.Context(), tenantID, pluginID, request.Version)
	if err != nil {
		h.logger.Error("Failed to load plugin after installation", map[string]interface{}{
			"tenant_id": tenantID,
			"plugin_id": pluginID,
			"version":   request.Version,
			"error":     err.Error(),
		})
		// Don't fail the installation, just log the error
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Plugin installed successfully",
	})
}

// UninstallPlugin uninstalls a plugin for the current tenant
func (h *PluginHandler) UninstallPlugin(c *gin.Context) {
	pluginID := c.Param("id")
	tenantID := c.GetString("tenant_id")

	// Get plugin installation to get version
	installation, err := h.registry.GetPluginInstallation(c.Request.Context(), tenantID, pluginID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Plugin not installed"})
		return
	}

	// Unload plugin from manager
	err = h.manager.UnloadPlugin(c.Request.Context(), tenantID, pluginID, installation.Version)
	if err != nil {
		h.logger.Warn("Failed to unload plugin", map[string]interface{}{
			"tenant_id": tenantID,
			"plugin_id": pluginID,
			"error":     err.Error(),
		})
	}

	// Uninstall plugin
	err = h.registry.UninstallPlugin(c.Request.Context(), tenantID, pluginID)
	if err != nil {
		h.logger.Error("Failed to uninstall plugin", map[string]interface{}{
			"tenant_id": tenantID,
			"plugin_id": pluginID,
			"error":     err.Error(),
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to uninstall plugin"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Plugin uninstalled successfully",
	})
}

// GetInstalledPlugins retrieves installed plugins for current tenant
func (h *PluginHandler) GetInstalledPlugins(c *gin.Context) {
	tenantID := c.GetString("tenant_id")

	installations, err := h.registry.GetTenantPlugins(c.Request.Context(), tenantID)
	if err != nil {
		h.logger.Error("Failed to get installed plugins", map[string]interface{}{
			"tenant_id": tenantID,
			"error":     err.Error(),
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to get installed plugins"})
		return
	}

	// Get plugin instances
	instances := h.manager.GetPluginInstances(tenantID)
	instanceMap := make(map[string]*PluginInstance)
	for _, instance := range instances {
		instanceMap[instance.PluginID] = instance
	}

	// Combine installation and instance data
	var result []map[string]interface{}
	for _, installation := range installations {
		pluginData := map[string]interface{}{
			"installation": installation,
			"instance":     instanceMap[installation.PluginID],
		}
		result = append(result, pluginData)
	}

	c.JSON(http.StatusOK, gin.H{
		"plugins": result,
		"total":   len(result),
	})
}

// GetPluginInstances retrieves plugin instances for current tenant
func (h *PluginHandler) GetPluginInstances(c *gin.Context) {
	tenantID := c.GetString("tenant_id")

	instances := h.manager.GetPluginInstances(tenantID)

	c.JSON(http.StatusOK, gin.H{
		"instances": instances,
		"total":     len(instances),
	})
}

// ScanPlugin performs security scan on a plugin
func (h *PluginHandler) ScanPlugin(c *gin.Context) {
	pluginID := c.Param("id")

	// Get plugin
	plugin, err := h.registry.GetPlugin(c.Request.Context(), pluginID)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Plugin not found"})
		return
	}

	// Get plugin code
	pluginCode, err := h.registry.GetPluginCode(c.Request.Context(), pluginID, plugin.Version)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"error": "Plugin code not found"})
		return
	}

	// Perform security scan
	scanResult, err := h.security.ScanPlugin(pluginCode.Code, plugin)
	if err != nil {
		h.logger.Error("Failed to scan plugin", map[string]interface{}{
			"plugin_id": pluginID,
			"error":     err.Error(),
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to scan plugin"})
		return
	}

	c.JSON(http.StatusOK, scanResult)
}

// ValidatePlugin validates plugin code and metadata
func (h *PluginHandler) ValidatePlugin(c *gin.Context) {
	var request struct {
		Metadata *PluginMetadata `json:"metadata" binding:"required"`
		Code     string          `json:"code" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	validator := NewValidator()

	// Validate metadata
	metadataErr := validator.ValidateMetadata(request.Metadata)
	
	// Validate code
	codeErr := validator.ValidateCode(request.Code, request.Metadata)

	result := map[string]interface{}{
		"valid":    metadataErr == nil && codeErr == nil,
		"metadata": map[string]interface{}{"valid": metadataErr == nil},
		"code":     map[string]interface{}{"valid": codeErr == nil},
	}

	if metadataErr != nil {
		result["metadata"].(map[string]interface{})["errors"] = metadataErr.Error()
	}

	if codeErr != nil {
		result["code"].(map[string]interface{})["errors"] = codeErr.Error()
	}

	c.JSON(http.StatusOK, result)
}

// SearchPlugins searches plugins in marketplace
func (h *PluginHandler) SearchPlugins(c *gin.Context) {
	query := c.Query("q")
	limit := 20

	if l := c.Query("limit"); l != "" {
		if parsed, err := strconv.Atoi(l); err == nil {
			limit = parsed
		}
	}

	plugins, err := h.registry.SearchPlugins(c.Request.Context(), query, limit)
	if err != nil {
		h.logger.Error("Failed to search plugins", map[string]interface{}{
			"query": query,
			"error": err.Error(),
		})
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to search plugins"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"plugins": plugins,
		"query":   query,
		"total":   len(plugins),
	})
}

// GetAvailableHooks returns available plugin hooks
func (h *PluginHandler) GetAvailableHooks(c *gin.Context) {
	hooks := []map[string]interface{}{
		{
			"name":        "email.received",
			"description": "Triggered when a new email is received",
			"payload": map[string]string{
				"email": "Email object with all email data",
			},
		},
		{
			"name":        "email.processed",
			"description": "Triggered when an email has been processed",
			"payload": map[string]string{
				"email": "Email object with processing results",
			},
		},
		{
			"name":        "email.sent",
			"description": "Triggered when an email is sent",
			"payload": map[string]string{
				"email": "Email object that was sent",
			},
		},
		{
			"name":        "workflow.start",
			"description": "Triggered when a workflow starts",
			"payload": map[string]string{
				"workflow_config": "Workflow configuration object",
			},
		},
		{
			"name":        "workflow.end",
			"description": "Triggered when a workflow completes",
			"payload": map[string]string{
				"workflow_result": "Workflow execution result",
			},
		},
		{
			"name":        "user.login",
			"description": "Triggered when a user logs in",
			"payload": map[string]string{
				"user": "User object",
			},
		},
		{
			"name":        "user.logout",
			"description": "Triggered when a user logs out",
			"payload": map[string]string{
				"user": "User object",
			},
		},
	}

	c.JSON(http.StatusOK, gin.H{
		"hooks": hooks,
		"total": len(hooks),
	})
}

// PublishPlugin publishes an approved plugin
func (h *PluginHandler) PublishPlugin(c *gin.Context) {
	pluginID := c.Param("id")

	err := h.registry.PublishPlugin(c.Request.Context(), pluginID)
	if err != nil {
		h.logger.Error("Failed to publish plugin", map[string]interface{}{
			"plugin_id": pluginID,
			"error":     err.Error(),
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Plugin published successfully",
	})
}

// ApprovePlugin approves a plugin for publication
func (h *PluginHandler) ApprovePlugin(c *gin.Context) {
	pluginID := c.Param("id")
	reviewerID := c.GetString("user_id")

	err := h.registry.ApprovePlugin(c.Request.Context(), pluginID, reviewerID)
	if err != nil {
		h.logger.Error("Failed to approve plugin", map[string]interface{}{
			"plugin_id":   pluginID,
			"reviewer_id": reviewerID,
			"error":       err.Error(),
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Plugin approved successfully",
	})
}

// RejectPlugin rejects a plugin
func (h *PluginHandler) RejectPlugin(c *gin.Context) {
	pluginID := c.Param("id")
	reviewerID := c.GetString("user_id")

	var request struct {
		Reason string `json:"reason" binding:"required"`
	}

	if err := c.ShouldBindJSON(&request); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	err := h.registry.RejectPlugin(c.Request.Context(), pluginID, request.Reason, reviewerID)
	if err != nil {
		h.logger.Error("Failed to reject plugin", map[string]interface{}{
			"plugin_id":   pluginID,
			"reviewer_id": reviewerID,
			"reason":      request.Reason,
			"error":       err.Error(),
		})
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message": "Plugin rejected successfully",
	})
}

// Additional helper methods...

// UpdatePlugin updates an existing plugin
func (h *PluginHandler) UpdatePlugin(c *gin.Context) {
	// Implementation for updating plugin
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented yet"})
}

// DeletePlugin deletes a plugin
func (h *PluginHandler) DeletePlugin(c *gin.Context) {
	// Implementation for deleting plugin
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented yet"})
}

// SuspendPlugin suspends a plugin
func (h *PluginHandler) SuspendPlugin(c *gin.Context) {
	// Implementation for suspending plugin
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented yet"})
}

// GetPluginCode retrieves plugin code
func (h *PluginHandler) GetPluginCode(c *gin.Context) {
	// Implementation for getting plugin code
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented yet"})
}

// UpdatePluginConfig updates plugin configuration
func (h *PluginHandler) UpdatePluginConfig(c *gin.Context) {
	// Implementation for updating plugin config
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented yet"})
}

// EnablePlugin enables a plugin
func (h *PluginHandler) EnablePlugin(c *gin.Context) {
	// Implementation for enabling plugin
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented yet"})
}

// DisablePlugin disables a plugin
func (h *PluginHandler) DisablePlugin(c *gin.Context) {
	// Implementation for disabling plugin
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented yet"})
}

// GetPluginInstance retrieves specific plugin instance
func (h *PluginHandler) GetPluginInstance(c *gin.Context) {
	// Implementation for getting plugin instance
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented yet"})
}

// GetPluginStats retrieves plugin statistics
func (h *PluginHandler) GetPluginStats(c *gin.Context) {
	// Implementation for getting plugin stats
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented yet"})
}

// ReloadPlugin reloads a plugin instance
func (h *PluginHandler) ReloadPlugin(c *gin.Context) {
	// Implementation for reloading plugin
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented yet"})
}

// GetMarketplace retrieves marketplace data
func (h *PluginHandler) GetMarketplace(c *gin.Context) {
	// Implementation for getting marketplace
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented yet"})
}

// GetCategories retrieves plugin categories
func (h *PluginHandler) GetCategories(c *gin.Context) {
	// Implementation for getting categories
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented yet"})
}

// GetPluginReviews retrieves plugin reviews
func (h *PluginHandler) GetPluginReviews(c *gin.Context) {
	// Implementation for getting plugin reviews
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented yet"})
}

// CreatePluginReview creates a plugin review
func (h *PluginHandler) CreatePluginReview(c *gin.Context) {
	// Implementation for creating plugin review
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented yet"})
}

// TestPlugin tests plugin functionality
func (h *PluginHandler) TestPlugin(c *gin.Context) {
	// Implementation for testing plugin
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented yet"})
}

// GetSDKDocs retrieves SDK documentation
func (h *PluginHandler) GetSDKDocs(c *gin.Context) {
	// Implementation for getting SDK docs
	c.JSON(http.StatusNotImplemented, gin.H{"error": "Not implemented yet"})
}