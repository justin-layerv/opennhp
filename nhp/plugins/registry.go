package plugins

import (
	"fmt"
	"sync"

	log "github.com/OpenNHP/opennhp/nhp/log"
)

// PluginFactory is a function that creates a new PluginHandler instance
type PluginFactory func() PluginHandler

var (
	// Global plugin registry - maps plugin IDs to their factory functions
	registryMu sync.RWMutex
	registry   = make(map[string]PluginFactory)
)

// RegisterPlugin registers a plugin factory with the given ID.
// This should be called during init() in each plugin package.
func RegisterPlugin(pluginId string, factory PluginFactory) {
	registryMu.Lock()
	defer registryMu.Unlock()

	if _, exists := registry[pluginId]; exists {
		log.Warning("Plugin %q is being re-registered, overwriting previous registration", pluginId)
	}
	registry[pluginId] = factory
	log.Info("Registered static plugin: %s", pluginId)
}

// GetPluginHandler returns a plugin handler for the given ID.
// It first checks the static registry, then falls back to dynamic loading.
// The pluginPath is only used for dynamic loading fallback.
func GetPluginHandler(pluginId string, pluginPath string) PluginHandler {
	// First try static registry
	registryMu.RLock()
	factory, found := registry[pluginId]
	registryMu.RUnlock()

	if found {
		log.Debug("Using statically registered plugin for %q", pluginId)
		return factory()
	}

	// Fall back to dynamic loading if path is provided
	if len(pluginPath) > 0 {
		log.Debug("Plugin %q not in registry, falling back to dynamic loading from %q", pluginId, pluginPath)
		return ReadPluginHandler(pluginPath)
	}

	log.Error("Plugin %q not found in registry and no plugin path provided", pluginId)
	return nil
}

// IsPluginRegistered checks if a plugin is registered in the static registry
func IsPluginRegistered(pluginId string) bool {
	registryMu.RLock()
	defer registryMu.RUnlock()
	_, found := registry[pluginId]
	return found
}

// ListRegisteredPlugins returns a list of all registered plugin IDs
func ListRegisteredPlugins() []string {
	registryMu.RLock()
	defer registryMu.RUnlock()

	ids := make([]string, 0, len(registry))
	for id := range registry {
		ids = append(ids, id)
	}
	return ids
}

// ClearRegistry clears all registered plugins (used for testing)
func ClearRegistry() {
	registryMu.Lock()
	defer registryMu.Unlock()
	registry = make(map[string]PluginFactory)
}

// ErrPluginNotRegistered is returned when a requested plugin is not found
var ErrPluginNotRegistered = fmt.Errorf("plugin not registered")
