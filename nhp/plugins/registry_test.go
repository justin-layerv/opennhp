package plugins

import (
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
)

// mockPluginHandler implements PluginHandler for testing
type mockPluginHandler struct {
	version   string
	signature string
	initError error
	closed    bool
}

func newMockPluginHandler(version string) *mockPluginHandler {
	return &mockPluginHandler{version: version}
}

func (m *mockPluginHandler) Version() string {
	return m.version
}

func (m *mockPluginHandler) Signature() string {
	return m.signature
}

func (m *mockPluginHandler) ExportedData() *PluginParamsOut {
	return nil
}

func (m *mockPluginHandler) Init(in *PluginParamsIn) error {
	return m.initError
}

func (m *mockPluginHandler) Close() error {
	m.closed = true
	return nil
}

func (m *mockPluginHandler) RequestOTP(req *common.NhpOTPRequest, helper *NhpServerPluginHelper) error {
	return errPluginNotImplemented
}

func (m *mockPluginHandler) RegisterAgent(req *common.NhpRegisterRequest, helper *NhpServerPluginHelper) (*common.ServerRegisterAckMsg, error) {
	return nil, errPluginNotImplemented
}

func (m *mockPluginHandler) ListService(req *common.NhpListRequest, helper *NhpServerPluginHelper) (*common.ServerListResultMsg, error) {
	return nil, errPluginNotImplemented
}

func (m *mockPluginHandler) AuthWithNHP(req *common.NhpAuthRequest, helper *NhpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	return nil, errPluginNotImplemented
}

func (m *mockPluginHandler) AuthWithHttp(ctx *gin.Context, req *common.HttpKnockRequest, helper *HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	return nil, errPluginNotImplemented
}

func TestRegisterPlugin(t *testing.T) {
	// Clear registry before test
	ClearRegistry()
	defer ClearRegistry()

	pluginId := "test-plugin"
	version := "v1.0.0"

	// Register a plugin
	RegisterPlugin(pluginId, func() PluginHandler {
		return newMockPluginHandler(version)
	})

	// Verify it's registered
	if !IsPluginRegistered(pluginId) {
		t.Errorf("Expected plugin %q to be registered", pluginId)
	}

	// Verify we can get a handler
	handler := GetPluginHandler(pluginId, "")
	if handler == nil {
		t.Fatalf("Expected to get a handler for plugin %q", pluginId)
	}

	if handler.Version() != version {
		t.Errorf("Expected version %q, got %q", version, handler.Version())
	}
}

func TestRegisterPlugin_Overwrite(t *testing.T) {
	// Clear registry before test
	ClearRegistry()
	defer ClearRegistry()

	pluginId := "test-plugin"
	version1 := "v1.0.0"
	version2 := "v2.0.0"

	// Register first version
	RegisterPlugin(pluginId, func() PluginHandler {
		return newMockPluginHandler(version1)
	})

	// Re-register with new version (should overwrite)
	RegisterPlugin(pluginId, func() PluginHandler {
		return newMockPluginHandler(version2)
	})

	// Should get the new version
	handler := GetPluginHandler(pluginId, "")
	if handler == nil {
		t.Fatalf("Expected to get a handler for plugin %q", pluginId)
	}

	if handler.Version() != version2 {
		t.Errorf("Expected version %q after overwrite, got %q", version2, handler.Version())
	}
}

func TestGetPluginHandler_NotRegistered(t *testing.T) {
	// Clear registry before test
	ClearRegistry()
	defer ClearRegistry()

	// Try to get an unregistered plugin without fallback path
	handler := GetPluginHandler("nonexistent", "")
	if handler != nil {
		t.Errorf("Expected nil handler for unregistered plugin, got %v", handler)
	}
}

func TestIsPluginRegistered(t *testing.T) {
	// Clear registry before test
	ClearRegistry()
	defer ClearRegistry()

	pluginId := "test-plugin"

	// Not registered yet
	if IsPluginRegistered(pluginId) {
		t.Errorf("Plugin should not be registered yet")
	}

	// Register it
	RegisterPlugin(pluginId, func() PluginHandler {
		return newMockPluginHandler("v1.0.0")
	})

	// Now it should be registered
	if !IsPluginRegistered(pluginId) {
		t.Errorf("Plugin should be registered now")
	}
}

func TestListRegisteredPlugins(t *testing.T) {
	// Clear registry before test
	ClearRegistry()
	defer ClearRegistry()

	// Empty registry
	plugins := ListRegisteredPlugins()
	if len(plugins) != 0 {
		t.Errorf("Expected empty list, got %v", plugins)
	}

	// Register some plugins
	RegisterPlugin("plugin-a", func() PluginHandler {
		return newMockPluginHandler("a")
	})
	RegisterPlugin("plugin-b", func() PluginHandler {
		return newMockPluginHandler("b")
	})
	RegisterPlugin("plugin-c", func() PluginHandler {
		return newMockPluginHandler("c")
	})

	// Verify count
	plugins = ListRegisteredPlugins()
	if len(plugins) != 3 {
		t.Errorf("Expected 3 plugins, got %d", len(plugins))
	}

	// Verify all are present
	pluginMap := make(map[string]bool)
	for _, p := range plugins {
		pluginMap[p] = true
	}
	for _, expected := range []string{"plugin-a", "plugin-b", "plugin-c"} {
		if !pluginMap[expected] {
			t.Errorf("Expected plugin %q in list", expected)
		}
	}
}

func TestClearRegistry(t *testing.T) {
	// Clear registry before test
	ClearRegistry()

	// Register some plugins
	RegisterPlugin("plugin-1", func() PluginHandler {
		return newMockPluginHandler("1")
	})
	RegisterPlugin("plugin-2", func() PluginHandler {
		return newMockPluginHandler("2")
	})

	// Verify they're registered
	if len(ListRegisteredPlugins()) != 2 {
		t.Errorf("Expected 2 plugins before clear")
	}

	// Clear and verify
	ClearRegistry()
	if len(ListRegisteredPlugins()) != 0 {
		t.Errorf("Expected 0 plugins after clear")
	}
}

func TestGetPluginHandler_FactoryCreatesFreshInstances(t *testing.T) {
	// Clear registry before test
	ClearRegistry()
	defer ClearRegistry()

	pluginId := "test-plugin"
	callCount := 0

	// Register a plugin that tracks how many times it's created
	RegisterPlugin(pluginId, func() PluginHandler {
		callCount++
		return newMockPluginHandler("v1.0.0")
	})

	// Get multiple handlers
	_ = GetPluginHandler(pluginId, "")
	_ = GetPluginHandler(pluginId, "")
	_ = GetPluginHandler(pluginId, "")

	// Factory should be called each time
	if callCount != 3 {
		t.Errorf("Expected factory to be called 3 times, got %d", callCount)
	}
}

func TestConcurrentRegistration(t *testing.T) {
	// Clear registry before test
	ClearRegistry()
	defer ClearRegistry()

	// Register plugins concurrently
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func(id int) {
			pluginId := "plugin-" + string(rune('a'+id%26)) + string(rune('0'+id%10))
			RegisterPlugin(pluginId, func() PluginHandler {
				return newMockPluginHandler("v1.0.0")
			})
			done <- true
		}(i)
	}

	// Wait for all registrations
	for i := 0; i < 100; i++ {
		<-done
	}

	// Registry should not have panicked and should have some plugins
	// (exact count depends on collision handling)
	plugins := ListRegisteredPlugins()
	if len(plugins) == 0 {
		t.Error("Expected some plugins to be registered after concurrent registration")
	}
}

func TestConcurrentGetPluginHandler(t *testing.T) {
	// Clear registry before test
	ClearRegistry()
	defer ClearRegistry()

	pluginId := "test-plugin"

	// Register a plugin
	RegisterPlugin(pluginId, func() PluginHandler {
		return newMockPluginHandler("v1.0.0")
	})

	// Get handlers concurrently
	done := make(chan bool)
	for i := 0; i < 100; i++ {
		go func() {
			handler := GetPluginHandler(pluginId, "")
			if handler == nil {
				t.Error("Got nil handler during concurrent access")
			}
			done <- true
		}()
	}

	// Wait for all gets
	for i := 0; i < 100; i++ {
		<-done
	}
}
