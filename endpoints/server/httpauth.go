package server

import (
	"fmt"
	"net/http"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

func (hs *HttpServer) authWithAspPlugin(c *gin.Context, req *common.HttpKnockRequest) {
	handler := hs.FindPluginHandler(req.AuthServiceId)
	if handler == nil {
		log.Error("no auth handler provided")
		c.JSON(http.StatusOK, gin.H{"errMsg": "no auth handler provided"})
		return
	}

	hs.runPluginAuth(c, req, handler)
}

// runPluginAuth calls the plugin's AuthWithHttp and handles the result.
// If the plugin aborted the context (e.g., NHP silent drop), no error
// response is written — preserving NHP protocol silence.
func (hs *HttpServer) runPluginAuth(c *gin.Context, req *common.HttpKnockRequest, handler plugins.PluginHandler) {
	helper := hs.NewHttpServerHelper()
	_, err := handler.AuthWithHttp(c, req, helper)
	if err != nil {
		log.Info("auth error: %v", err)
		if !c.Writer.Written() && !c.IsAborted() {
			c.JSON(http.StatusOK, gin.H{"errMsg": fmt.Sprintf("auth error: %v", err)})
		}
	} else {
		log.Info("auth completed successfully")
	}
}
