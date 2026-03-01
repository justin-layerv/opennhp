package passcode

import (
	"fmt"
	"strings"

	nhpplugins "github.com/fengyily/nhp-plugins-sdk"
	nhpsdkutils "github.com/fengyily/nhp-plugins-sdk/utils"
	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

type MiniProgramInfo struct {
	IsWeChat        bool
	IsMiniProgram   bool
	WeChatVersion   string
	MiniProgramType string // web-view or other identifier
	RawUserAgent    string
}

func detectMiniProgram(userAgent string) MiniProgramInfo {
	info := MiniProgramInfo{
		RawUserAgent: userAgent,
	}

	ua := strings.ToLower(userAgent)

	// Detect WeChat
	info.IsWeChat = strings.Contains(ua, "micromessenger")

	// Detect Mini Program environment
	if info.IsWeChat {
		// Method 1: Check miniprogram keyword
		if strings.Contains(ua, "miniprogram") {
			info.IsMiniProgram = true
			info.MiniProgramType = "miniprogram"
		}

		// Method 2: Check MiniProgram/ identifier
		if strings.Contains(ua, "miniprogram/") {
			info.IsMiniProgram = true
			info.MiniProgramType = "miniprogram_slash"
		}

		// Extract WeChat version
		if start := strings.Index(ua, "micromessenger/"); start != -1 {
			start += len("micromessenger/")
			end := strings.Index(ua[start:], " ")
			if end == -1 {
				end = len(ua) - start
			}
			info.WeChatVersion = ua[start : start+end]
		}
	}

	return info
}

func std_auth(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, string, error) {
	if helper == nil {
		return nil, "400", fmt.Errorf(" authRegular helper is null")
	}
	format := ctx.Query("format")

	userAgent := ctx.Request.UserAgent()
	info := detectMiniProgram(userAgent)
	log.Debug("User Agent: %s", info.RawUserAgent)
	log.Debug("Is WeChat: %v", info.IsWeChat)
	log.Debug("Is Mini Program: %v", info.IsMiniProgram)
	log.Debug("WeChat Version: %s", info.WeChatVersion)
	log.Debug("Mini Program Type: %s", info.MiniProgramType)

	if info.IsMiniProgram || info.IsWeChat {
		log.Info("Access from WeChat Mini Program or WeChat Browser detected.")
	} else {
		log.Error("Authenticating browser access denied!")
		return nil, "403", fmt.Errorf("authenticating browser access denied! iswechat: %t, ismini:%t", info.IsWeChat, info.IsMiniProgram)
	}

	var err error
	secret := ctx.Query("secret")
	cfgSecret := nhpsdkutils.GetStringFromMap(res.ExInfo, "secret")
	if secret != cfgSecret {
		log.Error("Authenticating passcode: %s failed!", secret)
		return nil, "403", fmt.Errorf("authenticating passcode: %s failed", secret)
	}

	log.Debug("Authenticating passcode: %s succeeded!", secret)

	result, errCode, knockErr := knockAndIssueTokens(ctx, req, res, helper)
	if knockErr != nil {
		return nil, errCode, knockErr
	}

	ackMsg, redirectUrl, err := nhpplugins.GetRedirectUrlByResource(result.AckMsg, res, resourceHandler.GetConfig(), "auth", "anonymous")
	if err != nil {
		log.Error("failed to get redirect url: %v", err)
		return ackMsg, "404", err
	}

	if len(redirectUrl) == 0 {
		log.Error("RedirectUrl is not provided.")
	}

	log.Info("ackMsg.ResourceHost: %+v", ackMsg.ResourceHost)
	respondSuccessOrRedirect(ctx, format, result.NHPToken, result.RefreshToken, redirectUrl)
	return ackMsg, "", nil
}
