package passcode

import (
	"fmt"
	"net/http"
	"strings"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
	nhpplugins "github.com/fengyily/nhp-plugins-sdk"
	nhpsdkutils "github.com/fengyily/nhp-plugins-sdk/utils"
	"github.com/gin-gonic/gin"
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

	resp := &nhpplugins.RefreshResponse{}
	// interact with udp server for door operation
	ackMsg, err := helper.AuthWithHttpCallbackFunc(req, res)
	if ackMsg == nil || len(ackMsg.ResourceHost) == 0 {
		log.Error("knock failed. ackMsg is nil")
		ackMsg = &common.ServerKnockAckMsg{}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		if err != nil {
			ackMsg.ErrMsg = err.Error()
		} else {
			ackMsg.ErrMsg = "ackMsg is nil"
		}
		return ackMsg, "505", fmt.Errorf("knock failed. ackMsg is nil err: %s", ackMsg.ErrMsg)
	} else {
		log.Info("knock succeeded.%+v", res.Resources)

		jwt := &nhpplugins.JWTToken{
			JwtKey: []byte(nhpsdkutils.GetStringFromMap(res.ExInfo, "JWTSecret")),
		}
		nhpToken, refreshToken, err := jwt.GenerateAll(res.AuthServiceId, res)
		if err != nil {
			log.Error("failed to generate token: %v", err)
			ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
			ackMsg.ErrMsg = err.Error()
			ctx.JSON(http.StatusOK, ackMsg)
			return ackMsg, "410", err
		}
		log.Info("token: %s", nhpToken)

		ackMsg.ErrMsg = ""
		// auth action (WeChat Mini Program verification), user is anonymous
		ackMsg, redirectUrl, err := nhpplugins.GetRedirectUrlByResource(ackMsg, res, resourceHander.GetConfig(), "auth", "anonymous")
		if err != nil {
			log.Error("failed to get redirect url: %v", err)
			return ackMsg, "404", err
		}

		if len(redirectUrl) == 0 {
			log.Error("RedirectUrl is not provided.")
		} else {
			resp.RedirectUrl = redirectUrl
		}

		resp.CookieDomain = res.CookieDomain
		resp.ResourceHost = ackMsg.ResourceHost
		resp.NHPRefreshToken = refreshToken
		resp.NHPToken = nhpToken

		ctx.SetCookie("nhp_token", nhpToken, nhpsdkutils.GetIntFromMap(res.ExInfo, "TokenExpire"), "/", res.CookieDomain, true, true)
		ctx.SetCookie("nhp_refresh_token", refreshToken, nhpsdkutils.GetIntFromMap(res.ExInfo, "TokenExpire"), "/", res.CookieDomain, true, true)
		ctx.SetSameSite(http.SameSiteNoneMode)

		log.Info("ackMsg.ResourceHost: %+v", ackMsg.ResourceHost)
		if format == "json" {
			ctx.JSON(http.StatusOK, map[string]interface{}{
				"code":              0,
				"nhp_token":         nhpToken,
				"nhp_refresh_token": refreshToken,
				"redirect_url":      redirectUrl,
				"message":           "success",
			})
		} else {
			ctx.Redirect(http.StatusFound, redirectUrl)
		}

		return ackMsg, "", nil
	}
}
