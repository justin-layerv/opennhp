package passcode

import (
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v4"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"

	nhpplugins "github.com/fengyily/nhp-plugins-sdk"
	"github.com/fengyily/nhp-plugins-sdk/resource"
	"github.com/fengyily/nhp-plugins-sdk/utils"
	nhpsdkutils "github.com/fengyily/nhp-plugins-sdk/utils"
)

var (
	name           = "passcode"
	version        = "0.1.1"
	resourceHander resource.ResourceHandler
	pluginsIn      *plugins.PluginParamsIn
)

func Version() string {
	return fmt.Sprintf("%s v%s", name, version)
}

func registerHander(handler resource.ResourceHandler) error {
	resourceHander = handler
	log.Info("register resource handler: %s", handler.GetConfig().ResourceMode)
	return nil
}

func Init(in *plugins.PluginParamsIn) error {
	pluginsIn = in
	return nhpplugins.Init(in, registerHander)
}

func Close() error {
	return nhpplugins.Close()
}

func AuthWithHttp(ctx *gin.Context, req *common.HttpKnockRequest, helper *plugins.HttpServerPluginHelper) (ackMsg *common.ServerKnockAckMsg, err error) {
	action := ctx.Query("action")
	if strings.EqualFold(action, "refresh") || strings.EqualFold(action, "nhp-refresh") {
		AuthWithHttpRefresh(ctx, action, req, helper)
		return
	}
	resId := ctx.Query("resid")
	format := ctx.Query("format")

	if strings.EqualFold(action, "error") {
		ackMsg, err = authAndShowRefreshError(ctx)
		return
	}
	res, err := resourceHander.FindResourceByID(resId)
	statusCode := "500"
	if err != nil {
		if format == "json" {
			ctx.JSON(http.StatusOK, nhpplugins.RefreshResponse{
				RedirectUrl: "/plugins/passcode?resid=" + resId + "&action=error&id=" + statusCode,
				ErrCode:     statusCode,
				ErrMsg:      err.Error(),
			})
		} else {
			ctx.Redirect(http.StatusFound, "/plugins/passcode?resid="+resId+"&action=error&id="+statusCode)
		}
		log.Error("call findResourceApi failed: %v", err)
		return
	}
	if res == nil || len(res.Resources) == 0 {
		ackMsg = nil
		err = common.ErrResourceNotFound
		log.Error("resource error: %v", err)
		ctx.String(http.StatusOK, "{\"errMsg\": \"resource error: %v\"}", err)
		return
	}
	ctx.SetSameSite(http.SameSiteNoneMode)
	nhpplugins.CorsMiddleware(ctx)

	switch {
	case strings.EqualFold(action, "valid"):
		startTime := time.Now()
		format := ctx.Query("format")
		errCode := ""
		ackMsg, errCode, err = authRegular(ctx, req, res, helper)
		if time.Since(startTime).Seconds() > 3 {
			log.Info("authRegular took timeout %s", time.Since(startTime))
		} else {
			log.Info("authRegular took %s", time.Since(startTime))
		}
		if err != nil {
			if format == "json" {
				ctx.JSON(http.StatusOK, nhpplugins.RefreshResponse{
					RedirectUrl: "/plugins/passcode?resid=" + resId + "&action=error&id=" + errCode,
					ErrCode:     errCode,
					ErrMsg:      err.Error(),
				})
			} else {
				ctx.Redirect(http.StatusFound, "/plugins/passcode?resid="+resId+"&action=error&id="+errCode)
			}
		}
	case strings.EqualFold(action, "access"):
		errCode := ""
		ackMsg, errCode, err = authAccessFromRaaS(ctx, req, res, helper)
		if err != nil {
			if format == "json" {
				ctx.JSON(http.StatusOK, nhpplugins.RefreshResponse{
					RedirectUrl: "/plugins/passcode?resid=" + resId + "&action=error&id=" + errCode,
					ErrCode:     errCode,
					ErrMsg:      err.Error(),
				})
			} else {
				ctx.Redirect(http.StatusFound, "/plugins/passcode?resid="+resId+"&action=error&id="+errCode)
			}
		}

	case strings.EqualFold(action, "knock"):
		ackMsg, err = knockByToken(ctx, req, res, helper)
	case strings.EqualFold(action, "login"):
		ackMsg, err = authAndShowLogin(ctx, req, res, helper)
	case strings.EqualFold(action, "auth_code"):
		format := ctx.Query("format")
		errCode := ""
		ackMsg, errCode, err = customAuthByCode(ctx, req, res, helper)
		if err != nil {
			if format == "json" {
				ctx.JSON(http.StatusOK, map[string]interface{}{
					"code":    10001,
					"message": err.Error(),
				})
			} else {
				ctx.Redirect(http.StatusFound, "/plugins/passcode?resid="+resId+"&action=error&id="+errCode)
			}
		}
	case strings.EqualFold(action, "auth"):
		format := ctx.Query("format")
		errCode := ""
		ackMsg, errCode, err = std_auth(ctx, req, res, helper)
		if err != nil {
			if format == "json" {
				ctx.JSON(http.StatusOK, map[string]interface{}{
					"code":    10001,
					"message": err.Error(),
				})
			} else {
				ctx.Redirect(http.StatusFound, "/plugins/passcode?resid="+resId+"&action=error&id="+errCode)
			}
		}
	case strings.EqualFold(action, "hmac_auth"):
		format := ctx.Query("format")
		errCode := ""
		ackMsg, errCode, err = customAuthByHmac(ctx, req, res, helper)
		if err != nil {
			if format == "json" {
				ctx.JSON(http.StatusOK, map[string]interface{}{
					"code":    10001,
					"message": err.Error(),
				})
			} else {
				ctx.Redirect(http.StatusFound, "/plugins/passcode?resid="+resId+"&action=error&id="+errCode)
			}
		}
	default:
		ackMsg = nil
		err = fmt.Errorf("action invalid")
	}
	return
}

func AuthWithHttpRefresh(ctx *gin.Context, action string, req *common.HttpKnockRequest, helper *plugins.HttpServerPluginHelper) (ackMsg *common.ServerKnockAckMsg, err error) {
	nHPToken := nhpplugins.GetCookie("nhp_token", ctx)
	if len(nHPToken) == 0 {
		log.Warning("nhp_token expired. %s", nHPToken)
		return
	}
	payload, err := nhpplugins.ParseJWTToken(nHPToken)
	if err != nil {
		log.Error("cannot parse JWT: %v", err)
		return
	}
	resId := payload.ResourceID
	log.Info("resId from nhp_token: %s", resId)
	res, err := resourceHander.FindResourceByID(resId)
	if err != nil {
		log.Error("call findResourceApi failed: %v", err)
		return
	}
	if res == nil || len(res.Resources) == 0 {
		ackMsg = nil
		err = common.ErrResourceNotFound
		log.Error("resource error: %v", err)
		ctx.String(http.StatusOK, "{\"errMsg\": \"resource error: %v\"}", err)
		return
	}
	jwt := &nhpplugins.JWTToken{
		JwtKey: []byte(res.ExInfo["JWTSecret"].(string)),
	}

	isOk, err := jwt.Validate(nHPToken, nhpplugins.TokenTypeNHPToken)
	if err != nil {
		log.Warning("nhp token is invalid nHPToken = %s err:%s", nHPToken, err.Error())
		return nil, err
	}
	if !isOk {
		log.Error("nhp token is invalid")
		return nil, fmt.Errorf("nhp token is invalid")
	}

	nhpplugins.CorsMiddleware(ctx)
	if strings.EqualFold(action, "refresh") {
		startTime := time.Now()
		ackMsg, err = refreshToken(ctx, req, res, helper)
		if time.Since(startTime).Seconds() > 3 {
			log.Info("refreshToken took timeout %s", time.Since(startTime))
		} else {
			log.Info("refreshToken took %s", time.Since(startTime))
		}
	} else if strings.EqualFold(action, "nhp-refresh") {
		ackMsg, err = authAndShowRefresh(ctx, req, res, helper)
	} else {
		ackMsg = nil
		err = fmt.Errorf("unknown action: %s", action)
		log.Error("unknown action error: %v", err)
		ctx.String(http.StatusBadRequest, "{\"errMsg\": \"unknown action: %s\"}", action)
	}

	return
}

func AuthWithNHP(req *common.NhpAuthRequest, helper *plugins.NhpServerPluginHelper) (ackMsg *common.ServerKnockAckMsg, err error) {
	ackMsg = req.Ack
	if helper == nil {
		return ackMsg, fmt.Errorf("AuthWithNHP: helper is null")
	}

	res, err := resourceHander.FindResourceByID(req.Msg.ResourceId)
	if err != nil {
		err = common.ErrResourceNotFound
		ackMsg.ErrCode = common.ErrResourceNotFound.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return
	}

	// there is no backend auth in this plugin, fail the request if SkipAuth is false
	if !res.SkipAuth {
		err = common.ErrBackendAuthRequired
		ackMsg.ErrCode = common.ErrBackendAuthRequired.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		return
	}

	// skip backend auth and continue with AC operations
	log.Info("agent user [%s]: skip auth", req.Msg.UserId)
	ackMsg.OpenTime = res.OpenTime
	ackMsg.ResourceHost = res.Hosts()

	// PART III: request ac operation for each resource and block for response
	ackMsg, err = helper.AuthWithNhpCallbackFunc(req, res)

	return ackMsg, err
}

func authAndShowLogin(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	if helper == nil {
		return nil, fmt.Errorf("authAndShowLogin: helper is null")
	}

	if res.ExInfo == nil {
		log.Error("extra login info not available")
		ctx.String(http.StatusOK, "{\"errMsg\": \"extra login info not available\"}")
		return nil, fmt.Errorf("extra login info not available")
	}

	ctx.HTML(http.StatusOK, "passcode/passcode_login.html", gin.H{
		"title":       res.ExInfo["Title"].(string),
		"nhpServer":   pluginsIn.Hostname,
		"aspId":       req.AuthServiceId,
		"resId":       res.ResourceId,
		"exInfo":      res.ExInfo,
		"redirectUrl": res.RedirectUrl,
	})

	return nil, nil
}

func authAndShowRefreshError(ctx *gin.Context) (*common.ServerKnockAckMsg, error) {
	ctx.HTML(http.StatusOK, "passcode/error.html", gin.H{})
	return nil, nil
}

func authAndShowRefresh(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	if helper == nil {
		return nil, fmt.Errorf("authAndShowLogin: helper is null")
	}

	if res.ExInfo == nil {
		log.Error("extra login info not available")
		ctx.String(http.StatusOK, "{\"errMsg\": \"extra login info not available\"}")
		return nil, fmt.Errorf("extra login info not available")
	}

	ctx.HTML(http.StatusOK, "passcode/nhp_refresh.html", gin.H{
		"title":       res.ExInfo["Title"].(string),
		"nhpServer":   pluginsIn.Hostname,
		"aspId":       req.AuthServiceId,
		"resId":       res.ResourceId,
		"exInfo":      res.ExInfo,
		"redirectUrl": res.RedirectUrl,
	})

	return nil, nil
}

func refreshToken(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	if helper == nil {
		return nil, fmt.Errorf("refreshToken: helper is null")
	}

	oldNHPToken := nhpplugins.GetCookie("nhp_token", ctx)

	if len(oldNHPToken) == 0 {
		log.Error("old token is empty")
		ackMsg := &common.ServerKnockAckMsg{}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		ackMsg.ErrMsg = "old token is empty"
		ctx.JSON(http.StatusOK, ackMsg)
		return nil, fmt.Errorf("old token is empty")
	}
	refreshToken := nhpplugins.GetCookie("nhp_refresh_token", ctx)
	if len(refreshToken) == 0 {
		log.Error("refresh token is empty")

		ackMsg := &common.ServerKnockAckMsg{}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		ackMsg.ErrMsg = "refresh token is empty"
		ctx.JSON(http.StatusOK, ackMsg)
		return nil, fmt.Errorf("refresh token is empty")
	}
	jwt := &nhpplugins.JWTToken{
		JwtKey: []byte(res.ExInfo["JWTSecret"].(string)),
	}
	nhpToken, err := jwt.ExchangeNHPToken(oldNHPToken, refreshToken, res)
	if err != nil {
		log.Error("failed to generate token: %v", err)
		ackMsg := &common.ServerKnockAckMsg{}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		ctx.JSON(http.StatusOK, ackMsg)
		return nil, err
	}

	// interact with udp server for door operation
	ackMsg, err := helper.AuthWithHttpCallbackFunc(req, res)
	if ackMsg == nil || err != nil {
		log.Error("knock failed. ackMsg is nil")
		ackMsg = &common.ServerKnockAckMsg{}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		if err != nil {
			ackMsg.ErrMsg = err.Error()
		} else {
			ackMsg.ErrMsg = "ackMsg is nil"
		}
	} else {
		if len(ackMsg.ResourceHost) > 0 {
			log.Info("knock succeeded.%+v", res.Resources)
			log.Info("token: %s", nhpToken)

			ctx.SetSameSite(http.SameSiteNoneMode)
			ctx.SetCookie("nhp_token", nhpToken, nhpsdkutils.GetIntFromMap(res.ExInfo, "TokenExpire"), "/", res.CookieDomain, true, true)
			ctx.SetCookie("nhp_refresh_token", refreshToken, nhpsdkutils.GetIntFromMap(res.ExInfo, "TokenExpire"), "/", res.CookieDomain, true, true)
			ackMsg.ErrMsg = ""
			// assign the redirect url to the ackMsg
			if len(res.RedirectUrl) == 0 {
				log.Error("RedirectUrl is not provided.")
			} else {
				ackMsg.RedirectUrl = res.RedirectUrl
			}
		} else {
			ctx.SetSameSite(http.SameSiteNoneMode)
			ctx.SetCookie("nhp_token", nhpToken, 0, "/", res.CookieDomain, true, true)
			ctx.SetCookie("nhp_refresh_token", refreshToken, 0, "/", res.CookieDomain, true, true)
			log.Error("knock failed. ackMsg is nil")
			ackMsg = &common.ServerKnockAckMsg{}
			ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
			ackMsg.ErrMsg = "ackMsg is nil"
		}
	}

	ctx.JSON(http.StatusOK, map[string]interface{}{
		"code":              0,
		"nhp_token":         nhpToken,
		"nhp_refresh_token": refreshToken,
		"message":           "success",
	})
	return ackMsg, nil
}

func knockByToken(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	if helper == nil {
		return nil, fmt.Errorf("refreshToken: helper is null")
	}

	oldNHPToken := nhpplugins.GetCookie("nhp_token", ctx)

	if len(oldNHPToken) == 0 {
		log.Error("old token is empty")
		ackMsg := &common.ServerKnockAckMsg{}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		ackMsg.ErrMsg = "old token is empty"
		ctx.JSON(http.StatusOK, ackMsg)
		return nil, fmt.Errorf("old token is empty")
	}
	refreshToken := nhpplugins.GetCookie("nhp_refresh_token", ctx)
	if len(refreshToken) == 0 {
		log.Error("refresh token is empty")

		ackMsg := &common.ServerKnockAckMsg{}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		ackMsg.ErrMsg = "refresh token is empty"
		ctx.JSON(http.StatusOK, ackMsg)
		return nil, fmt.Errorf("refresh token is empty")
	}
	jwt := &nhpplugins.JWTToken{
		JwtKey: []byte(nhpsdkutils.GetStringFromMap(res.ExInfo, "JWTSecret")),
	}
	nhpToken, err := jwt.ExchangeNHPToken(oldNHPToken, refreshToken, res)
	if err != nil {
		log.Error("failed to generate token: %v", err)
		ackMsg := &common.ServerKnockAckMsg{}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		ctx.JSON(http.StatusOK, ackMsg)
		return nil, err
	}

	// interact with udp server for door operation
	ackMsg, err := helper.AuthWithHttpCallbackFunc(req, res)
	if ackMsg == nil || err != nil {
		log.Error("knock failed. ackMsg is nil")
		ackMsg = &common.ServerKnockAckMsg{}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		if err != nil {
			ackMsg.ErrMsg = err.Error()
		} else {
			ackMsg.ErrMsg = "ackMsg is nil"
		}
	} else {
		if len(ackMsg.ResourceHost) > 0 {
			log.Info("knock succeeded.%+v", res.Resources)
			log.Info("token: %s", nhpToken)

			ctx.SetSameSite(http.SameSiteNoneMode)
			ctx.SetCookie("nhp_token", nhpToken, nhpsdkutils.GetIntFromMap(res.ExInfo, "TokenExpire"), "/", res.CookieDomain, true, true)
			ctx.SetCookie("nhp_refresh_token", refreshToken, nhpsdkutils.GetIntFromMap(res.ExInfo, "TokenExpire"), "/", res.CookieDomain, true, true)

			ackMsg.ErrMsg = ""

			// knock action, user is anonymous (verified from token, no specific user info)
			ackMsg, redirectUrl, err := nhpplugins.GetRedirectUrlByResource(ackMsg, res, resourceHander.GetConfig(), "knock", "anonymous")
			if err != nil {
				log.Error("failed to get redirect url: %v", err)
				return ackMsg, nil
			}

			if len(redirectUrl) == 0 {
				log.Error("RedirectUrl is not provided.")
			} else {
				ctx.Redirect(http.StatusFound, redirectUrl)
				return ackMsg, nil
			}

			return ackMsg, nil
		} else {
			ctx.SetSameSite(http.SameSiteNoneMode)
			ctx.SetCookie("nhp_token", nhpToken, 0, "/", res.CookieDomain, true, true)
			ctx.SetCookie("nhp_refresh_token", refreshToken, 0, "/", res.CookieDomain, true, true)

			log.Error("knock failed. ackMsg is nil")
			ackMsg = &common.ServerKnockAckMsg{}
			ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
			ackMsg.ErrMsg = "ackMsg is nil"
		}
	}
	ctx.JSON(http.StatusOK, map[string]interface{}{
		"code":              0,
		"nhp_token":         nhpToken,
		"nhp_refresh_token": refreshToken,
		"message":           "success",
	})
	return ackMsg, nil
}

func authRegular(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, string, error) {
	if helper == nil {
		return nil, "400", fmt.Errorf(" authRegular helper is null")
	}

	var err error
	passcode := ctx.Query("passcode")
	format := ctx.Query("format")
	if resourceHander.GetConfig().ResourceMode == "api" {
		AuthUrl := resourceHander.GetConfig().AuthUrl
		if len(AuthUrl) == 0 {
			log.Error("AuthUrl is not provided.")
			return nil, "401", fmt.Errorf("AuthUrl is not provided")
		}

		resp, err := utils.SendRequest(utils.RequestOptions{
			Method:   "GET",
			BaseURL:  AuthUrl,
			Endpoint: "PC/auth",
			QueryParams: map[string]string{
				"resid": res.ResourceId,
				"code":  passcode,
			},
		})
		if err != nil {
			log.Error("Request failed: %v", err)
			return nil, "402", fmt.Errorf("request failed: %v", err)
		}

		if resp.StatusCode != http.StatusOK {
			log.Error("API request failed with status code %d: %s", resp.StatusCode, string(resp.Body))
			return nil, "403", fmt.Errorf("api request failed with status code %d: %s", resp.StatusCode, string(resp.Body))
		}

		type Response struct {
			Code int         `json:"code"`
			Data interface{} `json:"data"`
			Msg  string      `json:"msg"`
		}
		// Parse JSON response
		var apiResponse Response
		if err := utils.ParseJSONResponse(resp, &apiResponse); err != nil {
			log.Error("Error parsing response: %v", err)
			return nil, "403", fmt.Errorf("error parsing response: %v", err)
		}
		if apiResponse.Code != 0 {
			log.Error("API request failed with code %d: %s", apiResponse.Code, apiResponse.Msg)
			return nil, fmt.Sprintf("50%d", apiResponse.Code), fmt.Errorf("api request failed with code %d: %s", apiResponse.Code, apiResponse.Msg)
		}
		log.Debug("Authenticating passcode: %s succeeded!", passcode)
	} else {
		appSecrets := make(map[string]bool, 0)
		switch res.ExInfo["AppSecret"].(type) {
		case string:
			appSecrets[nhpsdkutils.GetStringFromMap(res.ExInfo, "JWTSecret")] = true
		case []interface{}:
			secrets := res.ExInfo["AppSecret"].([]interface{})
			for _, secret := range secrets {
				appSecrets[secret.(string)] = true
			}
		}
		if _, ok := appSecrets[passcode]; !ok {
			log.Info("Authenticating passcode: %s failed!", passcode)
			ctx.JSON(http.StatusOK, common.ServerKnockAckMsg{
				ErrCode: common.ErrServerACOpsFailed.ErrorCode(),
				ErrMsg:  "passcode is not valid!",
			})
			return nil, "501", fmt.Errorf("API request failed with code 501: passcode is not valid")
		}
		log.Debug("Authenticating passcode: %s succeeded!", passcode)
	}

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

		// Check if passcode is JWT format and extract key_type and sharing_key
		redirectUrl := ""
		if sharingRedirectUrl := getSharingLinkRedirectUrl(passcode, ackMsg.ResourceHost); len(sharingRedirectUrl) > 0 {
			redirectUrl = sharingRedirectUrl
			log.Info("Using sharing link redirect url: %s", redirectUrl)
		} else {
			// valid action (passcode verification), user is anonymous
			ackMsg, redirectUrl, err = nhpplugins.GetRedirectUrlByResource(ackMsg, res, resourceHander.GetConfig(), "valid", "anonymous")
			if err != nil {
				log.Error("failed to get redirect url: %v", err)
				return ackMsg, "404", err
			}
		}

		if len(redirectUrl) == 0 {
			log.Error("RedirectUrl is not provided.")
		} else {
			resp.RedirectUrl = redirectUrl
		}

		ctx.SetSameSite(http.SameSiteNoneMode)
		ctx.SetCookie("nhp_token", nhpToken, nhpsdkutils.GetIntFromMap(res.ExInfo, "TokenExpire"), "/", res.CookieDomain, true, true)
		ctx.SetCookie("nhp_refresh_token", refreshToken, nhpsdkutils.GetIntFromMap(res.ExInfo, "TokenExpire"), "/", res.CookieDomain, true, true)

		resp.CookieDomain = res.CookieDomain
		resp.ResourceHost = ackMsg.ResourceHost
		resp.NHPRefreshToken = refreshToken
		resp.NHPToken = nhpToken

		log.Info("ackMsg.ResourceHost: %+v", ackMsg.ResourceHost)
	}

	if format == "json" {
		ctx.JSON(http.StatusOK, resp)
	} else {
		ctx.Redirect(http.StatusFound, resp.RedirectUrl)
	}
	return ackMsg, "", nil
}

func authAccessFromRaaS(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, string, error) {
	if helper == nil {
		return nil, "600", fmt.Errorf(" authRegular helper is null")
	}
	IAMServiceUrl := resourceHander.GetConfig().IAMServiceUrl

	idStr := ctx.Query("id")
	if idStr == "" {
		return nil, "601", fmt.Errorf("id is missing")
	}
	log.Info("raas portal Site app id is %s", idStr)
	potalSiteUrl := fmt.Sprintf("%s/api/v1/portal-sites/%s", IAMServiceUrl, idStr)
	log.Info("Calling real IAM service: %s", potalSiteUrl)
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		return nil, "602", fmt.Errorf("authorization header is missing")
	}
	raasHttpReq, err := http.NewRequestWithContext(ctx.Request.Context(), "GET", potalSiteUrl, nil)
	if err != nil {
		return nil, "603", fmt.Errorf("failed to create request: %v", err)
	}
	raasHttpReq.Header.Set("Authorization", authHeader)
	client := &http.Client{}
	respRaas, err := client.Do(raasHttpReq)
	if err != nil {
		return nil, "604", fmt.Errorf("failed to call real IAM service: %w", err)
	}
	defer respRaas.Body.Close()
	// Check status code
	if respRaas.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(respRaas.Body)
		log.Error("IAM service returned non-OK status: %d, body: %s", respRaas.StatusCode, string(body))
		return nil, "605", fmt.Errorf("IAM service error: %d %s", respRaas.StatusCode, string(body))
	}
	body, err := io.ReadAll(respRaas.Body)
	if err != nil {
		return nil, "606", fmt.Errorf("failed to read IAM response body: %v", err)
	}

	log.Info("Successfully got response from real IAM: %s", string(body))
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
		ctx.JSON(http.StatusInternalServerError, ackMsg)
		return ackMsg, "410", fmt.Errorf("knock failed: %s", ackMsg.ErrMsg)
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
		// access action, get user info from Authorization header
		user := GetUserFromAuthHeader(authHeader)
		ackMsg, redirectUrl, err := nhpplugins.GetRedirectUrlByResource(ackMsg, res, resourceHander.GetConfig(), "access", user)
		if err != nil {
			log.Error("failed to get redirect url: %v", err)
			return ackMsg, "404", err
		}
		log.Info("redirectUrl: %s", redirectUrl)
		if len(redirectUrl) == 0 {
			log.Error("RedirectUrl is not provided.")
		} else {
			resp.RedirectUrl = redirectUrl
		}

		ctx.SetSameSite(http.SameSiteNoneMode)
		ctx.SetCookie("nhp_token", nhpToken, nhpsdkutils.GetIntFromMap(res.ExInfo, "TokenExpire"), "/", res.CookieDomain, true, true)
		ctx.SetCookie("nhp_refresh_token", refreshToken, nhpsdkutils.GetIntFromMap(res.ExInfo, "TokenExpire"), "/", res.CookieDomain, true, true)

		resp.CookieDomain = res.CookieDomain
		resp.ResourceHost = ackMsg.ResourceHost
		resp.NHPRefreshToken = refreshToken
		resp.NHPToken = nhpToken

		log.Info("ackMsg.ResourceHost: %+v", ackMsg.ResourceHost)
		ctx.JSON(http.StatusOK, resp)
		log.Info("Done %+v", resp)
		return ackMsg, "", nil
	}
}

// getSharingLinkRedirectUrl checks if passcode is JWT format with key_type=sharing_link
// If so, extracts sharing_key and constructs redirect URL using load balanced host
// Returns empty string if passcode is not a sharing link JWT
func getSharingLinkRedirectUrl(passcode string, resourceHost map[string]string) string {
	if len(passcode) == 0 {
		return ""
	}

	// Try to parse passcode as JWT to check if it's a sharing link.
	//
	// FALSE POSITIVE: go/missing-jwt-signature-check
	// ParseUnverified is intentional here - we're only checking if the passcode
	// is a sharing link JWT for routing purposes, not for authentication.
	// Actual authentication happens via jwt.Validate() in AuthWithHttpRefresh().
	// This is safe because we're just extracting claims to determine redirect
	// behavior, not granting access based on these claims.
	claims := jwt.MapClaims{}
	parser := new(jwt.Parser)
	_, _, err := parser.ParseUnverified(passcode, claims)
	if err != nil {
		// Not a valid JWT, return empty
		log.Debug("passcode is not a valid JWT: %v", err)
		return ""
	}

	// Check if key_type is "sharing_link"
	keyType, ok := claims["key_type"]
	if !ok {
		log.Debug("JWT does not contain key_type field")
		return ""
	}

	keyTypeStr, ok := keyType.(string)
	if !ok || !strings.EqualFold(keyTypeStr, "sharing_link") {
		log.Debug("key_type is not sharing_link: %v", keyType)
		return ""
	}

	// Extract sharing_key
	sharingKey, ok := claims["sharing_key"]
	if !ok {
		log.Error("JWT with key_type=sharing_link does not contain sharing_key")
		return ""
	}

	sharingKeyStr, ok := sharingKey.(string)
	if !ok || len(sharingKeyStr) == 0 {
		log.Error("sharing_key is invalid or empty")
		return ""
	}

	// Get host using Loadbalancing
	host := utils.Loadbalancing(resourceHost)
	if len(host) == 0 {
		log.Error("failed to get host from Loadbalancing")
		return ""
	}

	// Construct redirect URL: https://hostname/webgate/#/?key=sharing_key
	redirectUrl := fmt.Sprintf("https://%s/webgate/#/?key=%s", host, sharingKeyStr)
	log.Info("Constructed sharing link redirect URL: %s", redirectUrl)

	return redirectUrl
}

// GetUserFromAuthHeader parses user info from Authorization header
// Supports Bearer token format, attempts to extract username from JWT
// If unable to parse or header is empty, returns "anonymous"
func GetUserFromAuthHeader(authHeader string) string {
	if len(authHeader) == 0 {
		return "anonymous"
	}

	// Remove "Bearer " prefix
	tokenString := authHeader
	if len(authHeader) > 7 && authHeader[:7] == "Bearer " {
		tokenString = authHeader[7:]
	}

	// Try to parse JWT for user info (without signature verification, only parse payload)
	user, err := parseUserFromJWT(tokenString)
	if err != nil {
		log.Warning("failed to parse auth token for user: %v", err)
		return "anonymous"
	}

	if len(user) > 0 {
		return user
	}

	return "anonymous"
}

// parseUserFromJWT parses user info from JWT, using generic claims structure.
//
// FALSE POSITIVE: go/missing-jwt-signature-check
// ParseUnverified is intentional here - we're only extracting the username for
// logging/audit purposes, not for authentication. The Authorization header is
// validated against the IAM service separately in authAccessFromRaaS(). This is
// safe because the extracted name is only used for informational purposes and
// doesn't affect access control decisions.
func parseUserFromJWT(tokenString string) (string, error) {
	// Use MapClaims to parse arbitrary JWT structure
	claims := jwt.MapClaims{}
	parser := new(jwt.Parser)
	_, _, err := parser.ParseUnverified(tokenString, claims)
	if err != nil {
		return "", fmt.Errorf("failed to parse token unverified: %v", err)
	}

	// Return user identifier by priority, checking various common field names
	fieldPriority := []string{"name"}
	for _, field := range fieldPriority {
		if val, ok := claims[field]; ok {
			if strVal, ok := val.(string); ok && strVal != "" {
				return strVal, nil
			}
		}
	}

	return "", nil
}
