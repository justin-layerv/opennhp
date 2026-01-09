package passcode

import (
	"fmt"
	"net/http"

	nhpplugins "github.com/fengyily/nhp-plugins-sdk"
	nhpsdkutils "github.com/fengyily/nhp-plugins-sdk/utils"
	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

// customAuthByHmac authenticates using HMAC signature
// Gets HMAC signature from Authorization header, format: HMAC resId:timestamp:signature
// res.ExInfo must contain: SecretKey, Algorithm (optional, defaults to sha256)
// AccessKey uses resId
func customAuthByHmac(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, string, error) {
	if helper == nil {
		return nil, "400", fmt.Errorf("customAuthByHmac helper is null")
	}

	format := ctx.Query("format")

	// 1. Get HMAC configuration from ExInfo
	secretKey := nhpsdkutils.GetStringFromMap(res.ExInfo, "SecretKey")
	if len(secretKey) == 0 {
		log.Error("SecretKey is not provided in ExInfo")
		return nil, "401", fmt.Errorf("SecretKey is not provided")
	}

	algorithm := nhpsdkutils.GetStringFromMap(res.ExInfo, "Algorithm")
	if len(algorithm) == 0 {
		algorithm = "sha256" // Default to sha256
	}

	expireSec := nhpsdkutils.GetIntFromMap(res.ExInfo, "ExpireSec")
	if expireSec == 0 {
		expireSec = 300 // Default 5 minutes validity
	}

	// 2. Get Authorization header
	authHeader := ctx.GetHeader("Authorization")
	if len(authHeader) == 0 {
		log.Error("Authorization header is empty")
		return nil, "402", fmt.Errorf("authorization header is empty")
	}

	// 3. Verify HMAC signature (AccessKey uses resId)
	valid, err := VerifyHMACFromHeader(res.ResourceId, secretKey, algorithm, expireSec, authHeader)
	if err != nil {
		log.Error("HMAC verification failed: %v", err)
		return nil, "403", fmt.Errorf("HMAC verification failed: %v", err)
	}
	if !valid {
		log.Error("HMAC signature is invalid")
		return nil, "403", fmt.Errorf("HMAC signature is invalid")
	}

	log.Debug("HMAC authentication succeeded for resource: %s", res.ResourceId)

	// 4. Business logic after authentication passed (same as customAuthByCode)
	//resp := &nhpplugins.RefreshResponse{}
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
	}

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
	// hmac action (verified via HMAC), user is anonymous
	ackMsg, redirectUrl, err := nhpplugins.GetRedirectUrlByResource(ackMsg, res, resourceHander.GetConfig(), "hmac", "anonymous")
	if err != nil {
		log.Error("failed to get redirect url: %v", err)
		return ackMsg, "404", err
	}

	if len(redirectUrl) == 0 {
		log.Error("RedirectUrl is not provided.")
	}

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

func customAuthByCode(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, string, error) {
	if helper == nil {
		return nil, "400", fmt.Errorf(" authRegular helper is null")
	}

	var err error
	passcode := ctx.Query("code")
	state := ctx.Query("state")
	format := ctx.Query("format")
	AuthUrl := nhpsdkutils.GetStringFromMap(res.ExInfo, "AuthUrl")
	if len(AuthUrl) == 0 {
		log.Error("AuthUrl is not provided.")
		return nil, "401", fmt.Errorf("AuthUrl is not provided")
	}

	method := nhpsdkutils.GetStringFromMap(res.ExInfo, "Method")
	if len(method) == 0 {
		method = "GET"
	}
	authResp, err := nhpsdkutils.SendRequest(nhpsdkutils.RequestOptions{
		Method:   method,
		BaseURL:  AuthUrl,
		Endpoint: "",
		QueryParams: map[string]string{
			"resid":  res.ResourceId,
			"code":   passcode,
			"secret": nhpsdkutils.GetStringFromMap(res.ExInfo, "AppSecret"),
			"state":  state,
		},
	})
	if err != nil {
		log.Error("Request failed: %v", err)
		return nil, "402", fmt.Errorf("request failed: %v", err)
	}

	if authResp.StatusCode != http.StatusOK {
		log.Error("API request failed with status code %d: %s", authResp.StatusCode, string(authResp.Body))
		return nil, "403", fmt.Errorf("api request failed with status code %d: %s", authResp.StatusCode, string(authResp.Body))
	}

	type Response struct {
		Code int         `json:"code"`
		Data interface{} `json:"data"`
		Msg  string      `json:"msg"`
	}
	// Parse JSON response
	var apiResponse Response
	if err := nhpsdkutils.ParseJSONResponse(authResp, &apiResponse); err != nil {
		log.Error("Error parsing response: %v", err)
		return nil, "403", fmt.Errorf("error parsing response: %v", err)
	}
	if apiResponse.Code != 0 {
		log.Error("API request failed with code %d: %s", apiResponse.Code, apiResponse.Msg)
		return nil, fmt.Sprintf("50%d", apiResponse.Code), fmt.Errorf("api request failed with code %d: %s", apiResponse.Code, apiResponse.Msg)
	}
	log.Debug("Authenticating passcode: %s succeeded!", passcode)

	//resp := &nhpplugins.RefreshResponse{}
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
		// auth_code action (verified via authorization code), user is anonymous
		ackMsg, redirectUrl, err := nhpplugins.GetRedirectUrlByResource(ackMsg, res, resourceHander.GetConfig(), "auth_code", "anonymous")
		if err != nil {
			log.Error("failed to get redirect url: %v", err)
			return ackMsg, "404", err
		}

		if len(redirectUrl) == 0 {
			log.Error("RedirectUrl is not provided.")
		}

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
