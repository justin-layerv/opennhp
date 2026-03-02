package passcode

import (
	"errors"
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
	nhpsdkutils "github.com/fengyily/nhp-plugins-sdk/utils"
)

var (
	name            = "passcode"
	version         = "0.1.1"
	resourceHandler resource.ResourceHandler
	pluginsIn       *plugins.PluginParamsIn
)

func Version() string {
	return name + " v" + version
}

func registerHandler(handler resource.ResourceHandler) error {
	resourceHandler = handler
	log.Info("register resource handler: %s", handler.GetConfig().ResourceMode)
	return nil
}

func Init(in *plugins.PluginParamsIn) error {
	pluginsIn = in
	return nhpplugins.Init(in, registerHandler)
}

func Close() error {
	return nhpplugins.Close()
}

// respondErrorRedirect sends a redirect-or-JSON error response for auth failures.
// Uses RefreshResponse format for actions that go through the standard auth flow.
func respondErrorRedirect(ctx *gin.Context, format, resId, errCode string, err error) {
	errorUrl := "/plugins/passcode?resid=" + resId + "&action=error&id=" + errCode
	if format == "json" {
		ctx.JSON(http.StatusOK, nhpplugins.RefreshResponse{
			RedirectUrl: errorUrl,
			ErrCode:     errCode,
			ErrMsg:      err.Error(),
		})
	} else {
		ctx.Redirect(http.StatusFound, errorUrl)
	}
}

// respondErrorJSON sends a redirect-or-JSON error response for custom auth failures.
// Uses a simple code/message format for auth_code, auth, and hmac_auth actions.
func respondErrorJSON(ctx *gin.Context, format, resId, errCode string, err error) {
	if format == "json" {
		ctx.JSON(http.StatusOK, map[string]any{
			"code":    10001,
			"message": err.Error(),
		})
	} else {
		ctx.Redirect(http.StatusFound, "/plugins/passcode?resid="+resId+"&action=error&id="+errCode)
	}
}

// knockTokenResult holds the output of a knock + JWT flow.
type knockTokenResult struct {
	AckMsg       *common.ServerKnockAckMsg
	NHPToken     string
	RefreshToken string
	KnockOK      bool // true when knock succeeded and ResourceHost is available
}

// knockAndIssueTokens performs the NHP knock via the helper, generates JWT
// tokens on success, and sets session cookies. Callers handle redirect URLs
// and the final HTTP response, including all error responses.
//
// Returns (knockTokenResult{}, errCode, error) on failure.
// Returns (knockTokenResult{...}, "", nil) on success.
func knockAndIssueTokens(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (knockTokenResult, string, error) {
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
		return knockTokenResult{}, "505", fmt.Errorf("knock failed: %s", ackMsg.ErrMsg)
	}

	log.Info("knock succeeded.%+v", res.Resources)

	jwt := &nhpplugins.JWTToken{
		JwtKey: []byte(nhpsdkutils.GetStringFromMap(res.ExInfo, "JWTSecret")),
	}
	nhpToken, refreshToken, err := jwt.GenerateAll(res.AuthServiceId, res)
	if err != nil {
		log.Error("failed to generate token: %v", err)
		return knockTokenResult{}, "410", err
	}
	log.Info("token: %s...", nhpToken[:min(10, len(nhpToken))])

	tokenExpire := nhpsdkutils.GetIntFromMap(res.ExInfo, "TokenExpire")
	ctx.SetCookie("nhp_token", nhpToken, tokenExpire, "/", res.CookieDomain, true, true)
	ctx.SetCookie("nhp_refresh_token", refreshToken, tokenExpire, "/", res.CookieDomain, true, true)

	return knockTokenResult{AckMsg: ackMsg, NHPToken: nhpToken, RefreshToken: refreshToken, KnockOK: true}, "", nil
}

// exchangeAndKnock reads NHP token cookies, exchanges them for a new token,
// performs the knock, and sets session cookies. On knock success, cookies are
// set with the configured TokenExpire. On knock failure with a non-nil ackMsg,
// cookies are cleared (expire=0). Callers handle the HTTP response.
//
// Returns (result, error). On token-exchange failure error is non-nil and
// result is zero-valued. On knock failure error is nil but result.KnockOK is
// false and result.AckMsg contains error details.
func exchangeAndKnock(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (knockTokenResult, error) {
	oldNHPToken := nhpplugins.GetCookie("nhp_token", ctx)
	if len(oldNHPToken) == 0 {
		log.Error("old token is empty")
		return knockTokenResult{}, errors.New("old token is empty")
	}

	refreshTok := nhpplugins.GetCookie("nhp_refresh_token", ctx)
	if len(refreshTok) == 0 {
		log.Error("refresh token is empty")
		return knockTokenResult{}, errors.New("refresh token is empty")
	}

	jwt := &nhpplugins.JWTToken{
		JwtKey: []byte(nhpsdkutils.GetStringFromMap(res.ExInfo, "JWTSecret")),
	}
	nhpToken, err := jwt.ExchangeNHPToken(oldNHPToken, refreshTok, res)
	if err != nil {
		log.Error("failed to exchange token: %v", err)
		return knockTokenResult{}, err
	}

	ackMsg, err := helper.AuthWithHttpCallbackFunc(req, res)

	// Both knock failure paths clear cookies so stale tokens are not reused.
	if ackMsg == nil || err != nil {
		log.Error("knock failed. ackMsg is nil")
		ctx.SetSameSite(http.SameSiteNoneMode)
		ctx.SetCookie("nhp_token", nhpToken, 0, "/", res.CookieDomain, true, true)
		ctx.SetCookie("nhp_refresh_token", refreshTok, 0, "/", res.CookieDomain, true, true)
		ackMsg = &common.ServerKnockAckMsg{}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		if err != nil {
			ackMsg.ErrMsg = err.Error()
		} else {
			ackMsg.ErrMsg = "knock failed: ackMsg is nil"
		}
		return knockTokenResult{AckMsg: ackMsg, NHPToken: nhpToken, RefreshToken: refreshTok}, nil
	}

	if len(ackMsg.ResourceHost) == 0 {
		log.Error("knock failed. ackMsg.ResourceHost is empty")
		ctx.SetSameSite(http.SameSiteNoneMode)
		ctx.SetCookie("nhp_token", nhpToken, 0, "/", res.CookieDomain, true, true)
		ctx.SetCookie("nhp_refresh_token", refreshTok, 0, "/", res.CookieDomain, true, true)
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		ackMsg.ErrMsg = "knock failed: ResourceHost is empty"
		return knockTokenResult{AckMsg: ackMsg, NHPToken: nhpToken, RefreshToken: refreshTok}, nil
	}

	log.Info("knock succeeded.%+v", res.Resources)
	log.Info("token: %s...", nhpToken[:min(10, len(nhpToken))])

	tokenExpire := nhpsdkutils.GetIntFromMap(res.ExInfo, "TokenExpire")
	ctx.SetSameSite(http.SameSiteNoneMode)
	ctx.SetCookie("nhp_token", nhpToken, tokenExpire, "/", res.CookieDomain, true, true)
	ctx.SetCookie("nhp_refresh_token", refreshTok, tokenExpire, "/", res.CookieDomain, true, true)

	ackMsg.ErrMsg = ""
	return knockTokenResult{AckMsg: ackMsg, NHPToken: nhpToken, RefreshToken: refreshTok, KnockOK: true}, nil
}

// respondSuccessOrRedirect sends either a JSON success payload or an HTTP
// redirect depending on the format query parameter.
func respondSuccessOrRedirect(ctx *gin.Context, format, nhpToken, refreshToken, redirectUrl string) {
	if format == "json" {
		ctx.JSON(http.StatusOK, map[string]any{
			"code":              0,
			"nhp_token":         nhpToken,
			"nhp_refresh_token": refreshToken,
			"redirect_url":      redirectUrl,
			"message":           "success",
		})
	} else {
		ctx.Redirect(http.StatusFound, redirectUrl)
	}
}

func AuthWithHttp(ctx *gin.Context, req *common.HttpKnockRequest, helper *plugins.HttpServerPluginHelper) (ackMsg *common.ServerKnockAckMsg, err error) {
	action := ctx.Query("action")
	if strings.EqualFold(action, "refresh") || strings.EqualFold(action, "nhp-refresh") {
		ackMsg, err = AuthWithHttpRefresh(ctx, action, req, helper)
		return
	}
	resId := ctx.Query("resid")
	format := ctx.Query("format")

	if strings.EqualFold(action, "error") {
		ackMsg, err = authAndShowRefreshError(ctx)
		return
	}
	res, err := resourceHandler.FindResourceByID(resId)
	statusCode := "500"
	if err != nil {
		respondErrorRedirect(ctx, format, resId, statusCode, err)
		log.Error("call findResourceApi failed: %v", err)
		return
	}
	if res == nil || len(res.Resources) == 0 {
		ackMsg = nil
		err = common.ErrResourceNotFound
		log.Error("resource error: %v", err)
		ctx.JSON(http.StatusOK, gin.H{"errMsg": fmt.Sprintf("resource error: %v", err)})
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
			respondErrorRedirect(ctx, format, resId, errCode, err)
		}
	case strings.EqualFold(action, "access"):
		errCode := ""
		ackMsg, errCode, err = authAccessFromRaaS(ctx, req, res, helper)
		if err != nil {
			respondErrorRedirect(ctx, format, resId, errCode, err)
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
			respondErrorJSON(ctx, format, resId, errCode, err)
		}
	case strings.EqualFold(action, "auth"):
		format := ctx.Query("format")
		errCode := ""
		ackMsg, errCode, err = std_auth(ctx, req, res, helper)
		if err != nil {
			respondErrorJSON(ctx, format, resId, errCode, err)
		}
	case strings.EqualFold(action, "hmac_auth"):
		format := ctx.Query("format")
		errCode := ""
		ackMsg, errCode, err = customAuthByHmac(ctx, req, res, helper)
		if err != nil {
			respondErrorJSON(ctx, format, resId, errCode, err)
		}
	default:
		ackMsg = nil
		err = errors.New("action invalid")
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
	res, err := resourceHandler.FindResourceByID(resId)
	if err != nil {
		log.Error("call findResourceApi failed: %v", err)
		return
	}
	if res == nil || len(res.Resources) == 0 {
		ackMsg = nil
		err = common.ErrResourceNotFound
		log.Error("resource error: %v", err)
		ctx.JSON(http.StatusOK, gin.H{"errMsg": fmt.Sprintf("resource error: %v", err)})
		return
	}
	jwt := &nhpplugins.JWTToken{
		JwtKey: []byte(nhpsdkutils.GetStringFromMap(res.ExInfo, "JWTSecret")),
	}

	isOk, err := jwt.Validate(nHPToken, nhpplugins.TokenTypeNHPToken)
	if err != nil {
		log.Warning("nhp token is invalid nHPToken = %s err:%s", nHPToken, err.Error())
		return nil, err
	}
	if !isOk {
		log.Error("nhp token is invalid")
		return nil, errors.New("nhp token is invalid")
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
		ctx.JSON(http.StatusBadRequest, gin.H{"errMsg": fmt.Sprintf("unknown action: %s", action)})
	}

	return
}

func AuthWithNHP(req *common.NhpAuthRequest, helper *plugins.NhpServerPluginHelper) (ackMsg *common.ServerKnockAckMsg, err error) {
	ackMsg = req.Ack
	if helper == nil {
		return ackMsg, errors.New("authWithNHP: helper is null")
	}

	res, err := resourceHandler.FindResourceByID(req.Msg.ResourceId)
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
		return nil, errors.New("authAndShowLogin: helper is null")
	}

	if res.ExInfo == nil {
		log.Error("extra login info not available")
		ctx.JSON(http.StatusOK, gin.H{"errMsg": "extra login info not available"})
		return nil, errors.New("extra login info not available")
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
		return nil, errors.New("authAndShowRefresh: helper is null")
	}

	if res.ExInfo == nil {
		log.Error("extra login info not available")
		ctx.JSON(http.StatusOK, gin.H{"errMsg": "extra login info not available"})
		return nil, errors.New("extra login info not available")
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
		return nil, errors.New("refreshToken: helper is null")
	}

	result, err := exchangeAndKnock(ctx, req, res, helper)
	if err != nil {
		ackMsg := &common.ServerKnockAckMsg{}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		ctx.JSON(http.StatusOK, ackMsg)
		return nil, err
	}

	if !result.KnockOK {
		ctx.JSON(http.StatusOK, result.AckMsg)
		return result.AckMsg, nil
	}

	if len(res.RedirectUrl) == 0 {
		log.Error("RedirectUrl is not provided.")
	} else {
		result.AckMsg.RedirectUrl = res.RedirectUrl
	}

	ctx.JSON(http.StatusOK, map[string]any{
		"code":              0,
		"nhp_token":         result.NHPToken,
		"nhp_refresh_token": result.RefreshToken,
		"message":           "success",
	})
	return result.AckMsg, nil
}

func knockByToken(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	if helper == nil {
		return nil, errors.New("knockByToken: helper is null")
	}

	result, err := exchangeAndKnock(ctx, req, res, helper)
	if err != nil {
		ackMsg := &common.ServerKnockAckMsg{}
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		ctx.JSON(http.StatusOK, ackMsg)
		return nil, err
	}

	if !result.KnockOK {
		ctx.JSON(http.StatusOK, result.AckMsg)
		return result.AckMsg, nil
	}

	ackMsg, redirectUrl, err := nhpplugins.GetRedirectUrlByResource(result.AckMsg, res, resourceHandler.GetConfig(), "knock", "anonymous")
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
}

func authRegular(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, string, error) {
	if helper == nil {
		return nil, "400", errors.New("authRegular helper is null")
	}

	var err error
	passcode := ctx.Query("passcode")
	format := ctx.Query("format")
	if resourceHandler.GetConfig().ResourceMode == "api" {
		AuthUrl := resourceHandler.GetConfig().AuthUrl
		if len(AuthUrl) == 0 {
			log.Error("AuthUrl is not provided.")
			return nil, "401", errors.New("auth URL is not provided")
		}

		resp, err := nhpsdkutils.SendRequest(nhpsdkutils.RequestOptions{
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
			return nil, "402", fmt.Errorf("request failed: %w", err)
		}

		if resp.StatusCode != http.StatusOK {
			log.Error("API request failed with status code %d: %s", resp.StatusCode, string(resp.Body))
			return nil, "403", fmt.Errorf("api request failed with status code %d: %s", resp.StatusCode, string(resp.Body))
		}

		type Response struct {
			Code int    `json:"code"`
			Data any    `json:"data"`
			Msg  string `json:"msg"`
		}
		// Parse JSON response
		var apiResponse Response
		if err := nhpsdkutils.ParseJSONResponse(resp, &apiResponse); err != nil {
			log.Error("Error parsing response: %v", err)
			return nil, "403", fmt.Errorf("error parsing response: %w", err)
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
		case []any:
			secrets := res.ExInfo["AppSecret"].([]any)
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

	result, errCode, knockErr := knockAndIssueTokens(ctx, req, res, helper)
	if knockErr != nil {
		return nil, errCode, knockErr
	}

	// Check if passcode is a sharing link JWT
	redirectUrl := ""
	if sharingRedirectUrl := getSharingLinkRedirectUrl(passcode, result.AckMsg.ResourceHost); len(sharingRedirectUrl) > 0 {
		redirectUrl = sharingRedirectUrl
		log.Info("Using sharing link redirect url: %s", redirectUrl)
	} else {
		result.AckMsg, redirectUrl, err = nhpplugins.GetRedirectUrlByResource(result.AckMsg, res, resourceHandler.GetConfig(), "valid", "anonymous")
		if err != nil {
			log.Error("failed to get redirect url: %v", err)
			return result.AckMsg, "404", err
		}
	}

	if len(redirectUrl) == 0 {
		log.Error("RedirectUrl is not provided.")
	}

	resp := &nhpplugins.RefreshResponse{
		RedirectUrl:     redirectUrl,
		CookieDomain:    res.CookieDomain,
		ResourceHost:    result.AckMsg.ResourceHost,
		NHPToken:        result.NHPToken,
		NHPRefreshToken: result.RefreshToken,
	}

	log.Info("ackMsg.ResourceHost: %+v", result.AckMsg.ResourceHost)
	if format == "json" {
		ctx.JSON(http.StatusOK, resp)
	} else {
		ctx.Redirect(http.StatusFound, resp.RedirectUrl)
	}
	return result.AckMsg, "", nil
}

func authAccessFromRaaS(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, string, error) {
	if helper == nil {
		return nil, "600", errors.New("authAccessFromRaaS helper is null")
	}
	IAMServiceUrl := resourceHandler.GetConfig().IAMServiceUrl

	idStr := ctx.Query("id")
	if idStr == "" {
		return nil, "601", errors.New("id is missing")
	}
	log.Info("raas portal Site app id is %s", idStr)
	potalSiteUrl := fmt.Sprintf("%s/api/v1/portal-sites/%s", IAMServiceUrl, idStr)
	log.Info("Calling real IAM service: %s", potalSiteUrl)
	authHeader := ctx.GetHeader("Authorization")
	if authHeader == "" {
		return nil, "602", errors.New("authorization header is missing")
	}
	raasHttpReq, err := http.NewRequestWithContext(ctx.Request.Context(), "GET", potalSiteUrl, nil)
	if err != nil {
		return nil, "603", fmt.Errorf("failed to create request: %w", err)
	}
	raasHttpReq.Header.Set("Authorization", authHeader)
	client := &http.Client{}
	respRaas, err := client.Do(raasHttpReq)
	if err != nil {
		return nil, "604", fmt.Errorf("failed to call real IAM service: %w", err)
	}
	defer func() { _ = respRaas.Body.Close() }()
	// Check status code
	if respRaas.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(respRaas.Body)
		log.Error("IAM service returned non-OK status: %d, body: %s", respRaas.StatusCode, string(body))
		return nil, "605", fmt.Errorf("IAM service error: %d %s", respRaas.StatusCode, string(body))
	}
	body, err := io.ReadAll(respRaas.Body)
	if err != nil {
		return nil, "606", fmt.Errorf("failed to read IAM response body: %w", err)
	}

	log.Info("Successfully got response from real IAM: %s", string(body))

	result, errCode, knockErr := knockAndIssueTokens(ctx, req, res, helper)
	if knockErr != nil {
		return nil, errCode, knockErr
	}

	user := GetUserFromAuthHeader(authHeader)
	ackMsg, redirectUrl, err := nhpplugins.GetRedirectUrlByResource(result.AckMsg, res, resourceHandler.GetConfig(), "access", user)
	if err != nil {
		log.Error("failed to get redirect url: %v", err)
		return ackMsg, "404", err
	}
	log.Info("redirectUrl: %s", redirectUrl)
	if len(redirectUrl) == 0 {
		log.Error("RedirectUrl is not provided.")
	}

	resp := &nhpplugins.RefreshResponse{
		RedirectUrl:     redirectUrl,
		CookieDomain:    res.CookieDomain,
		ResourceHost:    ackMsg.ResourceHost,
		NHPToken:        result.NHPToken,
		NHPRefreshToken: result.RefreshToken,
	}

	log.Info("ackMsg.ResourceHost: %+v", ackMsg.ResourceHost)
	ctx.JSON(http.StatusOK, resp)
	log.Info("Done %+v", resp)
	return ackMsg, "", nil
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
	host := nhpsdkutils.Loadbalancing(resourceHost)
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
		return "", fmt.Errorf("failed to parse token unverified: %w", err)
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
