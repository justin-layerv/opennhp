package passcode

import (
	"errors"
	"fmt"
	"net/http"

	nhpsdkutils "github.com/fengyily/nhp-plugins-sdk/utils"
	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/endpoints/server/staticplugins/internal/redirecturl"
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
		return nil, "400", errors.New("customAuthByHmac helper is null")
	}

	format := ctx.Query("format")

	// 1. Get HMAC configuration from ExInfo
	secretKey := nhpsdkutils.GetStringFromMap(res.ExInfo, "SecretKey")
	if len(secretKey) == 0 {
		log.Error("SecretKey is not provided in ExInfo")
		return nil, "401", errors.New("secret key is not provided")
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
		return nil, "402", errors.New("authorization header is empty")
	}

	// 3. Verify HMAC signature (AccessKey uses resId)
	valid, err := VerifyHMACFromHeader(res.ResourceId, secretKey, algorithm, expireSec, authHeader)
	if err != nil {
		log.Error("HMAC verification failed: %v", err)
		return nil, "403", fmt.Errorf("HMAC verification failed: %w", err)
	}
	if !valid {
		log.Error("HMAC signature is invalid")
		return nil, "403", errors.New("HMAC signature is invalid")
	}

	log.Debug("HMAC authentication succeeded for resource: %s", res.ResourceId)

	// 4. Business logic after authentication passed (same as customAuthByCode)
	result, errCode, knockErr := knockAndIssueTokens(ctx, req, res, helper)
	if knockErr != nil {
		return nil, errCode, knockErr
	}

	ackMsg, redirectUrl, err := redirecturl.GetByResource(result.AckMsg, res, resourceHandler.GetConfig(), "hmac", "anonymous")
	if err != nil {
		log.Error("failed to get redirect url: %v", err)
		return ackMsg, "404", err
	}

	log.Info("ackMsg.ResourceHost: %+v", ackMsg.ResourceHost)
	respondSuccessOrRedirect(ctx, format, result.NHPToken, result.RefreshToken, redirectUrl)
	return ackMsg, "", nil
}

func customAuthByCode(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, string, error) {
	if helper == nil {
		return nil, "400", errors.New("customAuthByCode helper is null")
	}

	var err error
	passcode := ctx.Query("code")
	state := ctx.Query("state")
	format := ctx.Query("format")
	AuthUrl := nhpsdkutils.GetStringFromMap(res.ExInfo, "AuthUrl")
	if len(AuthUrl) == 0 {
		log.Error("AuthUrl is not provided.")
		return nil, "401", errors.New("auth URL is not provided")
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
		return nil, "402", fmt.Errorf("request failed: %w", err)
	}

	if authResp.StatusCode != http.StatusOK {
		log.Error("API request failed with status code %d: %s", authResp.StatusCode, string(authResp.Body))
		return nil, "403", fmt.Errorf("api request failed with status code %d: %s", authResp.StatusCode, string(authResp.Body))
	}

	type Response struct {
		Code int    `json:"code"`
		Data any    `json:"data"`
		Msg  string `json:"msg"`
	}
	// Parse JSON response
	var apiResponse Response
	if err := nhpsdkutils.ParseJSONResponse(authResp, &apiResponse); err != nil {
		log.Error("Error parsing response: %v", err)
		return nil, "403", fmt.Errorf("error parsing response: %w", err)
	}
	if apiResponse.Code != 0 {
		log.Error("API request failed with code %d: %s", apiResponse.Code, apiResponse.Msg)
		return nil, fmt.Sprintf("50%d", apiResponse.Code), fmt.Errorf("api request failed with code %d: %s", apiResponse.Code, apiResponse.Msg)
	}
	log.Debug("Authenticating passcode: %s succeeded!", passcode)

	result, errCode, knockErr := knockAndIssueTokens(ctx, req, res, helper)
	if knockErr != nil {
		return nil, errCode, knockErr
	}

	ackMsg, redirectUrl, err := redirecturl.GetByResource(result.AckMsg, res, resourceHandler.GetConfig(), "auth_code", "anonymous")
	if err != nil {
		log.Error("failed to get redirect url: %v", err)
		return ackMsg, "404", err
	}

	log.Info("ackMsg.ResourceHost: %+v", ackMsg.ResourceHost)
	respondSuccessOrRedirect(ctx, format, result.NHPToken, result.RefreshToken, redirectUrl)
	return ackMsg, "", nil
}
