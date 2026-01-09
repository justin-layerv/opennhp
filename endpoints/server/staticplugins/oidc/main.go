package oidc

import (
	"fmt"
	"net/http"
	"strings"

	nhpplugins "github.com/fengyily/nhp-plugins-sdk"
	"github.com/fengyily/nhp-plugins-sdk/resource"
	nhpsdkutils "github.com/fengyily/nhp-plugins-sdk/utils"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"

	"github.com/OpenNHP/opennhp/nhp/common"
	nhplog "github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/plugins"
)

type config struct {
	AUTH0_DOMAIN       string
	OIDC_CLIENTID      string
	OIDC_AUTHORIZE_URL string
	OIDC_TOKEN_URL     string
	OIDC_CLIENTSECRET  string
	AUTH0_CALLBACK_URL string
}

var (
	// Example Plugin Settings
	log      *nhplog.Logger
	oktaAuth *Authenticator
	baseConf *config
)

var (
	name    = "oktaoidc"
	version = "0.1.1"

	resourceHander resource.ResourceHandler
	pluginsIn      *plugins.PluginParamsIn
)

func registerHander(handler resource.ResourceHandler) error {
	resourceHander = handler
	log.Info("registerHander handler.GetConfig() %+v", handler.GetConfig())
	log.Info("pluginsIn.PluginDirPath: %+v", pluginsIn.PluginDirPath)
	log.Info("register resource handler: %s", handler.GetConfig().ResourceMode)
	return nil
}
func Version() string {
	return fmt.Sprintf("%s v%s", name, version)
}

func Signature() string {
	return ""
}

func ExportedData() *plugins.PluginParamsOut {
	return &plugins.PluginParamsOut{}
}

func Init(in *plugins.PluginParamsIn) error {
	pluginsIn = in
	return nhpplugins.Init(in, registerHander)
}

func Close() error {
	return nhpplugins.Close()
}

func AuthWithHttp(ctx *gin.Context, req *common.HttpKnockRequest, helper *plugins.HttpServerPluginHelper) (ackMsg *common.ServerKnockAckMsg, err error) {
	if helper == nil {
		return nil, fmt.Errorf("AuthWithHttp: helper is null")
	}

	resId := ctx.Query("resid")
	action := ctx.Query("action")
	if len(resId) > 0 && strings.Contains(resId, "|") {
		params := strings.Split(resId, "|")
		resId = params[0]
		if len(params) > 1 {
			action = params[1]
		}
	}

	res, err := resourceHander.FindResourceByID(resId)
	if err != nil {
		log.Error("call FindResourceByID failed: %v", err)
		return
	}
	if res == nil || len(res.Resources) == 0 {
		ackMsg = nil
		err = common.ErrResourceNotFound
		log.Error("resource error: %v", err)
		ctx.String(http.StatusOK, "{\"errMsg\": \"resource error: %v\"}", err)
		return
	}
	baseConf = &config{
		AUTH0_DOMAIN:       nhpsdkutils.GetStringFromMap(res.ExInfo, "AUTH0_DOMAIN"),
		OIDC_CLIENTID:      nhpsdkutils.GetStringFromMap(res.ExInfo, "OIDC_CLIENTID"),
		OIDC_CLIENTSECRET:  nhpsdkutils.GetStringFromMap(res.ExInfo, "OIDC_CLIENTSECRET"),
		OIDC_AUTHORIZE_URL: nhpsdkutils.GetStringFromMap(res.ExInfo, "OIDC_AUTHORIZE_URL"),
		OIDC_TOKEN_URL:     nhpsdkutils.GetStringFromMap(res.ExInfo, "OIDC_TOKEN_URL"),
		AUTH0_CALLBACK_URL: nhpsdkutils.GetStringFromMap(res.ExInfo, "AUTH0_CALLBACK_URL"),
	}
	corsMiddleware(ctx)

	switch {
	case strings.EqualFold(action, "valid"):
		ackMsg, err = authRegular(ctx, req, res, helper)

	case strings.EqualFold(action, "login"):
		authAndShowLogin(ctx)

	case strings.EqualFold(action, "oauth"):
		err = authOkta(ctx)

	default:
		ackMsg = nil
		err = fmt.Errorf("action invalid")
	}
	return
}

func authAndShowLogin(ctx *gin.Context) {
	session := sessions.Default(ctx)
	t := session.Get("oauth_token")
	resid := ctx.Query("resid")
	oauthToken, ok1 := t.(oauth2.Token)
	s := session.Get("state")
	state, ok2 := s.(string)
	if ok1 && ok2 {
		_, err := oktaAuth.VerifyIDToken(ctx.Request.Context(), &oauthToken)
		if err == nil {
			ctx.Redirect(http.StatusSeeOther, "/plugins/oktaoidc?resid="+resid+"&action=valid"+"&state="+state)
			return
		}
	}

	ctx.HTML(http.StatusOK, "oktaoidc/home.html", gin.H{})
}

func authOkta(ctx *gin.Context) error {
	var err error
	oktaAuth, err = NewAuthenticator(*baseConf)
	if err != nil {
		ctx.String(http.StatusOK, "{\"errMsg\": \"failed to initialize authenticator\"}")
		oktaAuth = nil
		return fmt.Errorf("failed to initialize authenticator")
	}

	err = oktaAuth.DoAuth(ctx)
	if err != nil {
		ctx.String(http.StatusOK, "{\"errMsg\": \"user authentication failed\"}")
		return fmt.Errorf("user authentication failed")
	}

	return nil
}

func authRegular(ctx *gin.Context, req *common.HttpKnockRequest, res *common.ResourceData, helper *plugins.HttpServerPluginHelper) (*common.ServerKnockAckMsg, error) {
	if oktaAuth == nil {
		ctx.String(http.StatusOK, "{\"errMsg\": \"invalid authenticator\"}")
		return nil, fmt.Errorf("invalid authenticator")
	}

	session := sessions.Default(ctx)
	if ctx.Query("state") != session.Get("state") {
		ctx.String(http.StatusOK, "{\"errMsg\": \"invalid authentication session\"}")
		log.Error("session.state = %s, query.state = %s", session.Get("state"), ctx.Query("state"))
		return nil, fmt.Errorf("invalid authentication session")
	}

	authorizeCode := ctx.Query("code")
	var err error
	var oktaToken *oauth2.Token

	if len(authorizeCode) > 0 {
		// when there is authorize code in query, it is a callback from okta
		// Exchange an authorization code for a token.
		oktaToken, err = oktaAuth.Exchange(ctx.Request.Context(), authorizeCode)
		if err != nil {
			ctx.String(http.StatusOK, "{\"errMsg\": \"failed to convert an authorization code into a token\"}")
			return nil, fmt.Errorf("failed to convert an authorization code into a token")
		}

		idToken, err := oktaAuth.VerifyIDToken(ctx.Request.Context(), oktaToken)
		if err != nil {
			ctx.String(http.StatusOK, "{\"errMsg\": \"failed to verify ID token\"}")
			return nil, fmt.Errorf("failed to verify ID token")
		}

		var profile map[string]interface{}
		if err := idToken.Claims(&profile); err != nil {
			ctx.String(http.StatusOK, "{\"errMsg\": \"failed to claim user profile\"}")
			return nil, fmt.Errorf("failed to claim user profile")
		}

		session.Set("oauth_token", *oktaToken)
		session.Set("profile", profile)

		log.Info("User profile: %+v", profile)
		session.Save()
	} else {
		// if no authorize code exists, try extract the oauth token from the session
		oauthToken := session.Get("oauth_token")
		t, ok := oauthToken.(oauth2.Token)
		if !ok {
			ctx.String(http.StatusOK, "{\"errMsg\": \"invalid session paramete\"}")
			return nil, fmt.Errorf("invalid session parameter")
		}
		oktaToken = &t

		idToken, err := oktaAuth.VerifyIDToken(ctx.Request.Context(), oktaToken)
		if err != nil {
			ctx.String(http.StatusOK, "{\"errMsg\": \"failed to verify ID token\"}")
			session.Clear()
			ctx.Redirect(http.StatusSeeOther, fmt.Sprintf("/plugins/oktaoidc?resid=%s&action=login", res.Id()))
			return nil, fmt.Errorf("failed to verify ID token")
		}
		var profile map[string]interface{}
		if err := idToken.Claims(&profile); err != nil {
			ctx.String(http.StatusOK, "{\"errMsg\": \"failed to claim user profile\"}")
			return nil, fmt.Errorf("failed to claim user profile")
		}

		session.Set("oauth_token", *oktaToken)
		session.Set("profile", profile)
		log.Info("User profile: %+v", profile)
		session.Save()
	}
	resp := &nhpplugins.RefreshResponse{}
	// interact with udp server for ac operation
	ackMsg, err := helper.AuthWithHttpCallbackFunc(req, res)
	if err != nil {
		log.Error("AuthWithHttpCallbackFunc failed: %v", err)
		ctx.JSON(http.StatusOK, gin.H{"errMsg": fmt.Sprintf("auth callback failed: %v", err)})
		return nil, err
	}
	if ackMsg == nil {
		log.Error("AuthWithHttpCallbackFunc returned nil ackMsg")
		ctx.JSON(http.StatusOK, gin.H{"errMsg": "internal error: nil response"})
		return nil, fmt.Errorf("nil ackMsg from AuthWithHttpCallbackFunc")
	}

	if ackMsg.ErrCode != common.ErrSuccess.ErrorCode() {
		log.Error("knock failed. %v", ackMsg.ErrMsg)
		ctx.JSON(http.StatusOK, gin.H{"errMsg": fmt.Sprintf("knock failed: %s", ackMsg.ErrMsg)})
		return nil, fmt.Errorf("knock failed: %s", ackMsg.ErrMsg)
	}

	ackMsg, redirectUrl, err := nhpplugins.GetRedirectUrlByResource(ackMsg, res, resourceHander.GetConfig(), "oidc", "")
	if err != nil {
		log.Error("failed to get redirect url: %v", err)
		return ackMsg, err
	}

	if len(redirectUrl) == 0 {
		log.Error("RedirectUrl is not provided.")
		resp.RedirectUrl = ackMsg.RedirectUrl
	} else {
		resp.RedirectUrl = redirectUrl
	}

	ackMsg.ErrMsg = ""
	// Add validation before token generation
	jwtSecret := nhpsdkutils.GetStringFromMap(res.ExInfo, "JWTSecret")
	if jwtSecret == "" {
		log.Error("JWTSecret is empty or not found in ExInfo")
		ctx.String(http.StatusOK, "{\"errMsg\": \"JWT secret not configured\"}")
		return nil, fmt.Errorf("JWT secret not configured")
	}

	jwt := &nhpplugins.JWTToken{
		JwtKey: []byte(jwtSecret),
	}

	// Verify jwt object
	if jwt == nil {
		log.Error("Failed to create JWTToken object")
		ctx.String(http.StatusOK, "{\"errMsg\": \"failed to create token generator\"}")
		return nil, fmt.Errorf("failed to create token generator")
	}

	nhpToken, refreshToken, err := jwt.GenerateAll(res.AuthServiceId, res)
	if err != nil {
		log.Error("failed to generate token: %v", err)
		ackMsg.ErrCode = common.ErrServerACOpsFailed.ErrorCode()
		ackMsg.ErrMsg = err.Error()
		ctx.JSON(http.StatusOK, ackMsg)
		return ackMsg, err
	}

	// Verify the generated token
	if nhpToken == "" {
		log.Error("Generated nhpToken is empty")
		ctx.String(http.StatusOK, "{\"errMsg\": \"failed to generate authentication token\"}")
		return nil, fmt.Errorf("empty authentication token generated")
	}

	if refreshToken == "" {
		log.Error("Generated refreshToken is empty")
		ctx.String(http.StatusOK, "{\"errMsg\": \"failed to generate refresh token\"}")
		return nil, fmt.Errorf("empty refresh token generated")
	}

	resp.CookieDomain = res.CookieDomain
	resp.NHPRefreshToken = refreshToken
	resp.NHPToken = nhpToken

	if ctx.Query("format") == "json" {
		ctx.JSON(http.StatusOK, resp)
	} else {
		ctx.SetSameSite(http.SameSiteNoneMode)
		ctx.SetCookie("nhp_token", nhpToken, nhpsdkutils.GetIntFromMap(res.ExInfo, "TokenExpire"), "/", res.CookieDomain, true, true)
		ctx.SetCookie("nhp_refresh_token", refreshToken, nhpsdkutils.GetIntFromMap(res.ExInfo, "TokenExpire"), "/", res.CookieDomain, true, true)
		ctx.Redirect(http.StatusFound, resp.RedirectUrl)
	}
	return ackMsg, nil
}

func AuthWithNHP(req *common.NhpAuthRequest, helper *plugins.NhpServerPluginHelper) (ackMsg *common.ServerKnockAckMsg, err error) {
	ackMsg = req.Ack
	if helper == nil {
		return ackMsg, fmt.Errorf("AuthWithNHP: helper is null")
	}

	var res *common.ResourceData
	res, err = resourceHander.FindResourceByID(req.Msg.ResourceId)
	if err != nil {
		log.Error("call findResourceApi failed: %v", err)
		return
	}
	if res == nil || len(res.Resources) == 0 {
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

	// PART III: request ac operation for each resource and block for response
	ackMsg, err = helper.AuthWithNhpCallbackFunc(req, res)

	return ackMsg, err
}

func corsMiddleware(ctx *gin.Context) {
	originResource := ctx.Request.Header.Get("Origin")

	if originResource != "" {
		// HTTP headers for CORS
		ctx.Writer.Header().Set("Access-Control-Allow-Origin", originResource) // allow cross-origin resource sharing
	}

	ctx.Next()
}
