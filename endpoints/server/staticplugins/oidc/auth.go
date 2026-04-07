package oidc

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"github.com/gin-contrib/sessions"
	"github.com/gin-gonic/gin"
	"golang.org/x/oauth2"
)

// oidcDiscoveryTimeout bounds the OIDC provider discovery handshake
// (.well-known/openid-configuration). Without this cap, a slow or hung Auth0
// would burn the entire HTTP request budget on discovery and starve other
// stages of the auth flow. The full HTTP request typically has a 30s budget;
// 10s leaves headroom for token exchange and userinfo lookups.
const oidcDiscoveryTimeout = 10 * time.Second

// Authenticator is used to authenticate our users.
type Authenticator struct {
	*oidc.Provider
	oauth2.Config
}

// NewAuthenticator instantiates the *Authenticator. The supplied ctx
// controls cancellation of the discovery handshake; this function additionally
// applies oidcDiscoveryTimeout so a slow Auth0 cannot stall the caller for
// the full request budget.
func NewAuthenticator(ctx context.Context, conf config) (*Authenticator, error) {
	discoveryCtx, cancel := context.WithTimeout(ctx, oidcDiscoveryTimeout)
	defer cancel()

	provider, err := oidc.NewProvider(
		discoveryCtx,
		"https://"+conf.AUTH0_DOMAIN,
	)
	if err != nil {
		return nil, err
	}

	oauth2Conf := oauth2.Config{
		ClientID:     conf.OIDC_CLIENTID,
		ClientSecret: conf.OIDC_CLIENTSECRET,
		RedirectURL:  conf.AUTH0_CALLBACK_URL,
		Endpoint:     provider.Endpoint(),
		Scopes:       []string{oidc.ScopeOpenID, "profile"},
	}

	return &Authenticator{
		Provider: provider,
		Config:   oauth2Conf,
	}, nil
}

// VerifyIDToken verifies that an *oauth2.Token is a valid *oidc.IDToken.
func (a *Authenticator) VerifyIDToken(ctx context.Context, token *oauth2.Token) (*oidc.IDToken, error) {
	rawIDToken, ok := token.Extra("id_token").(string)
	if !ok {
		return nil, errors.New("no id_token field in oauth2 token")
	}

	oidcConfig := &oidc.Config{
		ClientID: a.ClientID,
	}

	return a.Verifier(oidcConfig).Verify(ctx, rawIDToken)
}

func (a *Authenticator) DoAuth(ctx *gin.Context) error {
	state, err := generateRandomState()
	if err != nil {
		return err
	}

	// Save the state inside the session
	session := sessions.Default(ctx)
	session.Set("state", state)
	if err := session.Save(); err != nil {
		return err
	}

	ctx.Redirect(http.StatusTemporaryRedirect, a.AuthCodeURL(state))
	return nil
}

func generateRandomState() (string, error) {
	b := make([]byte, 32)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}

	state := base64.StdEncoding.EncodeToString(b)

	return state, nil
}
