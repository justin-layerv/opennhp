package common

import (
	"context"
	"net/url"
)

// an object contains represent knocking user information
type AgentUser struct {
	UserId         string
	DeviceId       string
	OrganizationId string
	AuthServiceId  string
}

// authsvcprovider and resource
type LoginPageContext struct {
	Title              string `json:"title,omitempty"`
	ClientId           string `json:"clientId,omitempty"`
	AppKey             string `json:"appKey,omitempty"`
	AppSecret          string `json:"appSecret,omitempty"`
	RedirectUrl        string `json:"redirectUrl,omitempty"`
	RedirectWithParams bool   `json:"redirectWithParams,omitempty"`
}

type ResourceData struct {
	ResourceGroup `mapstructure:",squash"`
	// optional extension data
	AppKey             string         `json:"appKey,omitempty"`
	AppSecret          string         `json:"appSecret,omitempty"`
	AccessKey          string         `json:"accessKey,omitempty"` //nolint:gosec // G117: JSON tag required — resource config loaded from TOML, not user input
	SecretKey          string         `json:"secretKey,omitempty"`
	ExInfo             map[string]any `json:"exinfo,omitempty"`
	RedirectUrl        string         `json:"redirectUrl,omitempty"`
	RedirectWithParams bool           `json:"redirectWithParams,omitempty"`
	SkipAuth           bool           `json:"skipAuth,omitempty"`
	CookieDomain       string         `json:"cookieDomain,omitempty"`
}

type ResourceGroupMap map[string]*ResourceData
type AuthServiceProviderData struct {
	ResourceGroups ResourceGroupMap `json:"ress"`
	AuthSvcId      string           `json:"aspId"`
	PluginPath     string           `json:"pluginPath,omitempty"`
	PluginHash     string           `json:"pluginHash,omitempty"`
}
type AuthSvcProviderMap map[string]*AuthServiceProviderData

// FindResource returns the first ResourceInfo for a given resource ID.
// This is used by server-to-server forwarding to find the AC connection.
// Returns nil if the resource ID is not found or has no resource entries.
func (asp *AuthServiceProviderData) FindResource(resourceId string) *ResourceInfo {
	if asp == nil {
		return nil
	}
	resData := asp.ResourceGroups[resourceId]
	if resData == nil {
		return nil
	}
	// Return first resource info (all entries in a resource group typically use the same AC)
	for _, info := range resData.Resources {
		return info
	}
	return nil
}

// GetResourceData returns the ResourceData for a given resource ID.
// Returns nil if the resource ID is not found.
func (asp *AuthServiceProviderData) GetResourceData(resourceId string) *ResourceData {
	if asp == nil {
		return nil
	}
	return asp.ResourceGroups[resourceId]
}

// requests
type NhpOTPRequest struct {
	Msg     *AgentOTPMsg `json:"msg"`
	SrcAddr *NetAddress  `json:"srcAddr"`
}

type NhpRegisterRequest struct {
	Msg       *AgentRegisterMsg     `json:"msg"`
	Ack       *ServerRegisterAckMsg `json:"ack"`
	PublicKey string                `json:"pubKey"`
	SrcAddr   *NetAddress           `json:"srcAddr"`
}

type NhpAuthRequest struct {
	Msg            *AgentKnockMsg     `json:"msg"`
	Ack            *ServerKnockAckMsg `json:"ack"`
	PublicKey      string             `json:"pubKey"`
	SrcAddr        *NetAddress        `json:"srcAddr"`
	OriginalPacket []byte             `json:"-"` // Original encrypted knock packet for server-to-server forwarding
}

type NhpListRequest struct {
	Msg       *AgentListMsg        `json:"msg"`
	Ack       *ServerListResultMsg `json:"ack"`
	PublicKey string               `json:"pubKey"`
	SrcAddr   *NetAddress          `json:"srcAddr"`
}

type HttpKnockRequest struct {
	UserId         string   `json:"usrId"`
	DeviceId       string   `json:"devId"`
	OrganizationId string   `json:"orgId,omitempty"`
	AuthServiceId  string   `json:"aspId"`
	ResourceId     string   `json:"resId"`
	Token          string   `json:"token"`
	Code           string   `json:"code"`
	DstUrl         string   `json:"dstUrl"`
	Command        string   `json:"command"`
	Url            *url.URL `json:"-"`
	UserAgent      string   `json:"-"`
	SrcIp          string   `json:"srcIp,omitempty"`
	SrcPort        int      `json:"srcPort,omitempty"`
	Forwarded      bool     `json:"forwarded,omitempty"` // Set by internal forwarding to prevent loops

	// Ctx carries the request context for downstream cancellation and value
	// propagation (e.g., correlation IDs).
	//
	// DEPRECATED: storing context in a struct is a Go anti-pattern. The field
	// is retained because the github.com/fengyily/nhp-plugins-sdk callback
	// signature `HttpPluginPostAuthFunc` does not accept an explicit context
	// parameter, so plugins built against that SDK have no other way to
	// thread context through to handleHttpOpenResource. Internal nhp code
	// should NOT add new readers of this field; once the SDK callback gains
	// a context parameter (or is vendored/forked) this field can be removed.
	Ctx context.Context `json:"-"`
}

type HttpRefreshRequest struct {
	Token string `json:"token"`
	SrcIp string `json:"srcIp"`
}
