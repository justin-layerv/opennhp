package redirecturl

import (
	"encoding/json"
	"errors"
	"net/url"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/log"

	"github.com/fengyily/nhp-plugins-sdk/models"
	"github.com/fengyily/nhp-plugins-sdk/resource"
	nhpsdkutils "github.com/fengyily/nhp-plugins-sdk/utils"
)

var errInvalidRedirectURL = errors.New("invalid redirect url")

// SafeForLog returns a redirect URL without userinfo, query, or fragment data.
// It intentionally preserves scheme, host, and path; use it only for redirect
// URLs whose secrets are confined to userinfo, query, or fragment components.
func SafeForLog(raw string) string {
	if raw == "" {
		return ""
	}

	u, err := url.Parse(raw)
	if err != nil {
		return "<invalid redirect URL>"
	}

	safe := *u
	safe.User = nil
	safe.RawQuery = ""
	safe.Fragment = ""
	safe.RawFragment = ""
	return safe.String()
}

// GetByResource mirrors nhpplugins.GetRedirectUrlByResource from
// github.com/fengyily/nhp-plugins-sdk v0.1.30 while avoiding its token-bearing
// logs. The returned URL still includes access_token for clients. Empty
// redirect/no-host returns intentionally match the SDK and are logged here so
// callers do not duplicate those diagnostics.
func GetByResource(ackMsg *common.ServerKnockAckMsg, res *common.ResourceData, conf resource.Config, action, user string) (*common.ServerKnockAckMsg, string, error) {
	if len(res.RedirectUrl) == 0 {
		// Preserve SDK v0.1.30's empty-redirect diagnostic for parity, even
		// though some callers treat an empty helper result as a benign fallback.
		log.Error("RedirectUrl is not provided.")
		return ackMsg, "", nil
	}

	redirectURL, err := url.Parse(res.RedirectUrl)
	if err != nil {
		log.Error("failed to parse redirect url for resource %s (len=%d)", res.ResourceId, len(res.RedirectUrl))
		return ackMsg, "", errInvalidRedirectURL
	}

	defaultRes := nhpsdkutils.Loadbalancing(ackMsg.ResourceHost)
	if len(defaultRes) == 0 {
		log.Error("no resource host available for redirect for resource %s", res.ResourceId)
		return ackMsg, "", nil
	}
	redirectURL.Host = defaultRes
	log.Info("All host [%+v], load balancing redirectURL: %s", ackMsg.ResourceHost, SafeForLog(redirectURL.String()))

	var subServices []models.Resource
	if subArray, ok := res.ExInfo["Sub"].([]models.Resource); ok {
		log.Debug("subArray is of type []models.Resource{} with length %d", len(subArray))
		for _, item := range subArray {
			subServices = append(subServices, models.Resource{
				IP:            item.IP,
				Port:          item.Port,
				Scheme:        item.Scheme,
				MapPort:       item.MapPort,
				ConnectorPort: item.ConnectorPort,
			})
		}
	} else {
		log.Debug("sub is not an array or missing, skipping sub services")
	}

	if len(user) == 0 {
		user = "anonymous"
	}

	serviceInfo := models.ServiceInfo{
		AppId:  res.ResourceId,
		Action: action,
		User:   user,
		Resource: models.Resource{
			IP:            nhpsdkutils.GetStringFromMap(res.ExInfo, "Ip"),
			Port:          nhpsdkutils.GetIntFromMap(res.ExInfo, "Port"),
			Scheme:        nhpsdkutils.GetStringFromMap(res.ExInfo, "Scheme"),
			MapPort:       nhpsdkutils.GetIntFromMap(res.ExInfo, "MapPort"),
			ConnectorPort: nhpsdkutils.GetIntFromMap(res.ExInfo, "ConPort"),
		},
		Sub: subServices,
	}

	infoJSON, err := json.Marshal(serviceInfo)
	if err != nil {
		log.Error("failed to marshal service info: %v", err)
		// Intentional hardening divergence from SDK v0.1.30: never mint a
		// redirect token from empty JSON if ServiceInfo becomes non-marshalable.
		return ackMsg, "", err
	}

	encryptedInfo, err := nhpsdkutils.EncryptWithGCM(infoJSON, conf.AesKey)
	if err != nil {
		log.Error("failed to encrypt service info: %v", err)
		return ackMsg, "", err
	}

	tokenString, err := nhpsdkutils.CreateAccessJWT(encryptedInfo, conf.AesKey)
	if err != nil {
		log.Error("failed to generate JWT: %v", err)
		return ackMsg, "", err
	}

	query := redirectURL.Query()
	query.Set("access_token", tokenString)
	redirectURL.RawQuery = query.Encode()
	return ackMsg, redirectURL.String(), nil
}
