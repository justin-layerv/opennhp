package common

import (
	"encoding/base64"
	"fmt"
	"strings"
	"testing"
)

func TestACSessionCodecsRequireCanonicalSessionID(t *testing.T) {
	const owner = "00112233445566778899aabbccddeeff"
	agentKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("A", NHPAgentPublicKeyBytes)))
	validAOP := `{"sessId":18446744073709551615,"sessOwnerId":"` + owner + `","agentPubKey":"` + agentKey + `","sessIssuedAtMillis":1700000000000,"opnTime":1,"future":"kept"}`
	var aop ServerACOpsMsg
	if err := DecodeServerACOpsMsg([]byte(validAOP), &aop); err != nil || aop.SessionId != ^uint64(0) || aop.OpenTime != 1 {
		t.Fatalf("valid AOP = %+v, %v", aop, err)
	}
	validART := `{"sessId":18446744073709551615,"sessOwnerId":"` + owner + `","errCode":"0","future":"kept"}`
	var art ACOpsResultMsg
	if err := DecodeACOpsResultMsg([]byte(validART), &art); err != nil || art.SessionId != ^uint64(0) {
		t.Fatalf("valid ART = %+v, %v", art, err)
	}
	var closeAOP ServerACOpsMsg
	if err := DecodeServerACOpsMsg([]byte(`{"sessId":1,"sessOwnerId":"`+owner+`","agentPubKey":"`+agentKey+`","sessIssuedAtMillis":1700000000000,"opnTime":0}`), &closeAOP); err != nil || closeAOP.OpenTime != 0 {
		t.Fatalf("canonical close AOP = %+v, %v", closeAOP, err)
	}

	for name, value := range map[string]string{
		"missing":   "",
		"zero":      `0`,
		"null":      `null`,
		"string":    `"1"`,
		"negative":  `-1`,
		"fraction":  `1.5`,
		"exponent":  `1e0`,
		"overflow":  `18446744073709551616`,
		"duplicate": `1,"sessId":2`,
	} {
		t.Run(name, func(t *testing.T) {
			body := `{"sessOwnerId":"` + owner + `","opnTime":1}`
			if value != "" {
				body = fmt.Sprintf(`{"sessId":%s,"sessOwnerId":"%s","opnTime":1}`, value, owner)
			}
			if err := DecodeServerACOpsMsg([]byte(body), &ServerACOpsMsg{}); err == nil {
				t.Fatalf("invalid AOP sessId %q accepted", value)
			}
			artBody := strings.Replace(body, `"opnTime":1`, `"errCode":"0"`, 1)
			if err := DecodeACOpsResultMsg([]byte(artBody), &ACOpsResultMsg{}); err == nil {
				t.Fatalf("invalid ART sessId %q accepted", value)
			}
		})
	}

	for name, value := range map[string]string{
		"missing":   "",
		"null":      `null`,
		"string":    `"1"`,
		"negative":  `-1`,
		"fraction":  `1.5`,
		"exponent":  `1e0`,
		"overflow":  `4294967296`,
		"duplicate": `1,"opnTime":2`,
	} {
		t.Run("opnTime "+name, func(t *testing.T) {
			body := `{"sessId":1,"sessOwnerId":"` + owner + `"}`
			if value != "" {
				body = fmt.Sprintf(`{"sessId":1,"sessOwnerId":"%s","opnTime":%s}`, owner, value)
			}
			if err := DecodeServerACOpsMsg([]byte(body), &ServerACOpsMsg{}); err == nil {
				t.Fatalf("invalid AOP opnTime %q accepted", value)
			}
		})
	}

	for name, value := range map[string]string{
		"missing":   "",
		"null":      `null`,
		"number":    `0`,
		"empty":     `""`,
		"duplicate": `"0","errCode":"52005"`,
	} {
		t.Run("errCode "+name, func(t *testing.T) {
			body := `{"sessId":1,"sessOwnerId":"` + owner + `"}`
			if value != "" {
				body = fmt.Sprintf(`{"sessId":1,"sessOwnerId":"%s","errCode":%s}`, owner, value)
			}
			if err := DecodeACOpsResultMsg([]byte(body), &ACOpsResultMsg{}); err == nil {
				t.Fatalf("invalid ART errCode %q accepted", value)
			}
		})
	}

	for name, value := range map[string]string{
		"missing":   "",
		"empty":     `""`,
		"uppercase": `"00112233445566778899AABBCCDDEEFF"`,
		"short":     `"0011"`,
		"nonhex":    `"00112233445566778899aabbccddeefg"`,
		"null":      `null`,
		"duplicate": `"00112233445566778899aabbccddeeff","sessOwnerId":"ffeeddccbbaa99887766554433221100"`,
	} {
		t.Run("sessOwnerId "+name, func(t *testing.T) {
			body := `{"sessId":1,"opnTime":1}`
			if value != "" {
				body = fmt.Sprintf(`{"sessId":1,"sessOwnerId":%s,"opnTime":1}`, value)
			}
			if err := DecodeServerACOpsMsg([]byte(body), &ServerACOpsMsg{}); err == nil {
				t.Fatalf("invalid AOP sessOwnerId %q accepted", value)
			}
			artBody := strings.Replace(body, `"opnTime":1`, `"errCode":"0"`, 1)
			if err := DecodeACOpsResultMsg([]byte(artBody), &ACOpsResultMsg{}); err == nil {
				t.Fatalf("invalid ART sessOwnerId %q accepted", value)
			}
		})
	}
}

func TestACSessionCodecRequiresCanonicalRegisteredAgentRetryBinding(t *testing.T) {
	const owner = "00112233445566778899aabbccddeeff"
	agentKey := base64.StdEncoding.EncodeToString([]byte(strings.Repeat("A", NHPAgentPublicKeyBytes)))
	base := `{"sessId":1,"sessOwnerId":"` + owner + `","agentPubKey":"` + agentKey + `","sessIssuedAtMillis":1700000000000,"usrId":"u","devId":"d","aspId":"agent","resId":"r","srcAddrs":[],"dstAddrs":[],"opnTime":30`
	valid := base + `,"runId":"0123456789abcdef","runAttempt":18446744073709551615}`
	var got ServerACOpsMsg
	if err := DecodeServerACOpsMsg([]byte(valid), &got); err != nil {
		t.Fatalf("canonical registered-agent AOP rejected: %v", err)
	}
	if got.RunID != "0123456789abcdef" || got.RunAttempt != ^uint64(0) {
		t.Fatalf("retry binding = (%q,%d), want canonical max attempt", got.RunID, got.RunAttempt)
	}

	for name, suffix := range map[string]string{
		"missing":   `,"runId":"0123456789abcdef"}`,
		"zero":      `,"runId":"0123456789abcdef","runAttempt":0}`,
		"null":      `,"runId":"0123456789abcdef","runAttempt":null}`,
		"string":    `,"runId":"0123456789abcdef","runAttempt":"1"}`,
		"negative":  `,"runId":"0123456789abcdef","runAttempt":-1}`,
		"fraction":  `,"runId":"0123456789abcdef","runAttempt":1.5}`,
		"exponent":  `,"runId":"0123456789abcdef","runAttempt":1e0}`,
		"overflow":  `,"runId":"0123456789abcdef","runAttempt":18446744073709551616}`,
		"duplicate": `,"runId":"0123456789abcdef","runAttempt":1,"runAttempt":2}`,
	} {
		t.Run(name, func(t *testing.T) {
			if err := DecodeServerACOpsMsg([]byte(base+suffix), &ServerACOpsMsg{}); err == nil {
				t.Fatalf("invalid runAttempt %s accepted", name)
			}
		})
	}
}
