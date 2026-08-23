package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
)

// decodeRequiredACBaseFields validates the NHP 1.2 base fields while leaving
// application-specific AOP/ART extension fields forward-compatible. Unknown
// fields and duplicate extension fields retain their existing JSON behavior,
// but each requested base field is presence-aware and accepted exactly once.
func decodeRequiredACBaseFields(raw []byte, requireOpenTime, requireErrCode bool) (uint64, string, uint32, string, error) {
	dec := json.NewDecoder(bytes.NewReader(raw))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return 0, "", 0, "", errors.New("AOP/ART must be one JSON object")
	}
	var sessionID uint64
	var sessionOwnerID string
	var openTime uint32
	var errCode string
	sessionFound := false
	sessionOwnerFound := false
	openTimeFound := false
	errCodeFound := false
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return 0, "", 0, "", err
		}
		key, ok := token.(string)
		if !ok {
			return 0, "", 0, "", errors.New("AOP/ART object key is not a string")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return 0, "", 0, "", err
		}
		switch key {
		case "sessId":
			if sessionFound {
				return 0, "", 0, "", errors.New("AOP/ART contains duplicate sessId")
			}
			sessionFound = true
			if err := json.Unmarshal(value, &sessionID); err != nil || sessionID == 0 ||
				!bytes.Equal(bytes.TrimSpace(value), []byte(strconv.FormatUint(sessionID, 10))) {
				return 0, "", 0, "", errors.New("AOP/ART sessId must be a canonical nonzero uint64 number")
			}
		case "sessOwnerId":
			if sessionOwnerFound {
				return 0, "", 0, "", errors.New("AOP/ART contains duplicate sessOwnerId")
			}
			sessionOwnerFound = true
			if err := json.Unmarshal(value, &sessionOwnerID); err != nil || !ValidNHPSessionOwnerID(sessionOwnerID) {
				return 0, "", 0, "", errors.New("AOP/ART sessOwnerId must be a canonical lowercase 128-bit hex string")
			}
		case "opnTime":
			if !requireOpenTime {
				continue
			}
			if openTimeFound {
				return 0, "", 0, "", errors.New("AOP contains duplicate opnTime")
			}
			openTimeFound = true
			var parsed uint64
			if err := json.Unmarshal(value, &parsed); err != nil || parsed > uint64(^uint32(0)) ||
				!bytes.Equal(bytes.TrimSpace(value), []byte(strconv.FormatUint(parsed, 10))) {
				return 0, "", 0, "", errors.New("AOP opnTime must be a canonical uint32 number")
			}
			openTime = uint32(parsed)
		case "errCode":
			if !requireErrCode {
				continue
			}
			if errCodeFound {
				return 0, "", 0, "", errors.New("ART contains duplicate errCode")
			}
			errCodeFound = true
			if err := json.Unmarshal(value, &errCode); err != nil || errCode == "" {
				return 0, "", 0, "", errors.New("ART errCode must be a nonempty JSON string")
			}
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return 0, "", 0, "", errors.New("AOP/ART JSON object is unterminated")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return 0, "", 0, "", errors.New("AOP/ART contains a trailing JSON value")
	}
	if !sessionFound {
		return 0, "", 0, "", errors.New("AOP/ART is missing sessId")
	}
	if !sessionOwnerFound {
		return 0, "", 0, "", errors.New("AOP/ART is missing sessOwnerId")
	}
	if requireOpenTime && !openTimeFound {
		return 0, "", 0, "", errors.New("AOP is missing opnTime")
	}
	if requireErrCode && !errCodeFound {
		return 0, "", 0, "", errors.New("ART is missing errCode")
	}
	return sessionID, sessionOwnerID, openTime, errCode, nil
}

func DecodeServerACOpsMsg(raw []byte, out *ServerACOpsMsg) error {
	if out == nil {
		return errors.New("nil AOP output")
	}
	sessionID, sessionOwnerID, openTime, _, err := decodeRequiredACBaseFields(raw, true, false)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return err
	}
	if out.SessionId != sessionID || out.SessionOwnerId != sessionOwnerID || out.OpenTime != openTime {
		return fmt.Errorf("AOP base fields changed during decode")
	}
	if err := validateAOPIdentityFields(raw, out); err != nil {
		return err
	}
	return nil
}

// validateAOPIdentityFields pins the NHP 1.2 Public Key field and the LayerV
// session/retry extensions without closing the AOP object to future unrelated
// extension fields. Each security-bearing field is presence-aware, canonical,
// and accepted at most once.
func validateAOPIdentityFields(raw []byte, out *ServerACOpsMsg) error {
	if out == nil {
		return errors.New("nil AOP output")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	start, err := dec.Token()
	if err != nil || start != json.Delim('{') {
		return errors.New("AOP must be one JSON object")
	}
	present := make(map[string]bool, 5)
	for dec.More() {
		token, err := dec.Token()
		if err != nil {
			return err
		}
		key, ok := token.(string)
		if !ok {
			return errors.New("AOP object key is not a string")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err
		}
		switch key {
		case "agentPubKey", "sessIssuedAtMillis", "runId", "runAttempt":
			if present[key] {
				return fmt.Errorf("AOP contains duplicate %s", key)
			}
			present[key] = true
		}
		switch key {
		case "agentPubKey":
			var parsed string
			if err := json.Unmarshal(value, &parsed); err != nil || !ValidNHPAgentPublicKey(parsed) {
				return errors.New("AOP agentPubKey must be a canonical 32-byte public key")
			}
		case "sessIssuedAtMillis":
			var parsed int64
			if err := json.Unmarshal(value, &parsed); err != nil || parsed <= 0 ||
				!bytes.Equal(bytes.TrimSpace(value), []byte(strconv.FormatInt(parsed, 10))) {
				return errors.New("AOP sessIssuedAtMillis must be a canonical positive int64 number")
			}
		case "runId":
			var parsed string
			if err := json.Unmarshal(value, &parsed); err != nil || ValidateAgentKnockRunID(parsed) != nil {
				return errors.New("AOP runId must be a canonical agent run identifier")
			}
		case "runAttempt":
			var parsed uint64
			if err := json.Unmarshal(value, &parsed); err != nil || parsed == 0 ||
				!bytes.Equal(bytes.TrimSpace(value), []byte(strconv.FormatUint(parsed, 10))) {
				return errors.New("AOP runAttempt must be a canonical positive uint64 number")
			}
		}
	}
	end, err := dec.Token()
	if err != nil || end != json.Delim('}') {
		return errors.New("AOP JSON object is unterminated")
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return errors.New("AOP contains a trailing JSON value")
	}
	if !present["sessIssuedAtMillis"] || out.SessionIssuedAtMillis <= 0 {
		return errors.New("AOP is missing sessIssuedAtMillis")
	}
	if !present["agentPubKey"] || !ValidNHPAgentPublicKey(out.AgentPublicKey) {
		return errors.New("AOP is missing agentPubKey")
	}
	if out.AuthServiceId == RegisteredAgentAuthServiceID {
		if !present["runId"] || ValidateAgentKnockRunID(out.RunID) != nil {
			return errors.New("registered-agent AOP is missing runId")
		}
		if !present["runAttempt"] || out.RunAttempt == 0 {
			return errors.New("registered-agent AOP is missing runAttempt")
		}
	}
	return nil
}

func DecodeACOpsResultMsg(raw []byte, out *ACOpsResultMsg) error {
	if out == nil {
		return errors.New("nil ART output")
	}
	sessionID, sessionOwnerID, _, errCode, err := decodeRequiredACBaseFields(raw, false, true)
	if err != nil {
		return err
	}
	if err := json.Unmarshal(raw, out); err != nil {
		return err
	}
	if out.SessionId != sessionID || out.SessionOwnerId != sessionOwnerID || out.ErrCode != errCode {
		return fmt.Errorf("ART base fields changed during decode")
	}
	return nil
}
