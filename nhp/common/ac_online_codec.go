package common

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

var acOnlineSessionControlFields = map[string]struct{}{
	"bootId":            {},
	"sessFlushGen":      {},
	"sessFlushComplete": {},
}

// DecodeACOnlineMsg preserves forward compatibility for ordinary AOL
// extensions while making the session-control tuple closed and
// presence-aware. A partial tuple, duplicate security field, or noncanonical
// generation is rejected before any registration/storage side effect.
func DecodeACOnlineMsg(raw []byte, out *ACOnlineMsg) error {
	if out == nil {
		return errors.New("nil ACOnlineMsg output")
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	tok, err := dec.Token()
	if err != nil {
		return err
	}
	if delim, ok := tok.(json.Delim); !ok || delim != '{' {
		return errors.New("AC online message must be one JSON object")
	}
	present := make(map[string]bool, len(acOnlineSessionControlFields))
	rawFields := make(map[string]json.RawMessage, len(acOnlineSessionControlFields))
	for dec.More() {
		nameToken, err := dec.Token()
		if err != nil {
			return err
		}
		name, ok := nameToken.(string)
		if !ok {
			return errors.New("AC online object key must be a string")
		}
		var value json.RawMessage
		if err := dec.Decode(&value); err != nil {
			return err
		}
		if _, securityField := acOnlineSessionControlFields[name]; !securityField {
			continue
		}
		if present[name] {
			return fmt.Errorf("AC online message contains duplicate %s", name)
		}
		present[name] = true
		rawFields[name] = value
	}
	if tok, err = dec.Token(); err != nil {
		return err
	} else if delim, ok := tok.(json.Delim); !ok || delim != '}' {
		return errors.New("AC online object is not closed")
	}
	var trailing any
	if err := dec.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("AC online message contains a trailing JSON value")
		}
		return err
	}

	securityPresent := present["bootId"] || present["sessFlushGen"] || present["sessFlushComplete"]
	if securityPresent && !(present["bootId"] && present["sessFlushGen"] && present["sessFlushComplete"]) {
		return errors.New("AC online session-control tuple must contain bootId, sessFlushGen, and sessFlushComplete")
	}
	if securityPresent {
		var bootID string
		if err := json.Unmarshal(rawFields["bootId"], &bootID); err != nil || !ValidNHPACBootID(bootID) {
			return errors.New("AC online bootId must be a canonical lowercase 128-bit value")
		}
		generation, err := decodeCanonicalPositiveUint64(rawFields["sessFlushGen"])
		if err != nil {
			return fmt.Errorf("AC online sessFlushGen: %w", err)
		}
		var complete bool
		if err := json.Unmarshal(rawFields["sessFlushComplete"], &complete); err != nil {
			return errors.New("AC online sessFlushComplete must be a JSON boolean")
		}
		if !complete {
			return errors.New("AC online sessFlushComplete must be true before registration")
		}
		if err := json.Unmarshal(raw, out); err != nil {
			return err
		}
		out.BootID = bootID
		out.SessionFlushGeneration = generation
		out.SessionFlushComplete = true
		return nil
	}
	return json.Unmarshal(raw, out)
}

func decodeCanonicalPositiveUint64(raw []byte) (uint64, error) {
	if len(raw) == 0 || raw[0] < '1' || raw[0] > '9' {
		return 0, errors.New("must be a canonical positive uint64 number")
	}
	for _, b := range raw[1:] {
		if b < '0' || b > '9' {
			return 0, errors.New("must be a canonical positive uint64 number")
		}
	}
	var value uint64
	if err := json.Unmarshal(raw, &value); err != nil || value == 0 {
		return 0, errors.New("must be a canonical positive uint64 number")
	}
	return value, nil
}
