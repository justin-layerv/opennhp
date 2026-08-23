package common

import (
	"encoding/json"
	"errors"
	"fmt"
)

// DecodeServerACAckMsg strictly binds a successful NHP_AAK to the exact AOL
// process boot, completed flush generation, and transaction. Ordinary AAK
// fields remain extensible, but duplicates are rejected and the authority
// tuple is mandatory on success. A rejected AAK must omit the tuple.
func DecodeServerACAckMsg(raw []byte, out *ServerACAckMsg) error {
	if out == nil {
		return errors.New("nil ServerACAckMsg output")
	}
	object, err := scanACSessionCloseObject(raw)
	if err != nil {
		return err
	}
	decoded := ServerACAckMsg{}
	if err := json.Unmarshal(raw, &decoded); err != nil {
		return err
	}
	errCodeRaw, ok := object["errCode"]
	if !ok || json.Unmarshal(errCodeRaw, &decoded.ErrCode) != nil {
		return errors.New("AAK errCode must be a JSON string")
	}
	registeredRaw, registeredPresent := object["registered"]
	if registeredPresent {
		if err := json.Unmarshal(registeredRaw, &decoded.Registered); err != nil {
			return errors.New("AAK registered must be a JSON boolean")
		}
	}

	tuplePresent := 0
	for _, name := range []string{"bootId", "sessFlushGen", "aolTrxId"} {
		if _, present := object[name]; present {
			tuplePresent++
		}
	}
	if IsSuccessErrCode(decoded.ErrCode) {
		if !registeredPresent || !decoded.Registered {
			return errors.New("successful AAK must contain registered:true")
		}
		if tuplePresent != 3 {
			return errors.New("successful AAK must contain bootId, sessFlushGen, and aolTrxId")
		}
		if err := json.Unmarshal(object["bootId"], &decoded.BootID); err != nil || !ValidNHPACBootID(decoded.BootID) {
			return errors.New("AAK bootId must be a canonical lowercase 128-bit value")
		}
		generation, err := decodeCanonicalPositiveUint64(object["sessFlushGen"])
		if err != nil {
			return fmt.Errorf("AAK sessFlushGen: %w", err)
		}
		transactionID, err := decodeCanonicalPositiveUint64(object["aolTrxId"])
		if err != nil {
			return fmt.Errorf("AAK aolTrxId: %w", err)
		}
		decoded.SessionFlushGeneration = generation
		decoded.AOLTransactionID = transactionID
	} else if tuplePresent != 0 {
		return errors.New("rejected AAK must omit the session-control authority tuple")
	}
	*out = decoded
	return nil
}
