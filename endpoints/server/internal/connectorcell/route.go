package connectorcell

import "github.com/OpenNHP/opennhp/nhp/core"

// routeCompletionIntent is an allocation-free structural probe. It recognizes
// only a top-level aspId=agent paired with query=agent_credential_recovery in a
// top-level usrData object. It never decodes or retains grant/key values. Its
// answer can select only the strict decoder or a frozen rejection; it can never
// authorize an Authority call by itself.
func routeCompletionIntent(raw []byte) bool {
	return routeASPQueryIntent(raw, completionAspID, completionQuery)
}

// IsRegistrationOTPIntent and IsRegistrationIntent intentionally apply the
// same body predicate: the authenticated NHP_OTP versus NHP_REG header is the
// sole operation discriminator. The separate names keep call sites tied to
// their header dispatch while both conservatively claim only bodies carrying
// the exact top-level qURL Connector aspId. Once claimed, the strict decoder
// owns malformed duplicate, unknown, and trailing forms so they cannot fall
// through to permissive plugin decoding.
func IsRegistrationOTPIntent(raw []byte) bool { return routeRegistrationASPIntent(raw) }

func IsRegistrationIntent(raw []byte) bool { return routeRegistrationASPIntent(raw) }

// IsRegistrationCompletionIntent additionally requires the exact completion
// query in the immediate top-level usrData object. Other agent LST operations
// remain on their existing dispatch paths.
func IsRegistrationCompletionIntent(raw []byte) bool {
	return routeASPQueryIntent(raw, registrationAspID, registrationCompletionQuery)
}

// IsConnectorResourceIntent recognizes only the registered-agent Connector
// resource discovery operation. Once this exact aspId/query pair is present,
// the strict resource decoder owns the body (including malformed duplicate,
// unknown, and trailing forms) so it can never fall through to permissive
// ListService dispatch.
func IsConnectorResourceIntent(raw []byte) bool {
	return routeASPQueryIntent(raw, connectorResourceAspID, connectorResourceQuery)
}

func routeRegistrationASPIntent(raw []byte) bool {
	return routeIntent(raw, registrationAspID, "", false)
}

func routeASPQueryIntent(raw []byte, aspID, query string) bool {
	return routeIntent(raw, aspID, query, true)
}

func routeIntent(raw []byte, aspID, query string, queryRequired bool) bool {
	if len(raw) == 0 || len(raw) > core.MaxDecompressedBodySize {
		return false
	}
	s := completionIntentScanner{
		raw: raw, targetASP: aspID, targetQuery: query,
		hasQuery: !queryRequired,
	}
	i := s.space(0)
	if i >= len(raw) || raw[i] != '{' {
		return false
	}
	return s.root(i + 1)
}

type completionIntentScanner struct {
	raw         []byte
	targetASP   string
	targetQuery string
	hasASP      bool
	hasQuery    bool
}

func (s *completionIntentScanner) root(i int) bool {
	for {
		i = s.space(i)
		if i >= len(s.raw) || s.raw[i] == '}' {
			return false
		}
		keyStart, keyEnd, ok := s.stringToken(i)
		if !ok {
			return false
		}
		i = s.space(keyEnd)
		if i >= len(s.raw) || s.raw[i] != ':' {
			return false
		}
		i = s.space(i + 1)
		switch {
		case jsonStringTokenEquals(s.raw[keyStart:keyEnd], "aspId"):
			valueStart, valueEnd, stringOK := s.stringToken(i)
			if stringOK {
				s.hasASP = s.hasASP || jsonStringTokenEquals(s.raw[valueStart:valueEnd], s.targetASP)
				i = valueEnd
			} else {
				i, ok = s.value(i)
				if !ok {
					return false
				}
			}
		case jsonStringTokenEquals(s.raw[keyStart:keyEnd], "usrData") && i < len(s.raw) && s.raw[i] == '{':
			i, ok = s.data(i + 1)
			if !ok {
				return false
			}
		default:
			i, ok = s.value(i)
			if !ok {
				return false
			}
		}
		if s.hasASP && s.hasQuery {
			return true
		}
		i = s.space(i)
		if i >= len(s.raw) {
			return false
		}
		switch s.raw[i] {
		case ',':
			i++
		case '}':
			return false
		default:
			return false
		}
	}
}

func (s *completionIntentScanner) data(i int) (int, bool) {
	for {
		i = s.space(i)
		if i >= len(s.raw) {
			return i, false
		}
		if s.raw[i] == '}' {
			return i + 1, true
		}
		keyStart, keyEnd, ok := s.stringToken(i)
		if !ok {
			return i, false
		}
		i = s.space(keyEnd)
		if i >= len(s.raw) || s.raw[i] != ':' {
			return i, false
		}
		i = s.space(i + 1)
		if jsonStringTokenEquals(s.raw[keyStart:keyEnd], "query") {
			valueStart, valueEnd, stringOK := s.stringToken(i)
			if stringOK {
				s.hasQuery = s.hasQuery || jsonStringTokenEquals(s.raw[valueStart:valueEnd], s.targetQuery)
				i = valueEnd
			} else {
				i, ok = s.value(i)
				if !ok {
					return i, false
				}
			}
		} else {
			i, ok = s.value(i)
			if !ok {
				return i, false
			}
		}
		if s.hasQuery && s.hasASP {
			return i, true
		}
		i = s.space(i)
		if i >= len(s.raw) {
			return i, false
		}
		switch s.raw[i] {
		case ',':
			i++
		case '}':
			return i + 1, true
		default:
			return i, false
		}
	}
}

func (s completionIntentScanner) value(i int) (int, bool) {
	i = s.space(i)
	if i >= len(s.raw) {
		return i, false
	}
	if s.raw[i] == '"' {
		_, end, ok := s.stringToken(i)
		return end, ok
	}
	if s.raw[i] == '{' || s.raw[i] == '[' {
		return s.composite(i)
	}
	start := i
	for i < len(s.raw) {
		switch s.raw[i] {
		case ' ', '\t', '\r', '\n', ',', '}', ']':
			return i, i > start
		default:
			i++
		}
	}
	return i, i > start
}

// composite skips an unknown object/array with a single depth counter. Exact
// bracket-type validation belongs to the strict decoder; accepting mismatched
// delimiters here can only conservatively route a malformed request to 52414.
func (s completionIntentScanner) composite(i int) (int, bool) {
	depth := 0
	for i < len(s.raw) {
		switch s.raw[i] {
		case '"':
			_, end, ok := s.stringToken(i)
			if !ok {
				return i, false
			}
			i = end
			continue
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return i + 1, true
			}
		}
		i++
	}
	return i, false
}

func (s completionIntentScanner) stringToken(i int) (int, int, bool) {
	if i >= len(s.raw) || s.raw[i] != '"' {
		return i, i, false
	}
	start := i
	for i++; i < len(s.raw); i++ {
		switch s.raw[i] {
		case '"':
			return start, i + 1, true
		case '\\':
			i++
			if i >= len(s.raw) {
				return start, i, false
			}
		case 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15,
			16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31:
			return start, i, false
		}
	}
	return start, i, false
}

func (s completionIntentScanner) space(i int) int {
	for i < len(s.raw) {
		switch s.raw[i] {
		case ' ', '\t', '\r', '\n':
			i++
		default:
			return i
		}
	}
	return i
}

func jsonStringTokenEquals(token []byte, want string) bool {
	if len(token) < 2 || token[0] != '"' || token[len(token)-1] != '"' {
		return false
	}
	wantIndex := 0
	for i := 1; i < len(token)-1; i++ {
		value := token[i]
		if value == '\\' {
			i++
			if i >= len(token)-1 {
				return false
			}
			switch token[i] {
			case '"', '\\', '/':
				value = token[i]
			case 'b':
				value = '\b'
			case 'f':
				value = '\f'
			case 'n':
				value = '\n'
			case 'r':
				value = '\r'
			case 't':
				value = '\t'
			case 'u':
				if i+4 >= len(token)-1 {
					return false
				}
				code, ok := asciiHex4(token[i+1 : i+5])
				if !ok || code > 0x7f {
					return false
				}
				value = byte(code)
				i += 4
			default:
				return false
			}
		}
		if wantIndex >= len(want) || value != want[wantIndex] {
			return false
		}
		wantIndex++
	}
	return wantIndex == len(want)
}

func asciiHex4(value []byte) (uint16, bool) {
	if len(value) != 4 {
		return 0, false
	}
	var decoded uint16
	for _, b := range value {
		decoded <<= 4
		switch {
		case b >= '0' && b <= '9':
			decoded |= uint16(b - '0')
		case b >= 'a' && b <= 'f':
			decoded |= uint16(b-'a') + 10
		case b >= 'A' && b <= 'F':
			decoded |= uint16(b-'A') + 10
		default:
			return 0, false
		}
	}
	return decoded, true
}
