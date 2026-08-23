package server

import (
	"errors"

	"github.com/OpenNHP/opennhp/nhp/common"
)

func (s *UdpServer) sessionOwnerID() (string, error) {
	if s == nil {
		return "", errors.New("nil NHP server")
	}
	s.acSessionOwnerOnce.Do(func() {
		if common.ValidNHPSessionOwnerID(s.acSessionOwnerID) {
			return
		}
		s.acSessionOwnerID, s.acSessionOwnerErr = common.NewNHPSessionOwnerID()
	})
	if s.acSessionOwnerErr != nil {
		return "", s.acSessionOwnerErr
	}
	if !common.ValidNHPSessionOwnerID(s.acSessionOwnerID) {
		return "", errors.New("invalid AC session owner identity")
	}
	return s.acSessionOwnerID, nil
}
