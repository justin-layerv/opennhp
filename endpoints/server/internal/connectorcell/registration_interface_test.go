package connectorcell_test

import (
	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorauthority"
	"github.com/OpenNHP/opennhp/endpoints/server/internal/connectorcell"
)

var _ connectorcell.RegistrationAuthority = (*connectorauthority.CellClient)(nil)
var _ connectorcell.RegistrationAuthority = (*connectorauthority.RegistrationCellClient)(nil)
