package ac

import (
	"context"
	"errors"

	"github.com/OpenNHP/opennhp/nhp/log"
)

// flushLiveNHPSessionsForControlGap closes admission, tears down every indexed
// NHP session, waits for the scheduler's immediate-flush tick, then advances
// the boot-local generation. AOL cannot advertise the new generation until
// this method returns successfully.
func (a *UdpAC) flushLiveNHPSessionsForControlGap() error {
	if a == nil {
		return errors.New("nil AC")
	}
	a.sessionControlFlushMu.Lock()
	defer a.sessionControlFlushMu.Unlock()

	a.sessionFlushComplete.Store(false)
	a.sessionControlLeaseHeld.Store(false)
	stateDir := a.sessionControlStateDir
	if stateDir == "" {
		stateDir = ExeDirPath
	}
	nextGeneration, err := reserveGapSessionControlGeneration(stateDir, a.sessionFlushGeneration.Load())
	if err != nil {
		return errors.New("persist next session-control flush generation: " + err.Error())
	}
	a.sessionFlushGeneration.Store(nextGeneration)
	ctx, cancel := context.WithTimeout(context.Background(), bootEnumerationDeadline)
	closed, closeErr := a.closeAllNHPSessionsVerified(ctx)
	cancel()
	if closeErr != nil {
		return errors.New("session-control lease flush did not converge: " + closeErr.Error())
	}
	if a.sessionControlFlushBeforeGenerationFn != nil {
		a.sessionControlFlushBeforeGenerationFn()
	}
	a.sessionFlushComplete.Store(true)
	log.Info("AC session-control lease flush completed: closed=%d generation=%d", closed, nextGeneration)
	return nil
}
