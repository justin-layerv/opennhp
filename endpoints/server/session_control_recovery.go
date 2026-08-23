package server

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/OpenNHP/opennhp/nhp/log"
)

const (
	sessionControlRecoveryInterval = time.Second
	// One durable row per shard per sweep prevents a hot partition from filling
	// every worker slot before the remaining shards are even queried.
	sessionControlRecoveryPageSize   = int32(1)
	sessionControlRecoveryWorkers    = 8
	sessionControlRecoveryQueueDepth = 256
)

type sessionControlRecoveryRuntime struct {
	mu                sync.Mutex
	cancel            context.CancelFunc
	wg                sync.WaitGroup
	cursors           [sessionControlSessionDueShardCount]*sessionControlDueSessionCursor
	dueThrough        [sessionControlSessionDueShardCount]int64
	closingCursors    [sessionControlSessionDueShardCount]*sessionControlDueSessionCursor
	closingDueThrough [sessionControlSessionDueShardCount]int64
	sessionQueue      chan sessionControlSessionAuthority
	sessionQueued     map[string]struct{}
	taskCursors       [sessionControlCloseDueShardCount]*sessionControlCloseTaskDueCursor
	taskDueThrough    [sessionControlCloseDueShardCount]int64
	taskQueue         chan sessionControlCloseTask
	taskQueued        map[string]struct{}
}

func sessionControlRecoverySessionKey(session sessionControlSessionAuthority) string {
	return session.Candidate.CellID + "#" + sessionControlSessionIDText(session.Candidate.SessionID)
}

func (s *UdpServer) validateSessionControlRecoveryCapabilities() error {
	if !s.sessionControlAuthorityRequired() {
		return nil
	}
	if _, ok := s.sessionControlStore.(sessionControlDueSessionStore); !ok {
		return errors.New("session-control due-session recovery capability is unavailable")
	}
	if _, ok := s.sessionControlStore.(sessionControlOwnerTaskDeliveryStore); !ok {
		return errors.New("session-control task-delivery recovery capability is unavailable")
	}
	if _, ok := s.sessionControlStore.(sessionControlCloseLifecycleStore); !ok {
		return errors.New("session-control close-lifecycle recovery capability is unavailable")
	}
	return nil
}

func (s *UdpServer) startSessionControlRecovery() error {
	if err := s.validateSessionControlRecoveryCapabilities(); err != nil {
		return err
	}
	if !s.sessionControlAuthorityRequired() {
		return nil
	}
	dueStore, ok := s.sessionControlStore.(sessionControlDueSessionStore)
	if !ok {
		return errors.New("session-control due-session recovery capability is unavailable")
	}
	taskStore, ok := s.sessionControlStore.(sessionControlOwnerTaskDeliveryStore)
	if !ok {
		return errors.New("session-control task-delivery recovery capability is unavailable")
	}
	lifecycleStore, ok := s.sessionControlStore.(sessionControlCloseLifecycleStore)
	if !ok {
		return errors.New("session-control close-lifecycle recovery capability is unavailable")
	}
	s.sessionControlRecovery.mu.Lock()
	defer s.sessionControlRecovery.mu.Unlock()
	if s.sessionControlRecovery.cancel != nil {
		return errors.New("session-control recovery is already running")
	}
	//nolint:gosec // G118: cancel is retained below and invoked by stopSessionControlRecovery.
	ctx, cancel := context.WithCancel(s.LifecycleCtx())
	s.sessionControlRecovery.cancel = cancel
	s.sessionControlRecovery.sessionQueue = make(chan sessionControlSessionAuthority, sessionControlRecoveryQueueDepth)
	s.sessionControlRecovery.sessionQueued = make(map[string]struct{})
	s.sessionControlRecovery.taskQueue = make(chan sessionControlCloseTask, sessionControlRecoveryQueueDepth)
	s.sessionControlRecovery.taskQueued = make(map[string]struct{})
	s.sessionControlRecovery.wg.Add(1 + 2*sessionControlRecoveryWorkers)
	go func() {
		defer s.sessionControlRecovery.wg.Done()
		s.runSessionControlRecovery(ctx, dueStore, taskStore)
	}()
	for range sessionControlRecoveryWorkers {
		go func() {
			defer s.sessionControlRecovery.wg.Done()
			s.runSessionControlSessionWorker(ctx, lifecycleStore)
		}()
		go func() {
			defer s.sessionControlRecovery.wg.Done()
			s.runSessionControlTaskWorker(ctx, taskStore)
		}()
	}
	return nil
}

func (s *UdpServer) stopSessionControlRecovery() {
	s.sessionControlRecovery.mu.Lock()
	cancel := s.sessionControlRecovery.cancel
	s.sessionControlRecovery.cancel = nil
	s.sessionControlRecovery.mu.Unlock()
	if cancel != nil {
		cancel()
		s.sessionControlRecovery.wg.Wait()
	}
	s.sessionControlRecovery.mu.Lock()
	s.sessionControlRecovery.sessionQueue = nil
	s.sessionControlRecovery.sessionQueued = nil
	s.sessionControlRecovery.taskQueue = nil
	s.sessionControlRecovery.taskQueued = nil
	s.sessionControlRecovery.mu.Unlock()
}

func (s *UdpServer) runSessionControlRecovery(ctx context.Context, dueStore sessionControlDueSessionStore,
	taskStore sessionControlOwnerTaskDeliveryStore,
) {
	ticker := time.NewTicker(sessionControlRecoveryInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
		}
		s.recoverDueReservedSessions(ctx, dueStore, time.Now().UnixMilli())
		s.recoverDueClosingSessions(ctx, dueStore, time.Now().UnixMilli())
		s.recoverDueExactCloseTasks(ctx, taskStore, time.Now().UnixMilli())
	}
}

func (s *UdpServer) runSessionControlSessionWorker(ctx context.Context,
	lifecycleStore sessionControlCloseLifecycleStore,
) {
	for {
		s.sessionControlRecovery.mu.Lock()
		sessionQueue := s.sessionControlRecovery.sessionQueue
		s.sessionControlRecovery.mu.Unlock()
		if sessionQueue == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case session := <-sessionQueue:
			key := sessionControlRecoverySessionKey(session)
			var err error
			switch session.State {
			case sessionControlSessionStateReserved:
				err = s.ensureDurableExactSessionClose(ctx, session.Candidate, session.RetainUntilMillis)
			case sessionControlSessionStateClosing:
				operationCtx, operationCancel := context.WithTimeout(ctx, DynamoDBOperationTimeout)
				err = s.advanceDurableExactCloseLifecycle(operationCtx, lifecycleStore, session)
				operationCancel()
			default:
				err = errSessionControlSessionCorrupt
			}
			s.sessionControlRecovery.mu.Lock()
			delete(s.sessionControlRecovery.sessionQueued, key)
			s.sessionControlRecovery.mu.Unlock()
			if err != nil && !errors.Is(err, errSessionControlSessionFenceDenied) &&
				!sessionControlLifecycleRetryable(err) && ctx.Err() == nil {
				log.Error("session-control recovery could not close session %d: %v", session.Candidate.SessionID, err)
			}
		}
	}
}

func (s *UdpServer) runSessionControlTaskWorker(ctx context.Context,
	taskStore sessionControlOwnerTaskDeliveryStore,
) {
	for {
		s.sessionControlRecovery.mu.Lock()
		taskQueue := s.sessionControlRecovery.taskQueue
		s.sessionControlRecovery.mu.Unlock()
		if taskQueue == nil {
			return
		}
		select {
		case <-ctx.Done():
			return
		case task := <-taskQueue:
			key := sessionControlRecoveryTaskKey(task)
			deliveryCtx, deliveryCancel := context.WithTimeout(ctx, DynamoDBOperationTimeout)
			err := s.deliverDueExactCloseTask(deliveryCtx, taskStore, task)
			deliveryCancel()
			s.sessionControlRecovery.mu.Lock()
			delete(s.sessionControlRecovery.taskQueued, key)
			s.sessionControlRecovery.mu.Unlock()
			if err != nil && !sessionControlTaskDeliveryIgnorable(err) && ctx.Err() == nil {
				log.Error("session-control recovery could not deliver close task %s: %v", task.EventID, err)
			}
		}
	}
}

func (s *UdpServer) enqueueDueReservedSession(ctx context.Context, session sessionControlSessionAuthority) {
	key := sessionControlRecoverySessionKey(session)
	s.sessionControlRecovery.mu.Lock()
	queue := s.sessionControlRecovery.sessionQueue
	if queue == nil {
		s.sessionControlRecovery.mu.Unlock()
		// Direct unit/model invocation deliberately remains synchronous. The
		// production runtime always initializes the bounded queue in Start.
		if err := s.ensureDurableExactSessionClose(ctx, session.Candidate, session.RetainUntilMillis); err != nil &&
			!errors.Is(err, errSessionControlSessionFenceDenied) {
			log.Error("session-control recovery could not close session %d: %v", session.Candidate.SessionID, err)
		}
		return
	}
	if _, exists := s.sessionControlRecovery.sessionQueued[key]; exists {
		s.sessionControlRecovery.mu.Unlock()
		return
	}
	s.sessionControlRecovery.sessionQueued[key] = struct{}{}
	select {
	case queue <- session:
		s.sessionControlRecovery.mu.Unlock()
	case <-ctx.Done():
		delete(s.sessionControlRecovery.sessionQueued, key)
		s.sessionControlRecovery.mu.Unlock()
	default:
		delete(s.sessionControlRecovery.sessionQueued, key)
		s.sessionControlRecovery.mu.Unlock()
	}
}

func (s *UdpServer) enqueueDueExactCloseTask(ctx context.Context, task sessionControlCloseTask) {
	key := sessionControlRecoveryTaskKey(task)
	s.sessionControlRecovery.mu.Lock()
	queue := s.sessionControlRecovery.taskQueue
	if queue == nil {
		s.sessionControlRecovery.mu.Unlock()
		return
	}
	if _, exists := s.sessionControlRecovery.taskQueued[key]; exists {
		s.sessionControlRecovery.mu.Unlock()
		return
	}
	s.sessionControlRecovery.taskQueued[key] = struct{}{}
	select {
	case queue <- task:
		s.sessionControlRecovery.mu.Unlock()
	case <-ctx.Done():
		delete(s.sessionControlRecovery.taskQueued, key)
		s.sessionControlRecovery.mu.Unlock()
	default:
		delete(s.sessionControlRecovery.taskQueued, key)
		s.sessionControlRecovery.mu.Unlock()
	}
}

func (s *UdpServer) recoverDueExactCloseTasks(ctx context.Context,
	store sessionControlOwnerTaskDeliveryStore, dueThroughMillis int64,
) {
	for shard := uint64(0); shard < sessionControlCloseDueShardCount; shard++ {
		if ctx.Err() != nil {
			return
		}
		through := s.sessionControlRecovery.taskDueThrough[shard]
		cursor := s.sessionControlRecovery.taskCursors[shard]
		if cursor == nil {
			through = dueThroughMillis
			s.sessionControlRecovery.taskDueThrough[shard] = through
		}
		page, err := store.ListDueExactCloseTasksPage(ctx, s.sessionControlCellID, shard,
			through, cursor, sessionControlRecoveryPageSize)
		if err != nil {
			if ctx.Err() == nil {
				log.Error("session-control close-task discovery shard %d failed: %v", shard, err)
			}
			continue
		}
		s.sessionControlRecovery.taskCursors[shard] = page.Next
		if page.Next == nil {
			s.sessionControlRecovery.taskDueThrough[shard] = 0
		}
		for _, task := range page.Tasks {
			s.enqueueDueExactCloseTask(ctx, task)
		}
	}
}

func (s *UdpServer) recoverDueReservedSessions(ctx context.Context,
	dueStore sessionControlDueSessionStore, dueThroughMillis int64,
) {
	for shard := uint64(0); shard < sessionControlSessionDueShardCount; shard++ {
		if ctx.Err() != nil {
			return
		}
		through := s.sessionControlRecovery.dueThrough[shard]
		cursor := s.sessionControlRecovery.cursors[shard]
		if cursor == nil {
			through = dueThroughMillis
			s.sessionControlRecovery.dueThrough[shard] = through
		}
		page, err := dueStore.ListDueReservedSessionsPage(ctx, s.sessionControlCellID, shard,
			through, cursor, sessionControlRecoveryPageSize)
		if err != nil {
			if ctx.Err() == nil {
				log.Error("session-control due-session recovery shard %d failed: %v", shard, err)
			}
			continue
		}
		s.sessionControlRecovery.cursors[shard] = page.Next
		if page.Next == nil {
			s.sessionControlRecovery.dueThrough[shard] = 0
		}
		for _, session := range page.Sessions {
			if ctx.Err() != nil {
				return
			}
			s.enqueueDueReservedSession(ctx, session)
		}
		// Rotate shards rather than draining an unbounded hot partition in one
		// pass. The next one-second sweep resumes discovery; due rows are durable.
	}
}

func (s *UdpServer) recoverDueClosingSessions(ctx context.Context,
	dueStore sessionControlDueSessionStore, dueThroughMillis int64,
) {
	for shard := uint64(0); shard < sessionControlSessionDueShardCount; shard++ {
		if ctx.Err() != nil {
			return
		}
		through := s.sessionControlRecovery.closingDueThrough[shard]
		cursor := s.sessionControlRecovery.closingCursors[shard]
		if cursor == nil {
			through = dueThroughMillis
			s.sessionControlRecovery.closingDueThrough[shard] = through
		}
		page, err := dueStore.ListDueClosingSessionsPage(ctx, s.sessionControlCellID, shard,
			through, cursor, sessionControlRecoveryPageSize)
		if err != nil {
			if ctx.Err() == nil {
				log.Error("session-control closing-session recovery shard %d failed: %v", shard, err)
			}
			continue
		}
		s.sessionControlRecovery.closingCursors[shard] = page.Next
		if page.Next == nil {
			s.sessionControlRecovery.closingDueThrough[shard] = 0
		}
		for _, session := range page.Sessions {
			s.enqueueDueReservedSession(ctx, session)
		}
	}
}
