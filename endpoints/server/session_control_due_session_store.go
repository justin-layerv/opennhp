package server

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

type sessionControlDueSessionCursor struct {
	CellID           string
	Shard            uint64
	DueThroughMillis int64
	State            string
	LastEvaluatedKey map[string]types.AttributeValue
}

type sessionControlDueSessionPage struct {
	Sessions []sessionControlSessionAuthority
	Next     *sessionControlDueSessionCursor
}

type sessionControlDueSessionStore interface {
	ListDueReservedSessionsPage(context.Context, string, uint64, int64,
		*sessionControlDueSessionCursor, int32) (*sessionControlDueSessionPage, error)
	ListDueClosingSessionsPage(context.Context, string, uint64, int64,
		*sessionControlDueSessionCursor, int32) (*sessionControlDueSessionPage, error)
}

var _ sessionControlDueSessionStore = (*dynamoSessionControlStore)(nil)

func sessionControlDueSessionShard(cellID string, shard uint64, state string) (string, error) {
	if !validSessionControlCellID(cellID) || shard >= sessionControlSessionDueShardCount ||
		(state != sessionControlSessionStateReserved && state != sessionControlSessionStateClosing) {
		return "", errors.New("invalid session-control due session shard")
	}
	return fmt.Sprintf("SESSION#%s#%s#%02d", state, cellID, shard), nil
}

func sessionControlSessionIDFromPK(pk string) (uint64, bool) {
	text := strings.TrimPrefix(pk, "SESSION#")
	if text == pk || len(text) != len(sessionControlSessionIDText(0)) {
		return 0, false
	}
	id, err := strconv.ParseUint(text, 10, 64)
	return id, err == nil && id != 0 && sessionControlSessionPK(id) == pk
}

func sessionControlDueSessionCursorPosition(key map[string]types.AttributeValue,
	dueShard string, dueThroughMillis int64,
) (string, bool) {
	pk, pkOK := key["pk"].(*types.AttributeValueMemberS)
	sk, skOK := key["sk"].(*types.AttributeValueMemberS)
	shard, shardOK := key["due_shard"].(*types.AttributeValueMemberS)
	sortKey, sortOK := key["due_sort"].(*types.AttributeValueMemberS)
	if !pkOK || !skOK || !shardOK || !sortOK || sk.Value != sessionControlSessionMetaSK ||
		shard.Value != dueShard || len(sortKey.Value) != 40 || sortKey.Value[19] != '#' {
		return "", false
	}
	sessionID, valid := sessionControlSessionIDFromPK(pk.Value)
	deadline, err := strconv.ParseInt(sortKey.Value[:19], 10, 64)
	if !valid || err != nil || sortKey.Value != sessionControlSessionIssuedText(deadline)+"#"+
		sessionControlSessionIDText(sessionID) {
		return "", false
	}
	if deadline <= 0 || deadline > dueThroughMillis {
		return "", false
	}
	return sortKey.Value + "#" + pk.Value, true
}

// ListDueReservedSessionsPage uses the eventual due index only as a liveness
// accelerator. Every hit is re-read from the strongly consistent base row and
// paired membership authority before it can trigger fail-closed recovery.
func (s *dynamoSessionControlStore) ListDueReservedSessionsPage(ctx context.Context,
	cellID string, shard uint64, dueThroughMillis int64, cursor *sessionControlDueSessionCursor,
	limit int32,
) (*sessionControlDueSessionPage, error) {
	return s.listDueSessionsPage(ctx, cellID, shard, dueThroughMillis, cursor, limit,
		sessionControlSessionStateReserved)
}

func (s *dynamoSessionControlStore) ListDueClosingSessionsPage(ctx context.Context,
	cellID string, shard uint64, dueThroughMillis int64, cursor *sessionControlDueSessionCursor,
	limit int32,
) (*sessionControlDueSessionPage, error) {
	return s.listDueSessionsPage(ctx, cellID, shard, dueThroughMillis, cursor, limit,
		sessionControlSessionStateClosing)
}

func (s *dynamoSessionControlStore) listDueSessionsPage(ctx context.Context,
	cellID string, shard uint64, dueThroughMillis int64, cursor *sessionControlDueSessionCursor,
	limit int32, expectedState string,
) (*sessionControlDueSessionPage, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if expectedState != sessionControlSessionStateReserved && expectedState != sessionControlSessionStateClosing {
		return nil, errors.New("invalid session-control due session state")
	}
	dueShard, err := sessionControlDueSessionShard(cellID, shard, expectedState)
	if err != nil || dueThroughMillis <= 0 {
		return nil, errors.New("invalid session-control due session scan")
	}
	var lastKey map[string]types.AttributeValue
	lastPosition := ""
	if cursor != nil {
		if cursor.CellID != cellID || cursor.Shard != shard ||
			cursor.DueThroughMillis != dueThroughMillis || cursor.State != expectedState ||
			len(cursor.LastEvaluatedKey) == 0 {
			return nil, errors.New("invalid session-control due session cursor")
		}
		var valid bool
		lastPosition, valid = sessionControlDueSessionCursorPosition(cursor.LastEvaluatedKey, dueShard, dueThroughMillis)
		if !valid {
			return nil, errors.New("invalid session-control due session cursor")
		}
		lastKey = cursor.LastEvaluatedKey
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	result, err := s.client.Query(opCtx, &dynamodb.QueryInput{
		TableName: aws.String(s.tableName), IndexName: aws.String(sessionControlDueIndexName),
		KeyConditionExpression: aws.String("due_shard = :shard AND due_sort <= :through"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":shard":   &types.AttributeValueMemberS{Value: dueShard},
			":through": &types.AttributeValueMemberS{Value: sessionControlSessionIssuedText(dueThroughMillis) + "#\uffff"},
		},
		ExclusiveStartKey: lastKey, Limit: aws.Int32(clampSessionControlPageLimit(limit)),
	})
	if err != nil {
		return nil, fmt.Errorf("session-control due session discovery: %w", err)
	}
	page := &sessionControlDueSessionPage{Sessions: make([]sessionControlSessionAuthority, 0, len(result.Items))}
	seen := make(map[uint64]struct{}, len(result.Items))
	for _, projected := range result.Items {
		pk, pkOK := projected["pk"].(*types.AttributeValueMemberS)
		sk, skOK := projected["sk"].(*types.AttributeValueMemberS)
		if !pkOK || !skOK || sk.Value != sessionControlSessionMetaSK {
			return nil, errSessionControlSessionCorrupt
		}
		sessionID, valid := sessionControlSessionIDFromPK(pk.Value)
		if !valid {
			return nil, errSessionControlSessionCorrupt
		}
		if _, duplicate := seen[sessionID]; duplicate {
			return nil, errSessionControlSessionCorrupt
		}
		seen[sessionID] = struct{}{}
		current, readErr := s.getSessionItem(opCtx, sessionID)
		if errors.Is(readErr, errSessionControlSessionNotFound) {
			continue // stale KEYS_ONLY projection
		}
		if readErr != nil {
			return nil, readErr
		}
		if current.State != expectedState {
			continue // another state transition changed or removed due authority
		}
		classified, classifyErr := s.classifyReservation(opCtx, current.Candidate)
		if classifyErr != nil {
			return nil, classifyErr
		}
		if classified.State != expectedState {
			continue
		}
		if classified.Candidate.CellID != cellID ||
			sessionControlSessionAuthorityDueAt(*classified) > dueThroughMillis ||
			sessionControlSessionAuthorityDueShard(*classified) != dueShard {
			return nil, errSessionControlSessionCorrupt
		}
		page.Sessions = append(page.Sessions, *classified)
	}
	if len(result.LastEvaluatedKey) != 0 {
		nextPosition, valid := sessionControlDueSessionCursorPosition(result.LastEvaluatedKey, dueShard, dueThroughMillis)
		if !valid || (lastPosition != "" && nextPosition <= lastPosition) {
			return nil, errSessionControlSessionCorrupt
		}
		page.Next = &sessionControlDueSessionCursor{
			CellID: cellID, Shard: shard, DueThroughMillis: dueThroughMillis, State: expectedState,
			LastEvaluatedKey: result.LastEvaluatedKey,
		}
	}
	return page, nil
}
