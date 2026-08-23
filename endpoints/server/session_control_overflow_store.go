package server

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/feature/dynamodb/attributevalue"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
	"github.com/aws/aws-sdk-go-v2/service/dynamodb/types"
)

const (
	sessionControlDueIndexName          = "due-index"
	sessionControlOverflowOrderKind     = "overflow_close_order"
	sessionControlOverflowOrderSchema   = uint64(1)
	sessionControlOverflowOrderPKPrefix = "OVERFLOWORDER#"
	sessionControlOverflowOrderSKPrefix = "ORDER#"
)

type sessionControlOverflowOrderRow struct {
	PK                       string                     `dynamodbav:"pk"`
	SK                       string                     `dynamodbav:"sk"`
	Kind                     string                     `dynamodbav:"kind"`
	SchemaVersion            uint64                     `dynamodbav:"schema_version"`
	CellID                   string                     `dynamodbav:"cell_id"`
	EventID                  string                     `dynamodbav:"event_id"`
	PreparedDirectoryVersion uint64                     `dynamodbav:"prepared_directory_version"`
	CreatedAtMillis          int64                      `dynamodbav:"created_at_ms"`
	WorkDigest               string                     `dynamodbav:"work_digest"`
	Work                     sessionControlCloseWorkRow `dynamodbav:"work"`
}

type sessionControlOverflowOrder struct {
	Work       sessionControlCloseWork
	WorkDigest string
}

func sessionControlOverflowOrderPK(cellID string) string {
	digest := sha256.Sum256([]byte("v1\x00" + cellID))
	return sessionControlOverflowOrderPKPrefix + hex.EncodeToString(digest[:])
}

func sessionControlOverflowOrderSK(work sessionControlCloseWork) string {
	return fmt.Sprintf("%s%020d#%020d#%s", sessionControlOverflowOrderSKPrefix,
		work.PreparedDirectoryVersion, work.CreatedAtMillis, work.EventID)
}

func sessionControlOverflowOrderKey(work sessionControlCloseWork) map[string]types.AttributeValue {
	return map[string]types.AttributeValue{
		"pk": &types.AttributeValueMemberS{Value: sessionControlOverflowOrderPK(work.CellID)},
		"sk": &types.AttributeValueMemberS{Value: sessionControlOverflowOrderSK(work)},
	}
}

func sessionControlOverflowOrderDigest(work sessionControlCloseWork) (string, error) {
	return sessionControlMaterializationDigest(struct {
		Version uint64
		Work    sessionControlCloseWork
	}{1, work})
}

func sessionControlOverflowOrderToRow(order sessionControlOverflowOrder) (sessionControlOverflowOrderRow, error) {
	if order.Work.Mode != sessionControlCloseWorkModeOverflow ||
		order.Work.State != sessionControlCloseWorkStatePending || validateSessionControlCloseWork(order.Work) != nil {
		return sessionControlOverflowOrderRow{}, errSessionControlCloseCorrupt
	}
	digest, err := sessionControlOverflowOrderDigest(order.Work)
	if err != nil || digest != order.WorkDigest {
		return sessionControlOverflowOrderRow{}, errSessionControlCloseCorrupt
	}
	work, err := sessionControlCloseWorkToRow(order.Work)
	if err != nil {
		return sessionControlOverflowOrderRow{}, err
	}
	return sessionControlOverflowOrderRow{PK: sessionControlOverflowOrderPK(order.Work.CellID),
		SK: sessionControlOverflowOrderSK(order.Work), Kind: sessionControlOverflowOrderKind,
		SchemaVersion: sessionControlOverflowOrderSchema, CellID: order.Work.CellID,
		EventID: order.Work.EventID, PreparedDirectoryVersion: order.Work.PreparedDirectoryVersion,
		CreatedAtMillis: order.Work.CreatedAtMillis, WorkDigest: order.WorkDigest, Work: work}, nil
}

func sessionControlOverflowOrderFromItem(item map[string]types.AttributeValue,
	cellID string) (sessionControlOverflowOrder, error) {
	if len(item) == 0 {
		return sessionControlOverflowOrder{}, errSessionControlCloseConflict
	}
	if _, hasTTL := item["ttl"]; hasTTL {
		return sessionControlOverflowOrder{}, errSessionControlCloseCorrupt
	}
	for _, name := range []string{"prepared_directory_version", "created_at_ms", "schema_version"} {
		if _, ok := item[name].(*types.AttributeValueMemberN); !ok {
			return sessionControlOverflowOrder{}, errSessionControlCloseCorrupt
		}
	}
	nested, ok := item["work"].(*types.AttributeValueMemberM)
	if !ok {
		return sessionControlOverflowOrder{}, errSessionControlCloseCorrupt
	}
	var row sessionControlOverflowOrderRow
	if err := attributevalue.UnmarshalMap(item, &row); err != nil {
		return sessionControlOverflowOrder{}, errSessionControlCloseCorrupt
	}
	work, err := sessionControlCloseWorkFromItem(nested.Value, true, cellID, row.EventID)
	if err != nil {
		return sessionControlOverflowOrder{}, errSessionControlCloseCorrupt
	}
	order := sessionControlOverflowOrder{Work: work, WorkDigest: row.WorkDigest}
	if row.PK != sessionControlOverflowOrderPK(cellID) || row.SK != sessionControlOverflowOrderSK(work) ||
		row.Kind != sessionControlOverflowOrderKind || row.SchemaVersion != sessionControlOverflowOrderSchema ||
		row.CellID != cellID || row.EventID != work.EventID ||
		row.PreparedDirectoryVersion != work.PreparedDirectoryVersion ||
		row.CreatedAtMillis != work.CreatedAtMillis {
		return sessionControlOverflowOrder{}, errSessionControlCloseCorrupt
	}
	digest, digestErr := sessionControlOverflowOrderDigest(work)
	if digestErr != nil || digest != order.WorkDigest {
		return sessionControlOverflowOrder{}, errSessionControlCloseCorrupt
	}
	return order, nil
}

func sessionControlOverflowOrderPut(tableName string,
	work sessionControlCloseWork) (types.TransactWriteItem, error) {
	digest, err := sessionControlOverflowOrderDigest(work)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	row, err := sessionControlOverflowOrderToRow(sessionControlOverflowOrder{Work: work, WorkDigest: digest})
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	return types.TransactWriteItem{Put: &types.Put{TableName: aws.String(tableName), Item: item,
		ConditionExpression: aws.String("attribute_not_exists(pk) AND attribute_not_exists(sk)")}}, nil
}

func sessionControlOverflowOrderCondition(tableName string,
	order sessionControlOverflowOrder) (types.TransactWriteItem, error) {
	row, err := sessionControlOverflowOrderToRow(order)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	item, err := attributevalue.MarshalMap(row)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	condition, names, values := sessionControlExactItemCondition(item)
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{TableName: aws.String(tableName),
		Key: sessionControlOverflowOrderKey(order.Work), ConditionExpression: aws.String(condition),
		ExpressionAttributeNames: names, ExpressionAttributeValues: values}}, nil
}

func sessionControlOverflowOrderDelete(tableName string,
	order sessionControlOverflowOrder) (types.TransactWriteItem, error) {
	condition, err := sessionControlOverflowOrderCondition(tableName, order)
	if err != nil {
		return types.TransactWriteItem{}, err
	}
	check := condition.ConditionCheck
	return types.TransactWriteItem{Delete: &types.Delete{TableName: aws.String(tableName), Key: check.Key,
		ConditionExpression: check.ConditionExpression, ExpressionAttributeNames: check.ExpressionAttributeNames,
		ExpressionAttributeValues: check.ExpressionAttributeValues}}, nil
}

func (s *dynamoSessionControlStore) getOverflowOrder(ctx context.Context,
	work sessionControlCloseWork) (*sessionControlOverflowOrder, error) {
	result, err := s.client.GetItem(ctx, &dynamodb.GetItemInput{TableName: aws.String(s.tableName),
		ConsistentRead: aws.Bool(true), Key: sessionControlOverflowOrderKey(work)})
	if err != nil {
		return nil, fmt.Errorf("session-control overflow order strong read: %w", err)
	}
	order, err := sessionControlOverflowOrderFromItem(result.Item, work.CellID)
	if err != nil {
		return nil, err
	}
	if order.Work != work {
		return nil, errSessionControlCloseCorrupt
	}
	return &order, nil
}

type sessionControlOverflowLeader struct {
	Directory sessionControlFenceDirectory
	Work      sessionControlCloseWork
}

type sessionControlOverflowScanCursor struct {
	Directory sessionControlFenceDirectory
	LastKey   map[string]types.AttributeValue
	Seen      uint64
}

type sessionControlOverflowClosePage struct {
	Directory sessionControlFenceDirectory
	Work      []sessionControlCloseWork
	Next      *sessionControlOverflowScanCursor
}

type sessionControlDueScanCursor struct {
	LastKey map[string]types.AttributeValue
}

type sessionControlDueClosePage struct {
	Work []sessionControlCloseWork
	Next *sessionControlDueScanCursor
}

func sessionControlOverflowHeaderCondition(work sessionControlCloseWork) types.TransactWriteItem {
	values := map[string]types.AttributeValue{
		":kind":            &types.AttributeValueMemberS{Value: sessionControlOverflowCloseKind},
		":schema":          &types.AttributeValueMemberN{Value: fmt.Sprint(sessionControlCloseWorkSchema)},
		":cell":            &types.AttributeValueMemberS{Value: work.CellID},
		":event":           &types.AttributeValueMemberS{Value: work.EventID},
		":selector_digest": &types.AttributeValueMemberS{Value: work.SelectorDigest},
		":mode":            &types.AttributeValueMemberS{Value: sessionControlCloseWorkModeOverflow},
		":state":           &types.AttributeValueMemberS{Value: sessionControlCloseWorkStatePending},
		":prepared":        &types.AttributeValueMemberN{Value: fmt.Sprint(work.PreparedDirectoryVersion)},
		":session_version": &types.AttributeValueMemberN{Value: fmt.Sprint(work.SessionVersion)},
		":target_count":    &types.AttributeValueMemberN{Value: fmt.Sprint(work.ExpectedTargetCount)},
		":created":         &types.AttributeValueMemberN{Value: fmt.Sprint(work.CreatedAtMillis)},
		":updated":         &types.AttributeValueMemberN{Value: fmt.Sprint(work.UpdatedAtMillis)},
		":due":             &types.AttributeValueMemberN{Value: fmt.Sprint(work.DueAtMillis)},
		":due_shard":       &types.AttributeValueMemberS{Value: sessionControlCloseDueShard(work)},
		":due_sort":        &types.AttributeValueMemberS{Value: sessionControlCloseDueSort(work)},
	}
	condition := "kind = :kind AND schema_version = :schema AND cell_id = :cell AND event_id = :event AND selector_digest = :selector_digest AND mode = :mode AND #state = :state AND prepared_directory_version = :prepared AND session_version = :session_version AND expected_target_count = :target_count AND created_at_ms = :created AND updated_at_ms = :updated AND due_at_ms = :due AND due_shard = :due_shard AND due_sort = :due_sort AND attribute_not_exists(#ttl)"
	return types.TransactWriteItem{ConditionCheck: &types.ConditionCheck{
		Key:                 sessionControlOverflowCloseKey(work.CellID, work.EventID),
		ConditionExpression: aws.String(condition), ExpressionAttributeNames: map[string]string{"#state": "state", "#ttl": "ttl"},
		ExpressionAttributeValues: values,
	}}
}

// readStableOverflowOrder reads the bounded oldest prefix under an exact
// CONTROL seqlock. Each immutable ORDER row embeds the complete work identity
// and is paired with a strong base-header read.
func (s *dynamoSessionControlStore) readStableOverflowOrder(ctx context.Context,
	cellID string, limit int32) (sessionControlFenceDirectory, []sessionControlOverflowOrder, error) {
	if limit <= 0 || limit > 2 {
		return sessionControlFenceDirectory{}, nil, errSessionControlCloseCorrupt
	}
	for range sessionControlFenceAttempts {
		before, err := s.getFenceDirectory(ctx, cellID)
		if err != nil {
			return sessionControlFenceDirectory{}, nil, err
		}
		result, queryErr := s.client.Query(ctx, &dynamodb.QueryInput{
			TableName: aws.String(s.tableName), ConsistentRead: aws.Bool(true),
			KeyConditionExpression: aws.String("pk = :pk AND begins_with(sk, :prefix)"),
			ExpressionAttributeValues: map[string]types.AttributeValue{
				":pk":     &types.AttributeValueMemberS{Value: sessionControlOverflowOrderPK(cellID)},
				":prefix": &types.AttributeValueMemberS{Value: sessionControlOverflowOrderSKPrefix},
			},
			Limit: aws.Int32(limit),
		})
		if queryErr != nil {
			return sessionControlFenceDirectory{}, nil,
				fmt.Errorf("session-control overflow order strong query: %w", queryErr)
		}
		orders := make([]sessionControlOverflowOrder, 0, len(result.Items))
		for _, item := range result.Items {
			order, decodeErr := sessionControlOverflowOrderFromItem(item, cellID)
			if decodeErr != nil {
				return sessionControlFenceDirectory{}, nil, decodeErr
			}
			header, headerErr := s.getCloseWork(ctx, cellID, order.Work.EventID, true)
			if headerErr != nil {
				return sessionControlFenceDirectory{}, nil, headerErr
			}
			if *header != order.Work {
				return sessionControlFenceDirectory{}, nil, errSessionControlCloseCorrupt
			}
			orders = append(orders, order)
		}
		after, err := s.getFenceDirectory(ctx, cellID)
		if err != nil {
			return sessionControlFenceDirectory{}, nil, err
		}
		if *before != *after {
			continue
		}
		if after.AdmissionBlocked != (after.OverflowCloseCount > 0) ||
			(after.OverflowCloseCount == 0 && len(orders) != 0) ||
			(after.OverflowCloseCount > 0 && len(orders) == 0) ||
			(after.OverflowCloseCount == 1 && len(orders) != 1) ||
			(after.OverflowCloseCount > 1 && limit == 2 && len(orders) != 2) {
			return sessionControlFenceDirectory{}, nil, errSessionControlCloseCorrupt
		}
		return *after, orders, nil
	}
	return sessionControlFenceDirectory{}, nil, errSessionControlCloseConflict
}

// SelectOldestOverflowCloseLeader installs the one deterministic per-cell
// scheduling authority after a complete strong partition proof. Capacity does
// not gate selection: only later promotion needs an ACTIVE slot.
func (s *dynamoSessionControlStore) SelectOldestOverflowCloseLeader(ctx context.Context,
	cellID string) (*sessionControlOverflowLeader, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlCellID(cellID) {
		return nil, errors.New("invalid session-control overflow leader")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	for range sessionControlFenceAttempts {
		directory, orders, err := s.readStableOverflowOrder(opCtx, cellID, 1)
		if err != nil {
			return nil, err
		}
		if len(orders) == 0 {
			return nil, errSessionControlCloseConflict
		}
		oldest := orders[0].Work
		if directory.OverflowLeaderEventID != "" {
			if directory.OverflowLeaderEventID != oldest.EventID ||
				directory.OverflowLeaderPreparedDirectoryVersion != oldest.PreparedDirectoryVersion {
				return nil, errSessionControlCloseCorrupt
			}
			return &sessionControlOverflowLeader{Directory: directory, Work: oldest}, nil
		}
		if oldest.PreparedDirectoryVersion > directory.Version || directory.Version >= ^uint64(0)-1 {
			return nil, errSessionControlCloseCorrupt
		}
		next := directory
		next.Version++
		next.OverflowLeaderEventID = oldest.EventID
		next.OverflowLeaderPreparedDirectoryVersion = oldest.PreparedDirectoryVersion
		next.OverflowLeaderSelectedDirectoryVersion = next.Version
		if oldest.UpdatedAtMillis > next.UpdatedAtMillis {
			next.UpdatedAtMillis = oldest.UpdatedAtMillis
		}
		if err := validateSessionControlFenceDirectory(next); err != nil {
			return nil, err
		}
		values := sessionControlFenceDirectoryConditionValues(directory)
		values[":leader_event"] = &types.AttributeValueMemberS{Value: next.OverflowLeaderEventID}
		values[":leader_prepared"] = &types.AttributeValueMemberN{Value: fmt.Sprint(next.OverflowLeaderPreparedDirectoryVersion)}
		values[":leader_selected"] = &types.AttributeValueMemberN{Value: fmt.Sprint(next.OverflowLeaderSelectedDirectoryVersion)}
		values[":updated_at"] = &types.AttributeValueMemberN{Value: fmt.Sprint(next.UpdatedAtMillis)}
		directoryWrite := types.TransactWriteItem{Update: &types.Update{
			TableName: aws.String(s.tableName), Key: sessionControlFenceDirectoryKey(cellID),
			UpdateExpression:         aws.String("SET #version = :next_version, overflow_leader_event_id = :leader_event, overflow_leader_prepared_directory_version = :leader_prepared, overflow_leader_selected_directory_version = :leader_selected, updated_at_ms = :updated_at"),
			ConditionExpression:      aws.String(sessionControlFenceDirectoryCondition()),
			ExpressionAttributeNames: map[string]string{"#version": "version", "#ttl": "ttl"}, ExpressionAttributeValues: values,
		}}
		headerCheck := sessionControlOverflowHeaderCondition(oldest)
		headerCheck.ConditionCheck.TableName = aws.String(s.tableName)
		orderCheck, err := sessionControlOverflowOrderCondition(s.tableName, orders[0])
		if err != nil {
			return nil, err
		}
		_, writeErr := s.client.TransactWriteItems(opCtx, &dynamodb.TransactWriteItemsInput{
			ClientRequestToken: sessionControlSessionToken("ol", cellID, oldest.EventID, oldest.PreparedDirectoryVersion,
				directory.Version, directory.ActiveFenceCount, directory.OverflowCloseCount),
			TransactItems: []types.TransactWriteItem{directoryWrite, orderCheck, headerCheck},
		})
		if writeErr == nil {
			return &sessionControlOverflowLeader{Directory: next, Work: oldest}, nil
		}
		var canceled *types.TransactionCanceledException
		if errors.As(writeErr, &canceled) {
			continue
		}
		resultCtx, resultCancel := s.sessionResultContext(ctx)
		resultDirectory, resultOrders, resultErr := s.readStableOverflowOrder(resultCtx, cellID, 1)
		resultCancel()
		if resultErr == nil && len(resultOrders) > 0 && resultDirectory.OverflowLeaderEventID == oldest.EventID &&
			resultDirectory.OverflowLeaderPreparedDirectoryVersion == oldest.PreparedDirectoryVersion &&
			resultOrders[0].Work == oldest {
			return &sessionControlOverflowLeader{Directory: resultDirectory, Work: oldest}, nil
		}
		return nil, fmt.Errorf("select session-control overflow leader: %w", writeErr)
	}
	return nil, errSessionControlCloseConflict
}

func clampSessionControlPageLimit(limit int32) int32 {
	if limit <= 0 || limit > sessionControlOverflowCloseQueryLimit {
		return sessionControlOverflowCloseQueryLimit
	}
	return limit
}

// ListOverflowCloseWorkPage is a bounded strong scan. A cursor is valid only
// for its exact directory authority. Terminal pages prove physical row parity;
// nonterminal pages preserve the cumulative seen count for the next call.
func (s *dynamoSessionControlStore) ListOverflowCloseWorkPage(ctx context.Context, cellID string,
	cursor *sessionControlOverflowScanCursor, limit int32) (*sessionControlOverflowClosePage, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	if !validSessionControlCellID(cellID) {
		return nil, errors.New("invalid session-control overflow cell id")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	before, err := s.getFenceDirectory(opCtx, cellID)
	if err != nil {
		return nil, err
	}
	var lastKey map[string]types.AttributeValue
	var seen uint64
	if cursor != nil {
		if cursor.Directory != *before || cursor.Seen > before.OverflowCloseCount || len(cursor.LastKey) == 0 {
			return nil, errSessionControlCloseConflict
		}
		lastKey = cursor.LastKey
		seen = cursor.Seen
	}
	result, err := s.client.Query(opCtx, &dynamodb.QueryInput{
		TableName: aws.String(s.tableName), ConsistentRead: aws.Bool(true),
		KeyConditionExpression: aws.String("pk = :pk"),
		ExpressionAttributeValues: map[string]types.AttributeValue{
			":pk": &types.AttributeValueMemberS{Value: sessionControlOverflowClosePK(cellID)},
		},
		ExclusiveStartKey: lastKey, Limit: aws.Int32(clampSessionControlPageLimit(limit)),
	})
	if err != nil {
		return nil, fmt.Errorf("session-control overflow close strong page: %w", err)
	}
	if uint64(len(result.Items)) > ^uint64(0)-seen {
		return nil, errSessionControlCloseCorrupt
	}
	seen += uint64(len(result.Items))
	work := make([]sessionControlCloseWork, 0, len(result.Items))
	for _, item := range result.Items {
		event, ok := item["event_id"].(*types.AttributeValueMemberS)
		if !ok || !validSessionControlFenceEventID(event.Value) {
			return nil, errSessionControlCloseCorrupt
		}
		decoded, decodeErr := sessionControlCloseWorkFromItem(item, true, cellID, event.Value)
		if decodeErr != nil {
			return nil, decodeErr
		}
		work = append(work, decoded)
	}
	after, err := s.getFenceDirectory(opCtx, cellID)
	if err != nil {
		return nil, err
	}
	if *before != *after || seen > after.OverflowCloseCount {
		return nil, errSessionControlCloseConflict
	}
	page := &sessionControlOverflowClosePage{Directory: *after, Work: work}
	if len(result.LastEvaluatedKey) == 0 {
		if seen != after.OverflowCloseCount || after.AdmissionBlocked != (seen > 0) {
			return nil, errSessionControlCloseCorrupt
		}
		return page, nil
	}
	if seen >= after.OverflowCloseCount {
		return nil, errSessionControlCloseCorrupt
	}
	page.Next = &sessionControlOverflowScanCursor{Directory: *after, LastKey: result.LastEvaluatedKey, Seen: seen}
	return page, nil
}

func sessionControlCloseDueShardForCell(cellID string, shard uint64) (string, error) {
	if !validSessionControlCellID(cellID) || shard >= sessionControlCloseDueShardCount {
		return "", errors.New("invalid session-control close due shard")
	}
	return fmt.Sprintf("CLOSE#%s#%02d", cellID, shard), nil
}

// ListDueCloseWorkPage uses the eventual GSI only for bounded discovery. Every
// hit is strong-read and decoded from its base key before it is returned. A
// missing GSI result is never interpreted as proof that work does not exist.
func (s *dynamoSessionControlStore) ListDueCloseWorkPage(ctx context.Context, cellID string, shard uint64,
	dueThroughMillis int64, cursor *sessionControlDueScanCursor, limit int32) (*sessionControlDueClosePage, error) {
	if err := s.validate(); err != nil {
		return nil, err
	}
	dueShard, err := sessionControlCloseDueShardForCell(cellID, shard)
	if err != nil || dueThroughMillis <= 0 {
		return nil, errors.New("invalid session-control close due scan")
	}
	opCtx, cancel := context.WithTimeout(ctx, s.timeout())
	defer cancel()
	var lastKey map[string]types.AttributeValue
	if cursor != nil {
		lastKey = cursor.LastKey
	}
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
		return nil, fmt.Errorf("session-control close due discovery: %w", err)
	}
	page := &sessionControlDueClosePage{Work: make([]sessionControlCloseWork, 0, len(result.Items))}
	for _, projected := range result.Items {
		pk, pkOK := projected["pk"].(*types.AttributeValueMemberS)
		sk, skOK := projected["sk"].(*types.AttributeValueMemberS)
		if !pkOK || !skOK || pk.Value == "" || sk.Value == "" {
			return nil, errSessionControlCloseCorrupt
		}
		base, getErr := s.client.GetItem(opCtx, &dynamodb.GetItemInput{
			TableName: aws.String(s.tableName), ConsistentRead: aws.Bool(true),
			Key: map[string]types.AttributeValue{
				"pk": &types.AttributeValueMemberS{Value: pk.Value},
				"sk": &types.AttributeValueMemberS{Value: sk.Value},
			},
		})
		if getErr != nil {
			return nil, fmt.Errorf("session-control close due base read: %w", getErr)
		}
		if len(base.Item) == 0 { // stale KEYS_ONLY hit
			continue
		}
		event, ok := base.Item["event_id"].(*types.AttributeValueMemberS)
		if !ok || !validSessionControlFenceEventID(event.Value) {
			return nil, errSessionControlCloseCorrupt
		}
		overflow := strings.HasPrefix(pk.Value, "OVERFLOW#")
		decoded, decodeErr := sessionControlCloseWorkFromItem(base.Item, overflow, cellID, event.Value)
		if decodeErr != nil {
			// No completed-audit row shape exists in this bounded foundation.
			// Therefore only an absent base row is a safely ignorable stale GSI
			// hit; every existing malformed or mutated authority fails closed.
			return nil, decodeErr
		}
		if decoded.DueAtMillis <= dueThroughMillis && sessionControlCloseDueShard(decoded) == dueShard {
			page.Work = append(page.Work, decoded)
		}
	}
	if len(result.LastEvaluatedKey) != 0 {
		page.Next = &sessionControlDueScanCursor{LastKey: result.LastEvaluatedKey}
	}
	return page, nil
}
