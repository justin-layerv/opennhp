package server

import (
	"context"
	"strings"
	"testing"

	"github.com/aws/aws-sdk-go-v2/service/dynamodb"
)

func TestDynamoDBStorage_Ping_NoTableConfigured(t *testing.T) {
	storage := &DynamoDBStorage{
		client: dynamodb.New(dynamodb.Options{}),
		config: DynamoDBConfig{
			ACAssignmentsTable: "",
		},
	}

	err := storage.Ping(context.Background())
	if err == nil {
		t.Fatal("Expected error when ACAssignmentsTable is empty, got nil")
	}

	expectedMsg := "no ACAssignmentsTable configured"
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Errorf("Expected error containing %q, got %q", expectedMsg, err.Error())
	}
}

func TestDynamoDBStorage_Ping_NilClient(t *testing.T) {
	storage := &DynamoDBStorage{
		client: nil,
		config: DynamoDBConfig{
			ACAssignmentsTable: "test-table",
		},
	}

	err := storage.Ping(context.Background())
	if err == nil {
		t.Fatal("Expected error when client is nil, got nil")
	}

	expectedMsg := "dynamodb client not initialized"
	if !strings.Contains(err.Error(), expectedMsg) {
		t.Errorf("Expected error containing %q, got %q", expectedMsg, err.Error())
	}
}
