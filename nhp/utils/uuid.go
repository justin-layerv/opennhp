package utils

import (
	"fmt"

	"github.com/google/uuid"
)

// GenerateUUIDv4 creates a random UUID (version 4)
func GenerateUUIDv4() (string, error) {
	u, err := uuid.NewRandom()
	if err != nil {
		return "", fmt.Errorf("failed to generate UUID v4: %w", err)
	}
	return u.String(), nil
}
