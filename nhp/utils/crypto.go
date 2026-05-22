package utils

import (
	"crypto/md5"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
)

func MD5(value string) string {
	_16bytes := md5.Sum([]byte(value))
	return hex.EncodeToString(_16bytes[:])
}

func Base64(value []byte) string {
	return base64.StdEncoding.EncodeToString(value)
}

func Md5sum(fullFilePath string) (string, error) {
	fileInfo, err := os.Stat(fullFilePath)
	if err != nil {
		return "", fmt.Errorf("file not found: %w", err)
	}

	if !fileInfo.Mode().IsRegular() {
		return "", errors.New("path is not a regular file")
	}

	file, err := os.Open(fullFilePath)
	if err != nil {
		return "", fmt.Errorf("failed to open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	hasher := md5.New()

	if _, err := io.Copy(hasher, file); err != nil {
		return "", fmt.Errorf("failed to read file content: %w", err)
	}

	// Convert hash to hex string
	return hex.EncodeToString(hasher.Sum(nil)), nil
}
