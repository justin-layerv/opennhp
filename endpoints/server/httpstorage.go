package server

import (
	"crypto/md5"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	uploadDir     = "etc/uploads"           // storage directory
	metadataDir   = "etc/metadata"          // metadata directory
	maxUploadSize = 20 * 1024 * 1024 * 1024 // 20G max upload size
	maxMemorySize = 10 * 1024 * 1024
)

type FileMetadata struct {
	UUID      string `json:"uuid"`       // file UUID
	Original  string `json:"original"`   // original file name
	MD5       string `json:"md5"`        // file MD5
	Path      string `json:"path"`       // file storage path
	Size      int64  `json:"size"`       // file size
	UploadURI string `json:"upload_uri"` // file download URI
}

// upload progress
var progressMap = make(map[string]int64)
var progressMutex sync.RWMutex

func (hs *HttpServer) initStorageRouter() {
	g := hs.ginEngine.Group("/storage")

	g.POST("/upload", func(c *gin.Context) {
		// check file size
		c.Request.Body = http.MaxBytesReader(c.Writer, c.Request.Body, maxUploadSize)
		if err := c.Request.ParseMultipartForm(maxMemorySize); err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"error":     "file size exceeds max upload size",
				"detail":    err.Error(),
				"max limit": maxUploadSize,
				"file size": c.Request.ContentLength,
			})
			return
		}

		// get file from form
		file, header, err := c.Request.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "file not found"})
			return
		}
		defer func() { _ = file.Close() }()

		// generate UUID and file path
		fileUUID := uuid.New().String()
		fileDir := filepath.Join(ExeDirPath, uploadDir, fileUUID)
		if err := os.MkdirAll(fileDir, os.ModePerm); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "create storage directory failed"})
			return
		}

		// create target file
		// Use filepath.Base to sanitize filename and prevent path traversal attacks.
		// This handles all edge cases including URL-encoded separators, null bytes, etc.
		filename := filepath.Base(header.Filename)
		if filename == "" || filename == "." || filename == ".." {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid filename"})
			return
		}
		filePath := filepath.Join(fileDir, filename)
		out, err := os.Create(filePath)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "create file failed"})
			return
		}
		defer func() { _ = out.Close() }()

		// create md5 calculator and progress tracker
		md5Hash := md5.New()
		progressKey := fileUUID // use UUID as progress key
		totalSize := header.Size

		// create multi-writer: write to file, calculate md5, and update progress
		multiWriter := io.MultiWriter(out, md5Hash)
		progressWriter := &ProgressWriter{
			Writer:   multiWriter,
			Progress: &progressMap,
			Key:      progressKey,
			Mutex:    &progressMutex,
			Total:    totalSize,
		}

		// copy file content
		if _, err := io.Copy(progressWriter, file); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "file copy failed"})
			return
		}

		// calculate md5
		fileMD5 := hex.EncodeToString(md5Hash.Sum(nil))

		// check if file already exists
		existingMetadata, exists := checkFileExists(fileMD5)
		if exists {
			// delete duplicate file
			_ = os.RemoveAll(fileDir)

			c.JSON(http.StatusOK, gin.H{
				"message":  "file already exists, skip storage",
				"file_uri": existingMetadata.UploadURI,
				"uuid":     existingMetadata.UUID,
				"md5":      existingMetadata.MD5,
			})
			return
		}

		// create metadata
		relativePath := filepath.Join(fileUUID, filename)
		fileURI := fmt.Sprintf("storage/download/%s/%s", fileUUID, filename)
		metadata := FileMetadata{
			UUID:      fileUUID,
			Original:  filename,
			MD5:       fileMD5,
			Path:      relativePath,
			Size:      totalSize,
			UploadURI: fileURI,
		}

		// save metadata
		if err := saveMetadata(metadata); err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "save metadata failed"})
			return
		}

		// delete progress after upload
		progressMutex.Lock()
		delete(progressMap, progressKey)
		progressMutex.Unlock()

		c.JSON(http.StatusOK, gin.H{
			"message":  "file upload success",
			"file_uri": fileURI,
			"uuid":     fileUUID,
			"md5":      fileMD5,
		})
	})

	// get upload progress
	g.GET("/progress/:uuid", func(c *gin.Context) {
		uuid := c.Param("uuid")
		progressMutex.RLock()
		defer progressMutex.RUnlock()

		bytesCopied, exists := progressMap[uuid]
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{"error": "file not in upload"})
			return
		}

		// calculate progress percent
		total, exists := progressMap[uuid+"_total"]
		if !exists {
			c.JSON(http.StatusOK, gin.H{
				"uuid":         uuid,
				"bytes_copied": bytesCopied,
			})
			return
		}

		percent := 0
		if total > 0 {
			percent = int(float64(bytesCopied) / float64(total) * 100)
		}

		c.JSON(http.StatusOK, gin.H{
			"uuid":         uuid,
			"bytes_copied": bytesCopied,
			"total_size":   total,
			"percent":      percent,
		})
	})

	// file download
	g.GET("/download/:uuid/:filename", func(c *gin.Context) {
		// Use filepath.Base to sanitize path components and prevent traversal attacks
		uuid := filepath.Base(c.Param("uuid"))
		filename := filepath.Base(c.Param("filename"))

		// Reject empty or special directory entries
		if uuid == "" || uuid == "." || uuid == ".." {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file name"})
			return
		}
		if filename == "" || filename == "." || filename == ".." {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file name"})
			return
		}

		filePath := filepath.Join(ExeDirPath, uploadDir, uuid, filename)

		safeDir := filepath.Join(ExeDirPath, uploadDir)
		safeDirAbs, err := filepath.Abs(safeDir)
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "internal server error"})
			return
		}

		absPath, err := filepath.Abs(filePath)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file name"})
			return
		}

		// ensure that the resolved path is within the safe directory
		if !strings.HasPrefix(absPath, safeDirAbs+string(os.PathSeparator)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file name"})
			return
		}

		// check file exists
		if _, err := os.Stat(absPath); os.IsNotExist(err) {
			c.JSON(http.StatusNotFound, gin.H{"error": "file not exists"})
			return
		}

		// provide file download
		c.Header("Content-Description", "File Transfer")
		// Properly quote filename to prevent header injection attacks
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"",
			strings.ReplaceAll(filename, "\"", "\\\"")))
		c.Header("Content-Type", "application/octet-stream")
		c.File(absPath)
	})

	// get file metadata
	g.GET("/metadata/:uuid", func(c *gin.Context) {
		uuid := c.Param("uuid")
		metadata, err := loadMetadata(uuid)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "file metadata not exists"})
			return
		}

		c.JSON(http.StatusOK, metadata)
	})
}

// ProgressWriter use to track upload progress
type ProgressWriter struct {
	io.Writer
	Progress *map[string]int64
	Key      string
	Mutex    *sync.RWMutex
	Total    int64
	written  int64
}

func (pw *ProgressWriter) Write(p []byte) (n int, err error) {
	n, err = pw.Writer.Write(p)
	if err == nil {
		pw.written += int64(n)
		pw.Mutex.Lock()
		(*pw.Progress)[pw.Key] = pw.written
		// store total size for progress calculation
		(*pw.Progress)[pw.Key+"_total"] = pw.Total
		pw.Mutex.Unlock()
	}
	return
}

// saveMetadata use to save file metadata
func saveMetadata(metadata FileMetadata) error {
	// Validate UUID to prevent path traversal
	safeUUID := filepath.Base(metadata.UUID)
	if safeUUID == "" || safeUUID == "." || safeUUID == ".." || safeUUID != metadata.UUID {
		return errors.New("invalid UUID format")
	}

	if _, err := os.Stat(filepath.Join(ExeDirPath, metadataDir)); os.IsNotExist(err) {
		if err := os.MkdirAll(filepath.Join(ExeDirPath, metadataDir), os.ModePerm); err != nil {
			return err
		}
	}

	metadataPath := filepath.Join(ExeDirPath, metadataDir, safeUUID+".json")
	file, err := os.Create(metadataPath)
	if err != nil {
		return err
	}
	defer func() { _ = file.Close() }()

	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	return encoder.Encode(metadata)
}

// loadMetadata use to load file metadata
func loadMetadata(uuid string) (FileMetadata, error) {
	var metadata FileMetadata
	metadataPath := filepath.Join(ExeDirPath, metadataDir, uuid+".json")

	absPath, err := filepath.Abs(metadataPath)
	if err != nil {
		return metadata, err
	}

	safeDir := filepath.Join(ExeDirPath, metadataDir)
	safeDirAbs, err := filepath.Abs(safeDir)
	if err != nil {
		return metadata, err
	}
	if !strings.HasPrefix(absPath, safeDirAbs+string(os.PathSeparator)) {
		return metadata, errors.New("invalid file name")
	}

	file, err := os.Open(absPath)
	if err != nil {
		return metadata, err
	}
	defer func() { _ = file.Close() }()

	decoder := json.NewDecoder(file)
	err = decoder.Decode(&metadata)
	return metadata, err
}

// checkFileExists use to check if file exists
func checkFileExists(md5 string) (FileMetadata, bool) {
	// check all metadata files
	files, err := os.ReadDir(filepath.Join(ExeDirPath, metadataDir))
	if err != nil {
		return FileMetadata{}, false
	}

	for _, file := range files {
		if file.IsDir() {
			continue
		}

		// Skip files that don't end with .json
		name := file.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		uuid := strings.TrimSuffix(name, ".json")
		if uuid == "" {
			continue
		}

		metadata, err := loadMetadata(uuid)
		if err == nil && metadata.MD5 == md5 {
			return metadata, true
		}
	}

	return FileMetadata{}, false
}
