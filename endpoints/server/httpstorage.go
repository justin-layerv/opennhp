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

	log "github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/utils"

	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
)

const (
	uploadDir     = "etc/uploads"           // storage directory
	metadataDir   = "etc/metadata"          // metadata directory
	maxUploadSize = 20 * 1024 * 1024 * 1024 // 20G max upload size
	maxMemorySize = 10 * 1024 * 1024

	errInvalidUUID     = "invalid uuid"
	errInvalidFilename = "invalid file name"
	errFileNotFound    = "file does not exist"
	errInternal        = "internal error"
)

type FileMetadata struct {
	UUID      string `json:"uuid"`       // file UUID
	Original  string `json:"original"`   // original file name
	MD5       string `json:"md5"`        // file MD5
	Path      string `json:"path"`       // file storage path
	Size      int64  `json:"size"`       // file size
	UploadURI string `json:"upload_uri"` // file download URI
}

// progressEntry holds the written and total byte counts for a single upload.
type progressEntry struct {
	written int64
	total   int64
}

// progressTracker manages upload progress state with thread-safe access.
type progressTracker struct {
	mu   sync.RWMutex
	data map[string]progressEntry
}

func newProgressTracker() *progressTracker {
	return &progressTracker{data: make(map[string]progressEntry)}
}

func (pt *progressTracker) set(key string, written, total int64) {
	pt.mu.Lock()
	pt.data[key] = progressEntry{written: written, total: total}
	pt.mu.Unlock()
}

func (pt *progressTracker) get(key string) (written int64, total int64, exists bool) {
	pt.mu.RLock()
	defer pt.mu.RUnlock()
	entry, exists := pt.data[key]
	if !exists {
		return 0, 0, false
	}
	return entry.written, entry.total, true
}

func (pt *progressTracker) remove(key string) {
	pt.mu.Lock()
	delete(pt.data, key)
	pt.mu.Unlock()
}

var uploadProgress = newProgressTracker()

// cachedMetadataDirAbs is set once at startup by initStorageRouter.
// loadMetadata uses it to avoid recomputing filepath.Abs on every call.
var cachedMetadataDirAbs string

// md5Index provides O(1) duplicate detection by mapping MD5 hashes to UUIDs.
// It is built from disk on startup and kept in sync by saveMetadata.
// Entries are only evicted when checkFileExists detects a stale entry
// (missing/corrupt metadata file on disk), not when files are deleted
// through other means (e.g., manual cleanup). This is acceptable because
// stale entries are self-healing on next lookup.
var md5Index = make(map[string]string) // md5 -> uuid
var md5IndexMu sync.RWMutex

// initMD5Index scans all metadata JSON files on disk and populates the
// in-memory md5Index map. It is called once at startup and is safe to
// call concurrently (it acquires a write lock).
func initMD5Index() {
	dir := filepath.Join(ExeDirPath, metadataDir)
	files, err := os.ReadDir(dir)
	if err != nil {
		if !os.IsNotExist(err) {
			log.Warning("[httpstorage] failed to read metadata dir: %v", err)
		}
		return
	}

	// Build the index without holding the lock to avoid blocking
	// concurrent lookups during potentially slow disk I/O.
	newIndex := make(map[string]string, len(files))

	for _, f := range files {
		if f.IsDir() {
			continue
		}
		name := f.Name()
		if !strings.HasSuffix(name, ".json") {
			continue
		}
		fileID := strings.TrimSuffix(name, ".json")
		if fileID == "" {
			continue
		}
		metadata, err := loadMetadata(fileID)
		if err != nil {
			log.Warning("[httpstorage] skipping corrupt metadata file %s: %v", name, err)
			continue
		}
		if metadata.MD5 != "" {
			newIndex[metadata.MD5] = metadata.UUID
		}
	}

	// Swap the index under the lock.
	md5IndexMu.Lock()
	md5Index = newIndex
	md5IndexMu.Unlock()

	log.Info("[httpstorage] MD5 index populated with %d entries", len(newIndex))
}

func (hs *HttpServer) initStorageRouter() {
	// Ensure storage directories exist at startup so per-request
	// existence checks are unnecessary.
	_ = os.MkdirAll(filepath.Join(ExeDirPath, uploadDir), os.ModePerm)
	_ = os.MkdirAll(filepath.Join(ExeDirPath, metadataDir), os.ModePerm)

	// Pre-compute absolute safe directories for path validation.
	uploadDirAbs, err := filepath.Abs(filepath.Join(ExeDirPath, uploadDir))
	if err != nil {
		log.Error("[httpstorage] failed to resolve upload dir: %v", err)
		return
	}
	metadataDirAbs, err := filepath.Abs(filepath.Join(ExeDirPath, metadataDir))
	if err != nil {
		log.Error("[httpstorage] failed to resolve metadata dir: %v", err)
		return
	}
	cachedMetadataDirAbs = metadataDirAbs

	initMD5Index()

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
		if !utils.IsValidPathComponent(filename) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid filename"})
			return
		}
		filePath := filepath.Join(fileDir, filename)
		out, err := os.Create(filePath) //nolint:gosec // G703: filename sanitized with filepath.Base above
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": "create file failed"})
			return
		}
		defer func() { _ = out.Close() }()

		// create md5 calculator and progress tracker
		md5Hash := md5.New()
		progressKey := fileUUID // use UUID as progress key
		totalSize := header.Size
		progressCleaned := false
		defer func() {
			if !progressCleaned {
				uploadProgress.remove(progressKey)
			}
		}()

		// create multi-writer: write to file, calculate md5, and update progress
		multiWriter := io.MultiWriter(out, md5Hash)
		pw := &progressWriter{
			Writer:  multiWriter,
			tracker: uploadProgress,
			key:     progressKey,
			total:   totalSize,
		}

		// copy file content
		if _, err := io.Copy(pw, file); err != nil {
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

		// Mark progress as cleaned; defer handles failure paths.
		uploadProgress.remove(progressKey)
		progressCleaned = true

		c.JSON(http.StatusOK, gin.H{
			"message":  "file upload success",
			"file_uri": fileURI,
			"uuid":     fileUUID,
			"md5":      fileMD5,
		})
	})

	// get upload progress
	g.GET("/progress/:uuid", func(c *gin.Context) {
		uuid := filepath.Base(c.Param("uuid"))
		if !utils.IsValidPathComponent(uuid) {
			c.JSON(http.StatusBadRequest, gin.H{"error": errInvalidUUID})
			return
		}

		bytesCopied, total, exists := uploadProgress.get(uuid)
		if !exists {
			c.JSON(http.StatusNotFound, gin.H{"error": "file not in upload"})
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
		if !utils.IsValidPathComponent(uuid) || !utils.IsValidPathComponent(filename) {
			c.JSON(http.StatusBadRequest, gin.H{"error": errInvalidFilename})
			return
		}

		filePath := filepath.Join(ExeDirPath, uploadDir, uuid, filename)

		absPath, err := filepath.Abs(filePath)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": errInvalidFilename})
			return
		}

		// ensure that the resolved path is within the safe directory
		if !utils.IsPathWithinDir(absPath, uploadDirAbs) {
			c.JSON(http.StatusBadRequest, gin.H{"error": errInvalidFilename})
			return
		}

		// Open file directly to eliminate TOCTOU race between stat and read.
		// Using the open file descriptor for both validation and serving ensures
		// the file cannot be swapped between check and use.
		f, err := os.Open(absPath) //nolint:gosec // G304: absPath validated by prefix check above
		if err != nil {
			if os.IsNotExist(err) {
				c.JSON(http.StatusNotFound, gin.H{"error": errFileNotFound})
			} else {
				c.JSON(http.StatusInternalServerError, gin.H{"error": errInternal})
			}
			return
		}
		defer func() { _ = f.Close() }()

		// Verify the opened file is a regular file (not a symlink, directory, etc.)
		fi, err := f.Stat()
		if err != nil {
			c.JSON(http.StatusInternalServerError, gin.H{"error": errInternal})
			return
		}
		if !fi.Mode().IsRegular() {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file"})
			return
		}

		// provide file download
		c.Header("Content-Description", "File Transfer")
		// Properly quote filename to prevent header injection attacks
		c.Header("Content-Disposition", fmt.Sprintf("attachment; filename=\"%s\"",
			strings.ReplaceAll(filename, "\"", "\\\"")))
		c.Header("Content-Type", "application/octet-stream")
		http.ServeContent(c.Writer, c.Request, filename, fi.ModTime(), f)
	})

	// get file metadata
	g.GET("/metadata/:uuid", func(c *gin.Context) {
		uuid := filepath.Base(c.Param("uuid"))
		if !utils.IsValidPathComponent(uuid) {
			c.JSON(http.StatusBadRequest, gin.H{"error": errInvalidUUID})
			return
		}
		metadata, err := loadMetadata(uuid)
		if err != nil {
			c.JSON(http.StatusNotFound, gin.H{"error": "file metadata does not exist"})
			return
		}

		c.JSON(http.StatusOK, metadata)
	})
}

const progressUpdateStep = 256 * 1024 // update tracker every 256KB

// progressWriter wraps an io.Writer to track upload progress via a progressTracker.
// Updates are throttled to every progressUpdateStep bytes to reduce lock contention.
type progressWriter struct {
	io.Writer
	tracker      *progressTracker
	key          string
	total        int64
	written      int64
	lastReported int64
}

func (pw *progressWriter) Write(p []byte) (n int, err error) {
	n, err = pw.Writer.Write(p)
	if err == nil {
		pw.written += int64(n)
		if pw.written-pw.lastReported >= progressUpdateStep || pw.written == pw.total {
			pw.tracker.set(pw.key, pw.written, pw.total)
			pw.lastReported = pw.written
		}
	}
	return
}

// saveMetadata use to save file metadata
func saveMetadata(metadata FileMetadata) error {
	// Validate UUID to prevent path traversal
	safeUUID := filepath.Base(metadata.UUID)
	if !utils.IsValidPathComponent(safeUUID) || safeUUID != metadata.UUID {
		return errors.New("invalid UUID format")
	}

	metadataPath := filepath.Join(ExeDirPath, metadataDir, safeUUID+".json")
	if err := utils.SaveStructAsJsonFile(metadataPath, metadata); err != nil {
		return err
	}

	// Update the in-memory MD5 index so subsequent lookups are O(1).
	// If a duplicate MD5 exists, this overwrites the previous UUID
	// (last-write-wins). This is acceptable as the upload handler's
	// dedup check prevents duplicate files from being stored.
	if metadata.MD5 != "" {
		md5IndexMu.Lock()
		md5Index[metadata.MD5] = metadata.UUID
		md5IndexMu.Unlock()
	}

	return nil
}

// loadMetadata use to load file metadata
func loadMetadata(uuid string) (FileMetadata, error) {
	var metadata FileMetadata
	metadataPath := filepath.Join(ExeDirPath, metadataDir, uuid+".json")

	absPath, err := filepath.Abs(metadataPath)
	if err != nil {
		return metadata, err
	}

	safeDirAbs := cachedMetadataDirAbs
	if safeDirAbs == "" {
		// Fallback for calls before initStorageRouter (e.g., tests).
		safeDirAbs, err = filepath.Abs(filepath.Join(ExeDirPath, metadataDir))
		if err != nil {
			return metadata, err
		}
	}
	if !utils.IsPathWithinDir(absPath, safeDirAbs) {
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

// checkFileExists performs an O(1) lookup in the in-memory MD5 index to
// determine whether a file with the given MD5 hash has already been uploaded.
// If the index entry exists but the underlying metadata file is missing or
// corrupt, the stale entry is removed and false is returned.
func checkFileExists(md5 string) (FileMetadata, bool) {
	md5IndexMu.RLock()
	fileUUID, exists := md5Index[md5]
	md5IndexMu.RUnlock()

	if !exists {
		return FileMetadata{}, false
	}

	metadata, err := loadMetadata(fileUUID)
	if err != nil || metadata.MD5 != md5 {
		// Stale or inconsistent index entry — remove it so we don't keep failing.
		// Re-check that the entry still points to the same UUID to avoid
		// deleting a concurrently re-added entry from a new upload.
		md5IndexMu.Lock()
		if md5Index[md5] == fileUUID {
			delete(md5Index, md5)
		}
		md5IndexMu.Unlock()
		return FileMetadata{}, false
	}

	return metadata, true
}
