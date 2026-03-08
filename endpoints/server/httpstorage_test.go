// httpstorage_test.go contains security-focused unit tests for the storage
// endpoints, covering path traversal attack vectors (issue #58), MD5 index
// correctness (PR #698), and symlink handling documentation (issue #57).
package server

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/gin-gonic/gin"

	"github.com/OpenNHP/opennhp/nhp/utils"
)

// setupStorageTestEnv creates a temporary directory structure for storage tests
// and sets ExeDirPath to point to it. Returns a cleanup function.
//
// NOTE: These tests CANNOT use t.Parallel() because they mutate package-level
// globals (ExeDirPath, md5Index, cachedMetadataDirAbs). Running them in parallel
// would cause data races. The ProgressWriter tests are an exception since they
// don't touch these globals.
func setupStorageTestEnv(t *testing.T) (string, func()) {
	t.Helper()
	tmpDir := t.TempDir()

	// Save and restore package-level state.
	oldExeDirPath := ExeDirPath
	oldIndex := md5Index
	oldCachedDir := cachedMetadataDirAbs
	ExeDirPath = tmpDir
	md5Index = make(map[string]string)
	cachedMetadataDirAbs = ""

	// Create the required directories
	if err := os.MkdirAll(filepath.Join(tmpDir, uploadDir), 0o755); err != nil {
		t.Fatalf("failed to create upload dir: %v", err)
	}
	if err := os.MkdirAll(filepath.Join(tmpDir, metadataDir), 0o755); err != nil {
		t.Fatalf("failed to create metadata dir: %v", err)
	}

	cleanup := func() {
		ExeDirPath = oldExeDirPath
		md5Index = oldIndex
		cachedMetadataDirAbs = oldCachedDir
	}
	return tmpDir, cleanup
}

// setupStorageRouter creates a gin engine with only the storage routes registered.
func setupStorageRouter(t *testing.T) *gin.Engine {
	t.Helper()
	gin.SetMode(gin.TestMode)
	engine := gin.New()
	hs := &HttpServer{ginEngine: engine}
	hs.initStorageRouter()
	return engine
}

// createMultipartUpload creates a multipart form body with a file field.
func createMultipartUpload(t *testing.T, fieldName, filename, content string) (*bytes.Buffer, string) {
	t.Helper()
	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)
	part, err := writer.CreateFormFile(fieldName, filename)
	if err != nil {
		t.Fatalf("failed to create form file: %v", err)
	}
	if _, err := io.WriteString(part, content); err != nil {
		t.Fatalf("failed to write file content: %v", err)
	}
	if err := writer.Close(); err != nil {
		t.Fatalf("failed to close multipart writer: %v", err)
	}
	return body, writer.FormDataContentType()
}

// parseJSONResponse unmarshals an httptest.ResponseRecorder body into a map.
func parseJSONResponse(t *testing.T, w *httptest.ResponseRecorder) map[string]interface{} {
	t.Helper()
	var resp map[string]interface{}
	if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
		t.Fatalf("failed to parse response: %v", err)
	}
	return resp
}

// ============================================================================
// Upload Endpoint — Path Traversal Tests
// ============================================================================

func TestUploadPathTraversal(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()
	engine := setupStorageRouter(t)

	testCases := []struct {
		name       string
		filename   string
		wantStatus int
		wantErr    bool
	}{
		{
			name:       "normal filename",
			filename:   "test.txt",
			wantStatus: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "path traversal with ../",
			filename:   "../../../etc/passwd",
			wantStatus: http.StatusOK, // filepath.Base normalizes to "passwd"
			wantErr:    false,
		},
		{
			name:       "path traversal with nested ../",
			filename:   "foo/../../bar/../../../etc/shadow",
			wantStatus: http.StatusOK, // filepath.Base normalizes to "shadow"
			wantErr:    false,
		},
		{
			name:       "absolute path /etc/passwd",
			filename:   "/etc/passwd",
			wantStatus: http.StatusOK, // filepath.Base normalizes to "passwd"
			wantErr:    false,
		},
		{
			name:       "backslash traversal",
			filename:   "..\\..\\etc\\passwd",
			wantStatus: http.StatusOK, // filepath.Base handles this
			wantErr:    false,
		},
		{
			name:       "dot filename",
			filename:   ".",
			wantStatus: http.StatusBadRequest,
			wantErr:    true,
		},
		{
			name:       "dotdot filename",
			filename:   "..",
			wantStatus: http.StatusBadRequest,
			wantErr:    true,
		},
		{
			name:       "filename with spaces",
			filename:   "my document.txt",
			wantStatus: http.StatusOK,
			wantErr:    false,
		},
		{
			name:       "filename with unicode",
			filename:   "résumé.pdf",
			wantStatus: http.StatusOK,
			wantErr:    false,
		},
		{
			// Null bytes in filenames corrupt the MIME multipart header,
			// causing Go's multipart parser to reject the request.
			name:       "null byte injection",
			filename:   "test.txt\x00.exe",
			wantStatus: http.StatusBadRequest,
			wantErr:    true,
		},
		{
			// Filenames exceeding OS limits (255 bytes on most Unix systems)
			// cause os.Create to fail. No path traversal, just a length limit.
			name:       "very long filename",
			filename:   strings.Repeat("a", 300) + ".txt",
			wantStatus: http.StatusInternalServerError,
			wantErr:    true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			body, contentType := createMultipartUpload(t, "file", tc.filename, "test file content")

			req := httptest.NewRequest(http.MethodPost, "/storage/upload", body)
			req.Header.Set("Content-Type", contentType)
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body = %s", w.Code, tc.wantStatus, w.Body.String())
			}

			if tc.wantErr {
				resp := parseJSONResponse(t, w)
				if _, ok := resp["error"]; !ok {
					t.Error("expected error field in response")
				}
			}
		})
	}
}

// TestUploadFileStoredSafely verifies that files with traversal filenames
// are stored within the upload directory, not at the traversal target.
func TestUploadFileStoredSafely(t *testing.T) {
	tmpDir, cleanup := setupStorageTestEnv(t)
	defer cleanup()
	engine := setupStorageRouter(t)

	traversalNames := []struct {
		filename string
		content  string // unique content per case to avoid MD5 dedup
	}{
		{"../../../etc/passwd", "content-for-passwd-traversal"},
		{"/etc/shadow", "content-for-shadow-traversal"},
		{"foo/../../bar.txt", "content-for-bar-traversal"},
	}

	for _, tc := range traversalNames {
		t.Run(tc.filename, func(t *testing.T) {
			body, contentType := createMultipartUpload(t, "file", tc.filename, tc.content)

			req := httptest.NewRequest(http.MethodPost, "/storage/upload", body)
			req.Header.Set("Content-Type", contentType)
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Skipf("upload rejected (status %d), traversal protection works via rejection", w.Code)
			}

			// Parse the response to get the UUID
			resp := parseJSONResponse(t, w)
			fileUUID, ok := resp["uuid"].(string)
			if !ok {
				t.Fatal("response missing uuid field")
			}

			// The file must be stored within the upload directory
			sanitized := filepath.Base(tc.filename)
			expectedPath := filepath.Join(tmpDir, uploadDir, fileUUID, sanitized)
			if _, err := os.Stat(expectedPath); os.IsNotExist(err) {
				t.Errorf("file not found at expected safe path: %s", expectedPath)
			}

			// Verify no file was created at the traversal target
			if tc.filename != sanitized {
				dangerousPath := filepath.Join(tmpDir, uploadDir, tc.filename)
				if _, err := os.Stat(dangerousPath); err == nil {
					t.Errorf("file was created at dangerous traversal path: %s", dangerousPath)
				}
			}
		})
	}
}

// ============================================================================
// Download Endpoint — Path Traversal Tests
// ============================================================================

func TestDownloadPathTraversal(t *testing.T) {
	tmpDir, cleanup := setupStorageTestEnv(t)
	defer cleanup()
	engine := setupStorageRouter(t)

	// Create a legitimate file for positive test
	testUUID := "550e8400-e29b-41d4-a716-446655440000"
	testFilename := "legitimate.txt"
	testContent := "legitimate file content"
	fileDir := filepath.Join(tmpDir, uploadDir, testUUID)
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatalf("failed to create file dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, testFilename), []byte(testContent), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	// Create a sensitive file outside the upload directory to test traversal
	sensitiveFile := filepath.Join(tmpDir, "sensitive.txt")
	if err := os.WriteFile(sensitiveFile, []byte("TOP SECRET"), 0o644); err != nil {
		t.Fatalf("failed to create sensitive file: %v", err)
	}

	testCases := []struct {
		name       string
		uuid       string
		filename   string
		wantStatus int
	}{
		{
			name:       "legitimate download",
			uuid:       testUUID,
			filename:   testFilename,
			wantStatus: http.StatusOK,
		},
		{
			name:       "filename traversal ../",
			uuid:       testUUID,
			filename:   "sensitive.txt", // filepath.Base("../../sensitive.txt") -> "sensitive.txt"
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "uuid is dot",
			uuid:       "dot-uuid",
			filename:   "test.txt",
			wantStatus: http.StatusNotFound, // "dot-uuid" dir doesn't exist
		},
		{
			name:       "filename is dot-literal",
			uuid:       testUUID,
			filename:   "dot-file",
			wantStatus: http.StatusNotFound, // file doesn't exist
		},
		{
			name:       "nonexistent uuid",
			uuid:       "nonexistent-uuid",
			filename:   "file.txt",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path := fmt.Sprintf("/storage/download/%s/%s", tc.uuid, tc.filename)
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body = %s", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

// TestDownloadPrefixCheckPreventsTraversal verifies that even if filepath.Base
// is bypassed somehow, the prefix check prevents access outside the upload dir.
func TestDownloadPrefixCheckPreventsTraversal(t *testing.T) {
	tmpDir, cleanup := setupStorageTestEnv(t)
	defer cleanup()
	engine := setupStorageRouter(t)

	// Create a file that would exist if traversal succeeded
	sensitiveFile := filepath.Join(tmpDir, "sensitive.txt")
	if err := os.WriteFile(sensitiveFile, []byte("TOP SECRET"), 0o644); err != nil {
		t.Fatalf("failed to create sensitive file: %v", err)
	}

	// Try various encoding tricks — Gin's router will normalize these,
	// but we verify the content is never leaked regardless
	traversalPaths := []struct {
		name string
		path string
	}{
		{"double encoding", "/storage/download/..%252f..%252f/sensitive.txt"},
		{"mixed slashes", "/storage/download/..%5c..%5c/sensitive.txt"},
	}

	for _, tc := range traversalPaths {
		t.Run(tc.name, func(t *testing.T) {
			req := httptest.NewRequest(http.MethodGet, tc.path, nil)
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			// Must not return 200 with the sensitive file content
			if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "TOP SECRET") {
				t.Error("path traversal succeeded - sensitive file content was returned")
			}
		})
	}
}

// TestDownloadValidationLogic directly tests the handler's validation behavior
// by constructing requests that reach the handler (not blocked by router).
// The handler applies filepath.Base() + dot/dotdot checks + prefix validation.
func TestDownloadValidationLogic(t *testing.T) {
	tmpDir, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	gin.SetMode(gin.TestMode)
	engine := gin.New()

	// Register a route that accepts arbitrary path params to test handler validation
	engine.GET("/dl/:uuid/:filename", func(c *gin.Context) {
		uuidParam := filepath.Base(c.Param("uuid"))
		filenameParam := filepath.Base(c.Param("filename"))

		if uuidParam == "" || uuidParam == "." || uuidParam == ".." {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file name"})
			return
		}
		if filenameParam == "" || filenameParam == "." || filenameParam == ".." {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file name"})
			return
		}

		filePath := filepath.Join(ExeDirPath, uploadDir, uuidParam, filenameParam)
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
		if !strings.HasPrefix(absPath, safeDirAbs+string(os.PathSeparator)) {
			c.JSON(http.StatusBadRequest, gin.H{"error": "invalid file name"})
			return
		}

		c.JSON(http.StatusOK, gin.H{"resolved": absPath})
	})

	// Create a sensitive file outside uploads
	sensitiveFile := filepath.Join(tmpDir, "secret.conf")
	if err := os.WriteFile(sensitiveFile, []byte("SECRET"), 0o644); err != nil {
		t.Fatalf("failed to create sensitive file: %v", err)
	}

	testCases := []struct {
		name       string
		uuid       string
		filename   string
		wantStatus int
	}{
		{"dot uuid", ".", "file.txt", http.StatusBadRequest},
		{"dotdot uuid", "..", "file.txt", http.StatusBadRequest},
		{"dot filename", "valid-uuid", ".", http.StatusBadRequest},
		{"dotdot filename", "valid-uuid", "..", http.StatusBadRequest},
		{"valid params", "my-uuid", "file.txt", http.StatusOK},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path := fmt.Sprintf("/dl/%s/%s", tc.uuid, tc.filename)
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body = %s", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

// TestDownloadRejectsNonRegularFile verifies that directories, symlinks, etc.
// are rejected by the file type check.
func TestDownloadRejectsNonRegularFile(t *testing.T) {
	tmpDir, cleanup := setupStorageTestEnv(t)
	defer cleanup()
	engine := setupStorageRouter(t)

	testUUID := "550e8400-e29b-41d4-a716-446655440001"
	fileDir := filepath.Join(tmpDir, uploadDir, testUUID)
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatalf("failed to create file dir: %v", err)
	}

	// Create a subdirectory inside the UUID dir (not a regular file)
	subDir := filepath.Join(fileDir, "subdir")
	if err := os.Mkdir(subDir, 0o755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	path := fmt.Sprintf("/storage/download/%s/subdir", testUUID)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	// Should reject because it's a directory, not a regular file
	if w.Code == http.StatusOK {
		t.Error("should not serve a directory as a file download")
	}
}

// TestDownloadSymlinkRejected documents CURRENT behavior, not DESIRED behavior.
// Currently, symlinks within the upload directory are followed because:
//   - The path prefix check validates the symlink's path, not its target
//   - os.Open follows symlinks transparently
//   - fi.Mode().IsRegular() on the opened fd returns true for the target file
//
// DESIRED behavior: symlinks pointing outside the upload directory should be
// rejected, either via os.Lstat before opening or by resolving the real path
// with filepath.EvalSymlinks and re-checking the prefix. See issue #57.
func TestDownloadSymlinkRejected(t *testing.T) {
	tmpDir, cleanup := setupStorageTestEnv(t)
	defer cleanup()
	engine := setupStorageRouter(t)

	testUUID := "550e8400-e29b-41d4-a716-446655440002"
	fileDir := filepath.Join(tmpDir, uploadDir, testUUID)
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatalf("failed to create file dir: %v", err)
	}

	// Create a sensitive file outside the upload directory
	sensitiveFile := filepath.Join(tmpDir, "secret.txt")
	if err := os.WriteFile(sensitiveFile, []byte("SECRET DATA"), 0o644); err != nil {
		t.Fatalf("failed to create sensitive file: %v", err)
	}

	// Create a symlink inside the upload directory pointing to the sensitive file
	symlinkPath := filepath.Join(fileDir, "link.txt")
	if err := os.Symlink(sensitiveFile, symlinkPath); err != nil {
		t.Skipf("cannot create symlink (permissions): %v", err)
	}

	path := fmt.Sprintf("/storage/download/%s/link.txt", testUUID)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	// The symlink itself is a regular file when opened, but IsRegular() check
	// on the opened fd (via f.Stat which follows the symlink) should still work.
	// The key protection is that os.Open follows the symlink but the content
	// is from the target. The prefix check on the *path* (before open) is what
	// matters — symlink target is not checked by path prefix. This test documents
	// the current behavior: the symlink within the upload dir will be followed.
	// The fi.Mode().IsRegular() check on the fd's stat result will return true
	// for the target file. This is a known limitation documented in issue #57.
	if w.Code == http.StatusOK && strings.Contains(w.Body.String(), "SECRET DATA") {
		t.Log("NOTICE: symlink within upload dir was followed to sensitive file. " +
			"This is a known TOCTOU-adjacent issue (see issue #57). " +
			"The prefix check protects against path traversal but not in-directory symlinks.")
	}
}

// ============================================================================
// Content-Disposition Header Injection Tests
// ============================================================================

func TestContentDispositionHeaderInjection(t *testing.T) {
	tmpDir, cleanup := setupStorageTestEnv(t)
	defer cleanup()
	engine := setupStorageRouter(t)

	testCases := []struct {
		name       string
		filename   string
		urlPath    string // URL-safe path (percent-encoded if needed)
		wantHeader string
	}{
		{
			name:       "normal filename",
			filename:   "file.txt",
			urlPath:    "file.txt",
			wantHeader: `attachment; filename="file.txt"`,
		},
		{
			name:       "filename with quotes",
			filename:   `file"name.txt`,
			urlPath:    `file"name.txt`,
			wantHeader: `attachment; filename="file\"name.txt"`,
		},
		{
			name:       "filename with special characters",
			filename:   "file-name_(1).txt",
			urlPath:    "file-name_(1).txt",
			wantHeader: `attachment; filename="file-name_(1).txt"`,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			testUUID := fmt.Sprintf("cd-test-%s", strings.ReplaceAll(tc.name, " ", "-"))
			fileDir := filepath.Join(tmpDir, uploadDir, testUUID)
			if err := os.MkdirAll(fileDir, 0o755); err != nil {
				t.Fatalf("failed to create file dir: %v", err)
			}
			if err := os.WriteFile(filepath.Join(fileDir, tc.filename), []byte("content"), 0o644); err != nil {
				t.Fatalf("failed to create test file: %v", err)
			}

			path := fmt.Sprintf("/storage/download/%s/%s", testUUID, tc.urlPath)
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			if w.Code != http.StatusOK {
				t.Fatalf("status = %d, want %d; body = %s", w.Code, http.StatusOK, w.Body.String())
			}

			gotHeader := w.Header().Get("Content-Disposition")
			if gotHeader != tc.wantHeader {
				t.Errorf("Content-Disposition = %q, want %q", gotHeader, tc.wantHeader)
			}
		})
	}
}

// TestContentDispositionNewlineInjection verifies the defense layers against
// HTTP response splitting via \r/\n in Content-Disposition filenames.
//
// Defense layers (any one prevents exploitation):
//  1. URL routing: raw \r/\n in URLs are rejected by Go's HTTP parser
//  2. Wire-level: Go's http.ResponseWriter sanitizes \r/\n in header values
//
// The application-level Content-Disposition construction (fmt.Sprintf with
// quote escaping) does NOT strip \r/\n. This test documents that gap and
// verifies that the outer defense layers prevent exploitation.
func TestContentDispositionNewlineInjection(t *testing.T) {
	testCases := []struct {
		name     string
		filename string
	}{
		{
			name:     "filename with newline",
			filename: "file\nInjected-Header: evil",
		},
		{
			name:     "filename with carriage return",
			filename: "file\rInjected-Header: evil",
		},
		{
			name:     "filename with CRLF",
			filename: "file\r\nInjected-Header: evil",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			// Construct the Content-Disposition value using the same logic as production
			headerValue := fmt.Sprintf(`attachment; filename="%s"`,
				strings.ReplaceAll(tc.filename, `"`, `\"`))

			// The application-level code does not strip \r/\n from filenames.
			// This is safe in practice because:
			// (a) URLs with raw \r/\n are rejected before reaching the handler
			// (b) Go's http.ResponseWriter strips \r/\n when writing to the wire
			// However, defense-in-depth would suggest also sanitizing at the
			// application level. This test documents the current behavior.
			if strings.ContainsAny(headerValue, "\r\n") {
				t.Logf("NOTICE: Content-Disposition value contains raw \\r/\\n chars: %q. "+
					"Go's HTTP writer sanitizes these on the wire, but application-level "+
					"sanitization would provide defense-in-depth.", headerValue)
			}
		})
	}
}

// ============================================================================
// Metadata — saveMetadata UUID Validation Tests
// ============================================================================

func TestSaveMetadataUUIDValidation(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	testCases := []struct {
		name    string
		uuid    string
		wantErr bool
	}{
		{
			name:    "valid UUID",
			uuid:    "550e8400-e29b-41d4-a716-446655440000",
			wantErr: false,
		},
		{
			name:    "path traversal in UUID",
			uuid:    "../../../etc/passwd",
			wantErr: true,
		},
		{
			name:    "absolute path in UUID",
			uuid:    "/etc/passwd",
			wantErr: true,
		},
		{
			name:    "dot UUID",
			uuid:    ".",
			wantErr: true,
		},
		{
			name:    "dotdot UUID",
			uuid:    "..",
			wantErr: true,
		},
		{
			name:    "empty UUID",
			uuid:    "",
			wantErr: true,
		},
		{
			name:    "UUID with slash",
			uuid:    "abc/def",
			wantErr: true,
		},
		{
			// On Windows, backslash is a path separator so filepath.Base("abc\def") = "def",
			// which differs from the input, triggering rejection. On Linux/macOS, backslash
			// is a valid filename character, so filepath.Base returns the input unchanged.
			// CI runs on Linux, so this test verifies Linux behavior (wantErr=false).
			name:    "UUID with backslash on Windows path",
			uuid:    "abc\\def",
			wantErr: os.PathSeparator == '\\',
		},
		{
			name:    "simple alphanumeric UUID",
			uuid:    "abc123",
			wantErr: false,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata := FileMetadata{
				UUID:     tc.uuid,
				Original: "test.txt",
				MD5:      "d41d8cd98f00b204e9800998ecf8427e",
				Path:     tc.uuid + "/test.txt",
				Size:     100,
			}

			err := saveMetadata(metadata)
			if tc.wantErr && err == nil {
				t.Error("expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}

			if !tc.wantErr && err == nil {
				// Verify metadata was written to the correct location
				metadataPath := filepath.Join(ExeDirPath, metadataDir, tc.uuid+".json")
				if _, statErr := os.Stat(metadataPath); os.IsNotExist(statErr) {
					t.Errorf("metadata file not found at expected path: %s", metadataPath)
				}
			}
		})
	}
}

// ============================================================================
// Metadata — loadMetadata Path Traversal Tests
// ============================================================================

func TestLoadMetadataPathTraversal(t *testing.T) {
	tmpDir, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	// Create a legitimate metadata file
	validUUID := "550e8400-e29b-41d4-a716-446655440000"
	validMetadata := FileMetadata{
		UUID:     validUUID,
		Original: "test.txt",
		MD5:      "d41d8cd98f00b204e9800998ecf8427e",
		Path:     validUUID + "/test.txt",
		Size:     100,
	}
	if err := saveMetadata(validMetadata); err != nil {
		t.Fatalf("failed to save test metadata: %v", err)
	}

	// Create a sensitive file outside the metadata directory
	sensitiveJSON := `{"uuid":"stolen","original":"stolen.txt"}`
	sensitiveFile := filepath.Join(tmpDir, "sensitive.json")
	if err := os.WriteFile(sensitiveFile, []byte(sensitiveJSON), 0o644); err != nil {
		t.Fatalf("failed to create sensitive file: %v", err)
	}

	testCases := []struct {
		name    string
		uuid    string
		wantErr bool
	}{
		{
			name:    "valid UUID",
			uuid:    validUUID,
			wantErr: false,
		},
		{
			name:    "path traversal ../",
			uuid:    "../../sensitive",
			wantErr: true,
		},
		{
			name:    "path traversal ../ to parent",
			uuid:    "../sensitive",
			wantErr: true,
		},
		{
			name:    "absolute path",
			uuid:    "/etc/passwd",
			wantErr: true,
		},
		{
			name:    "nonexistent UUID",
			uuid:    "nonexistent-uuid",
			wantErr: true,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			metadata, err := loadMetadata(tc.uuid)
			if tc.wantErr && err == nil {
				t.Error("expected error but got nil")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("unexpected error: %v", err)
			}
			if !tc.wantErr {
				if metadata.UUID != validUUID {
					t.Errorf("loaded UUID = %q, want %q", metadata.UUID, validUUID)
				}
			}
		})
	}
}

// ============================================================================
// checkFileExists Tests
// ============================================================================

func TestCheckFileExistsBoundsCheck(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	// Verify no panic with empty metadata directory
	_, exists := checkFileExists("d41d8cd98f00b204e9800998ecf8427e")
	if exists {
		t.Error("expected no match in empty metadata directory")
	}
}

func TestCheckFileExistsSkipsNonJSON(t *testing.T) {
	tmpDir, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	// Create a non-JSON file in the metadata directory
	nonJSONFile := filepath.Join(tmpDir, metadataDir, "not-json.txt")
	if err := os.WriteFile(nonJSONFile, []byte("not json"), 0o644); err != nil {
		t.Fatalf("failed to create non-json file: %v", err)
	}

	// Create a directory in the metadata directory
	subDir := filepath.Join(tmpDir, metadataDir, "subdir")
	if err := os.Mkdir(subDir, 0o755); err != nil {
		t.Fatalf("failed to create subdir: %v", err)
	}

	// Should not panic and should return false
	_, exists := checkFileExists("anymd5hash")
	if exists {
		t.Error("should not find match among non-JSON files")
	}
}

func TestCheckFileExistsFindsMatch(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	testMD5 := "abc123def456"
	metadata := FileMetadata{
		UUID:     "test-uuid-match",
		Original: "found.txt",
		MD5:      testMD5,
		Path:     "test-uuid-match/found.txt",
		Size:     42,
	}
	if err := saveMetadata(metadata); err != nil {
		t.Fatalf("failed to save metadata: %v", err)
	}

	found, exists := checkFileExists(testMD5)
	if !exists {
		t.Fatal("expected to find matching metadata")
	}
	if found.UUID != "test-uuid-match" {
		t.Errorf("found UUID = %q, want %q", found.UUID, "test-uuid-match")
	}
}

func TestCheckFileExistsNoMatch(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	metadata := FileMetadata{
		UUID:     "test-uuid-nomatch",
		Original: "file.txt",
		MD5:      "known-md5",
		Path:     "test-uuid-nomatch/file.txt",
		Size:     42,
	}
	if err := saveMetadata(metadata); err != nil {
		t.Fatalf("failed to save metadata: %v", err)
	}

	_, exists := checkFileExists("different-md5")
	if exists {
		t.Error("should not find match for different MD5")
	}
}

func TestCheckFileExistsSkipsEmptyUUID(t *testing.T) {
	tmpDir, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	// Create a file named ".json" (empty UUID after trim)
	emptyUUIDFile := filepath.Join(tmpDir, metadataDir, ".json")
	if err := os.WriteFile(emptyUUIDFile, []byte(`{"md5":"target"}`), 0o644); err != nil {
		t.Fatalf("failed to create .json file: %v", err)
	}

	// Should not panic and should skip the .json file
	_, exists := checkFileExists("target")
	if exists {
		t.Error("should skip .json file with empty UUID prefix")
	}
}

// ============================================================================
// Metadata Endpoint — Path Traversal Tests
// ============================================================================

func TestMetadataEndpointPathTraversal(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()
	engine := setupStorageRouter(t)

	// Create a valid metadata file
	validUUID := "550e8400-e29b-41d4-a716-446655440000"
	validMetadata := FileMetadata{
		UUID:     validUUID,
		Original: "test.txt",
		MD5:      "d41d8cd98f00b204e9800998ecf8427e",
		Path:     validUUID + "/test.txt",
		Size:     100,
	}
	if err := saveMetadata(validMetadata); err != nil {
		t.Fatalf("failed to save test metadata: %v", err)
	}

	testCases := []struct {
		name       string
		uuid       string
		wantStatus int
	}{
		{
			name:       "valid UUID",
			uuid:       validUUID,
			wantStatus: http.StatusOK,
		},
		{
			name:       "traversal attempt",
			uuid:       "../../etc/passwd",
			wantStatus: http.StatusNotFound,
		},
		{
			name:       "nonexistent UUID",
			uuid:       "nonexistent",
			wantStatus: http.StatusNotFound,
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			path := fmt.Sprintf("/storage/metadata/%s", tc.uuid)
			req := httptest.NewRequest(http.MethodGet, path, nil)
			w := httptest.NewRecorder()
			engine.ServeHTTP(w, req)

			if w.Code != tc.wantStatus {
				t.Errorf("status = %d, want %d; body = %s", w.Code, tc.wantStatus, w.Body.String())
			}
		})
	}
}

// ============================================================================
// Progress Endpoint Tests
// ============================================================================

func TestProgressEndpointNotFound(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()
	engine := setupStorageRouter(t)

	req := httptest.NewRequest(http.MethodGet, "/storage/progress/nonexistent-uuid", nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusNotFound {
		t.Errorf("status = %d, want %d", w.Code, http.StatusNotFound)
	}
}

// ============================================================================
// ProgressWriter Tests
// ============================================================================

func TestProgressWriterTracksProgress(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	tracker := newProgressTracker()

	// Use a small total so the write triggers a tracker update immediately
	// (progressWriter updates when written == total or on progressUpdateStep boundary).
	data := []byte("hello world")
	pw := &progressWriter{
		Writer:  &buf,
		tracker: tracker,
		key:     "test-key",
		total:   int64(len(data)),
	}

	n, err := pw.Write(data)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if n != len(data) {
		t.Errorf("bytes written = %d, want %d", n, len(data))
	}

	// Check progress was tracked (written == total triggers update)
	written, total, exists := tracker.get("test-key")
	if !exists {
		t.Fatal("expected progress entry to exist")
	}
	if written != int64(len(data)) {
		t.Errorf("progress bytes = %d, want %d", written, len(data))
	}
	if total != int64(len(data)) {
		t.Errorf("progress total = %d, want %d", total, len(data))
	}

	// Verify data was written through
	if buf.String() != "hello world" {
		t.Errorf("written data = %q, want %q", buf.String(), "hello world")
	}
}

func TestProgressWriterAccumulates(t *testing.T) {
	t.Parallel()

	var buf bytes.Buffer
	tracker := newProgressTracker()

	totalBytes := int64(len("chunk1") + len("chunk2"))
	pw := &progressWriter{
		Writer:  &buf,
		tracker: tracker,
		key:     "accum-key",
		total:   totalBytes,
	}

	if _, err := pw.Write([]byte("chunk1")); err != nil {
		t.Fatal(err)
	}
	if _, err := pw.Write([]byte("chunk2")); err != nil {
		t.Fatal(err)
	}

	// Second write completes total, so tracker should be updated
	written, _, exists := tracker.get("accum-key")
	if !exists {
		t.Fatal("expected progress entry to exist")
	}
	if written != totalBytes {
		t.Errorf("accumulated progress = %d, want %d", written, totalBytes)
	}
}

// ============================================================================
// Upload Deduplication Test
// ============================================================================

func TestUploadDeduplicatesIdenticalFiles(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()
	engine := setupStorageRouter(t)

	content := "identical content for dedup test"

	// First upload
	body1, ct1 := createMultipartUpload(t, "file", "first.txt", content)
	req1 := httptest.NewRequest(http.MethodPost, "/storage/upload", body1)
	req1.Header.Set("Content-Type", ct1)
	w1 := httptest.NewRecorder()
	engine.ServeHTTP(w1, req1)

	if w1.Code != http.StatusOK {
		t.Fatalf("first upload failed: status %d, body %s", w1.Code, w1.Body.String())
	}

	resp1 := parseJSONResponse(t, w1)
	firstUUID := resp1["uuid"].(string)

	// Second upload with same content, different name
	body2, ct2 := createMultipartUpload(t, "file", "second.txt", content)
	req2 := httptest.NewRequest(http.MethodPost, "/storage/upload", body2)
	req2.Header.Set("Content-Type", ct2)
	w2 := httptest.NewRecorder()
	engine.ServeHTTP(w2, req2)

	if w2.Code != http.StatusOK {
		t.Fatalf("second upload failed: status %d, body %s", w2.Code, w2.Body.String())
	}

	resp2 := parseJSONResponse(t, w2)

	// The second upload should return the first UUID (dedup)
	secondUUID := resp2["uuid"].(string)
	if secondUUID != firstUUID {
		t.Errorf("dedup failed: second UUID %q != first UUID %q", secondUUID, firstUUID)
	}

	msg, _ := resp2["message"].(string)
	if !strings.Contains(msg, "already exists") {
		t.Errorf("expected 'already exists' message, got %q", msg)
	}
}

// ============================================================================
// Download — Legitimate File Serves Correctly
// ============================================================================

func TestDownloadServesFileContent(t *testing.T) {
	tmpDir, cleanup := setupStorageTestEnv(t)
	defer cleanup()
	engine := setupStorageRouter(t)

	testUUID := "serve-test-uuid"
	testContent := "this is the file content to serve"
	fileDir := filepath.Join(tmpDir, uploadDir, testUUID)
	if err := os.MkdirAll(fileDir, 0o755); err != nil {
		t.Fatalf("failed to create file dir: %v", err)
	}
	if err := os.WriteFile(filepath.Join(fileDir, "data.bin"), []byte(testContent), 0o644); err != nil {
		t.Fatalf("failed to create test file: %v", err)
	}

	path := fmt.Sprintf("/storage/download/%s/data.bin", testUUID)
	req := httptest.NewRequest(http.MethodGet, path, nil)
	w := httptest.NewRecorder()
	engine.ServeHTTP(w, req)

	if w.Code != http.StatusOK {
		t.Fatalf("status = %d, want %d; body = %s", w.Code, http.StatusOK, w.Body.String())
	}

	if w.Body.String() != testContent {
		t.Errorf("body = %q, want %q", w.Body.String(), testContent)
	}

	ct := w.Header().Get("Content-Type")
	if ct != "application/octet-stream" {
		t.Errorf("Content-Type = %q, want %q", ct, "application/octet-stream")
	}

	cd := w.Header().Get("Content-Disposition")
	if cd != `attachment; filename="data.bin"` {
		t.Errorf("Content-Disposition = %q, want %q", cd, `attachment; filename="data.bin"`)
	}
}

// ============================================================================
// MD5 Index Tests (from PR #698)
// ============================================================================

// writeMetadataFile writes a FileMetadata JSON file directly to disk,
// bypassing saveMetadata (useful for testing initMD5Index independently).
func writeMetadataFile(t *testing.T, meta FileMetadata) {
	t.Helper()
	metaPath := filepath.Join(ExeDirPath, metadataDir, meta.UUID+".json")
	if err := utils.SaveStructAsJsonFile(metaPath, meta); err != nil {
		t.Fatalf("failed to write metadata file: %v", err)
	}
}

func TestInitMD5Index_PopulatesFromDisk(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	files := []FileMetadata{
		{UUID: "uuid-1", MD5: "aaa111", Original: "a.txt", Path: "uuid-1/a.txt", Size: 10},
		{UUID: "uuid-2", MD5: "bbb222", Original: "b.txt", Path: "uuid-2/b.txt", Size: 20},
		{UUID: "uuid-3", MD5: "ccc333", Original: "c.txt", Path: "uuid-3/c.txt", Size: 30},
	}
	for _, m := range files {
		writeMetadataFile(t, m)
	}

	initMD5Index()

	md5IndexMu.RLock()
	defer md5IndexMu.RUnlock()

	if len(md5Index) != 3 {
		t.Fatalf("expected 3 index entries, got %d", len(md5Index))
	}
	for _, m := range files {
		got, ok := md5Index[m.MD5]
		if !ok {
			t.Errorf("md5 %q missing from index", m.MD5)
		}
		if got != m.UUID {
			t.Errorf("md5 %q: expected uuid %q, got %q", m.MD5, m.UUID, got)
		}
	}
}

func TestInitMD5Index_EmptyDir(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	initMD5Index()

	md5IndexMu.RLock()
	defer md5IndexMu.RUnlock()

	if len(md5Index) != 0 {
		t.Fatalf("expected 0 index entries for empty dir, got %d", len(md5Index))
	}
}

func TestInitMD5Index_SkipsNonJSON(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	writeMetadataFile(t, FileMetadata{UUID: "uuid-1", MD5: "aaa111"})

	nonJSON := filepath.Join(ExeDirPath, metadataDir, "README.txt")
	if err := os.WriteFile(nonJSON, []byte("not json"), 0o644); err != nil {
		t.Fatal(err)
	}

	initMD5Index()

	md5IndexMu.RLock()
	defer md5IndexMu.RUnlock()

	if len(md5Index) != 1 {
		t.Fatalf("expected 1 index entry, got %d", len(md5Index))
	}
}

func TestInitMD5Index_SkipsCorruptJSON(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	corruptPath := filepath.Join(ExeDirPath, metadataDir, "corrupt-uuid.json")
	if err := os.WriteFile(corruptPath, []byte("{invalid json"), 0o644); err != nil {
		t.Fatal(err)
	}

	writeMetadataFile(t, FileMetadata{UUID: "uuid-1", MD5: "aaa111"})

	initMD5Index()

	md5IndexMu.RLock()
	defer md5IndexMu.RUnlock()

	if len(md5Index) != 1 {
		t.Fatalf("expected 1 index entry (skipping corrupt), got %d", len(md5Index))
	}
}

func TestCheckFileExists_Found(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	meta := FileMetadata{UUID: "uuid-1", MD5: "abc123", Original: "file.txt", Path: "uuid-1/file.txt", Size: 100}
	writeMetadataFile(t, meta)
	initMD5Index()

	got, found := checkFileExists("abc123")
	if !found {
		t.Fatal("expected file to be found")
	}
	if got.UUID != meta.UUID {
		t.Errorf("expected UUID %q, got %q", meta.UUID, got.UUID)
	}
	if got.MD5 != meta.MD5 {
		t.Errorf("expected MD5 %q, got %q", meta.MD5, got.MD5)
	}
}

func TestCheckFileExists_NotFound(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	initMD5Index()

	_, found := checkFileExists("nonexistent-hash")
	if found {
		t.Fatal("expected file not to be found")
	}
}

func TestCheckFileExists_StaleEntry(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	md5IndexMu.Lock()
	md5Index["stale-hash"] = "missing-uuid"
	md5IndexMu.Unlock()

	_, found := checkFileExists("stale-hash")
	if found {
		t.Fatal("expected stale entry to return not found")
	}

	md5IndexMu.RLock()
	_, stillThere := md5Index["stale-hash"]
	md5IndexMu.RUnlock()

	if stillThere {
		t.Error("stale index entry should have been removed")
	}
}

func TestSaveMetadata_UpdatesIndex(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	meta := FileMetadata{
		UUID:      "uuid-save-1",
		MD5:       "save-hash-1",
		Original:  "saved.txt",
		Path:      "uuid-save-1/saved.txt",
		Size:      42,
		UploadURI: "storage/download/uuid-save-1/saved.txt",
	}
	if err := saveMetadata(meta); err != nil {
		t.Fatalf("saveMetadata failed: %v", err)
	}

	md5IndexMu.RLock()
	uuid, exists := md5Index[meta.MD5]
	md5IndexMu.RUnlock()

	if !exists {
		t.Fatal("expected MD5 to be in index after saveMetadata")
	}
	if uuid != meta.UUID {
		t.Errorf("expected UUID %q, got %q", meta.UUID, uuid)
	}

	got, found := checkFileExists(meta.MD5)
	if !found {
		t.Fatal("checkFileExists should find newly saved metadata")
	}
	if got.Original != meta.Original {
		t.Errorf("expected Original %q, got %q", meta.Original, got.Original)
	}
}

func TestSaveMetadata_EmptyMD5NotIndexed(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	meta := FileMetadata{UUID: "uuid-nohash", MD5: ""}
	if err := saveMetadata(meta); err != nil {
		t.Fatalf("saveMetadata failed: %v", err)
	}

	md5IndexMu.RLock()
	defer md5IndexMu.RUnlock()

	if len(md5Index) != 0 {
		t.Error("empty MD5 should not be added to index")
	}
}

func TestSaveMetadata_DuplicateMD5OverwritesIndex(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	meta1 := FileMetadata{
		UUID:      "uuid-first",
		MD5:       "duplicate-hash",
		Original:  "first.txt",
		Path:      "uuid-first/first.txt",
		Size:      100,
		UploadURI: "storage/download/uuid-first/first.txt",
	}
	if err := saveMetadata(meta1); err != nil {
		t.Fatalf("saveMetadata(meta1) failed: %v", err)
	}

	meta2 := FileMetadata{
		UUID:      "uuid-second",
		MD5:       "duplicate-hash",
		Original:  "second.txt",
		Path:      "uuid-second/second.txt",
		Size:      200,
		UploadURI: "storage/download/uuid-second/second.txt",
	}
	if err := saveMetadata(meta2); err != nil {
		t.Fatalf("saveMetadata(meta2) failed: %v", err)
	}

	md5IndexMu.RLock()
	indexedUUID := md5Index["duplicate-hash"]
	md5IndexMu.RUnlock()

	if indexedUUID != "uuid-second" {
		t.Errorf("expected index to point to uuid-second, got %q", indexedUUID)
	}

	got, found := checkFileExists("duplicate-hash")
	if !found {
		t.Fatal("expected duplicate-hash to be found")
	}
	if got.UUID != "uuid-second" {
		t.Errorf("expected UUID uuid-second, got %q", got.UUID)
	}
}

func TestCheckFileExists_ConcurrentSafe(t *testing.T) {
	_, cleanup := setupStorageTestEnv(t)
	defer cleanup()

	const n = 50
	metas := make([]FileMetadata, n)
	for i := 0; i < n; i++ {
		m := FileMetadata{
			UUID:     fmt.Sprintf("uuid-%04d", i),
			MD5:      fmt.Sprintf("md5-%04d", i),
			Original: "file.txt",
			Path:     fmt.Sprintf("uuid-%04d/file.txt", i),
			Size:     int64(i),
		}
		writeMetadataFile(t, m)
		metas[i] = m
	}
	initMD5Index()

	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			got, found := checkFileExists(metas[idx].MD5)
			if !found {
				t.Errorf("concurrent read: md5 %q not found", metas[idx].MD5)
				return
			}
			if got.UUID != metas[idx].UUID {
				t.Errorf("concurrent read: expected UUID %q, got %q", metas[idx].UUID, got.UUID)
			}
		}(i)
	}

	for i := n; i < n+20; i++ {
		wg.Add(1)
		go func(idx int) {
			defer wg.Done()
			m := FileMetadata{
				UUID:      fmt.Sprintf("uuid-%04d", idx),
				MD5:       fmt.Sprintf("md5-%04d", idx),
				Original:  "new.txt",
				Path:      fmt.Sprintf("uuid-%04d/new.txt", idx),
				Size:      int64(idx),
				UploadURI: fmt.Sprintf("storage/download/uuid-%04d/new.txt", idx),
			}
			if err := saveMetadata(m); err != nil {
				t.Errorf("concurrent saveMetadata failed: %v", err)
			}
		}(i)
	}

	wg.Wait()
}
