package db

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/OpenNHP/opennhp/nhp/common"
	"github.com/OpenNHP/opennhp/nhp/core"
	ztdolib "github.com/OpenNHP/opennhp/nhp/core/ztdo"
	"github.com/OpenNHP/opennhp/nhp/log"
	"github.com/OpenNHP/opennhp/nhp/utils"
)

type DataPrivateKeyStore struct {
	DataPrivateKeyBase64    string `json:"dataPrivateKeyBase64"`
	ProviderPublicKeyBase64 string `json:"providerPublicKeyBase64"`
}

// NewDataPrivateKeyStore create a new DataPrivateKeyStore
func NewDataPrivateKeyStore(providerPublicKeyBase64 string) *DataPrivateKeyStore {
	return &DataPrivateKeyStore{
		ProviderPublicKeyBase64: providerPublicKeyBase64,
	}
}

// NewDataPrivateKeyStoreWith create a new DataPrivateKeyStore with doId.
//
// Defense-in-depth #1161: doId arrives on the wire via DWRMsg.DoId and
// is concatenated into a filesystem path below. ReadZdtoConfig (called
// from HandleDHPDAVMessage) already validates before forwarding, but
// this is the boundary that actually builds the path — a new caller
// forgetting to validate would reopen the traversal sink here.
// Validate at the boundary.
//
// Non-validation errors collapse to common.ErrDataPrivateKeyStore so a
// new caller that forgets to re-wrap (like udpdevice.go:904 already
// does) can't leak os.Open's *PathError — the raw cause is kept in
// the server log.
func NewDataPrivateKeyStoreWith(doId string) (d *DataPrivateKeyStore, err error) {
	if err := common.ValidateDoID(doId); err != nil {
		log.Warning("db[NewDataPrivateKeyStoreWith] rejected DoId=%q: %v", doId, err)
		return nil, err
	}

	etcDir := filepath.Join(common.ExeDirPath, "etc", "ztdo")
	fileName := "data-key-" + doId + ".json"
	fullPath := filepath.Join(etcDir, fileName)

	// open and read all the content in file
	file, err := os.Open(fullPath)
	if err != nil {
		log.Error("db[NewDataPrivateKeyStoreWith] DoId=%q open: %v", doId, err)
		return nil, common.ErrDataPrivateKeyStore
	}
	defer func() { _ = file.Close() }()

	fileContentByte, err := io.ReadAll(file)
	if err != nil {
		log.Error("db[NewDataPrivateKeyStoreWith] DoId=%q read: %v", doId, err)
		return nil, common.ErrDataPrivateKeyStore
	}

	d = &DataPrivateKeyStore{}
	if err := d.fromJson(fileContentByte); err != nil {
		log.Error("db[NewDataPrivateKeyStoreWith] DoId=%q unmarshal: %v", doId, err)
		return nil, common.ErrDataPrivateKeyStore
	}

	return
}

func (d *DataPrivateKeyStore) Generate(mode ztdolib.DataKeyPairECCMode) ([]byte, error) {
	ecdh, err := core.NewECDH(mode.ToEccType())
	if err != nil {
		return nil, fmt.Errorf("failed to generate ECDH key pair: %w", err)
	}
	d.DataPrivateKeyBase64 = ecdh.PrivateKeyBase64()
	return ecdh.PrivateKey(), nil
}

// Save saves the dataPrivateKeyBase64 to a file, the format of file name is data-<doId>.json
// Notes: this default way to store data private key is not safe. In the wild environment, need to use a secure way to store data private key.
//
// Defense-in-depth #1161: see NewDataPrivateKeyStoreWith for the
// rationale. Validate at the boundary so a new caller can't reopen
// the traversal sink, and collapse non-validation errors to
// common.ErrDataPrivateKeyStore so filesystem paths can't leak.
func (d *DataPrivateKeyStore) Save(doId string) error {
	if err := common.ValidateDoID(doId); err != nil {
		log.Warning("db[DataPrivateKeyStore.Save] rejected DoId=%q: %v", doId, err)
		return err
	}

	// Make sure the etc directory exists. MkdirAll runs against the
	// absolute ztdo path — before #1161 this used the bare relative
	// "etc/ztdo" against CWD while os.Create below used the absolute
	// path, so Save only worked when something else had already
	// created <ExeDirPath>/etc/ztdo first (server.SaveZdtoConfig did
	// in practice).
	etcDir := filepath.Join(common.ExeDirPath, "etc", "ztdo")
	if err := os.MkdirAll(etcDir, 0755); err != nil {
		log.Error("db[DataPrivateKeyStore.Save] DoId=%q mkdir: %v", doId, err)
		return common.ErrDataPrivateKeyStore
	}

	fileName := "data-key-" + doId + ".json"
	fullPath := filepath.Join(etcDir, fileName)
	if _, err := os.Stat(fullPath); err == nil {
		log.Error("db[DataPrivateKeyStore.Save] DoId=%q already exists at %s", doId, fullPath)
		return common.ErrDataPrivateKeyStore
	}

	file, err := os.Create(fullPath)
	if err != nil {
		log.Error("db[DataPrivateKeyStore.Save] DoId=%q create: %v", doId, err)
		return common.ErrDataPrivateKeyStore
	}
	defer func() { _ = file.Close() }()

	if _, err := file.Write(d.toJson()); err != nil {
		log.Error("db[DataPrivateKeyStore.Save] DoId=%q write: %v", doId, err)
		return common.ErrDataPrivateKeyStore
	}

	return nil
}

// Defense-in-depth #1161: see NewDataPrivateKeyStoreWith.
func (d *DataPrivateKeyStore) Delete(doId string) error {
	if err := common.ValidateDoID(doId); err != nil {
		log.Warning("db[DataPrivateKeyStore.Delete] rejected DoId=%q: %v", doId, err)
		return err
	}

	etcDir := filepath.Join(common.ExeDirPath, "etc", "ztdo")
	fileName := "data-key-" + doId + ".json"
	fullPath := filepath.Join(etcDir, fileName)

	// delete the file
	if err := os.Remove(fullPath); err != nil {
		log.Error("db[DataPrivateKeyStore.Delete] DoId=%q remove: %v", doId, err)
		return common.ErrDataPrivateKeyStore
	}
	return nil
}

func (d *DataPrivateKeyStore) toJson() []byte {
	dataPrkStoreJson, err := json.Marshal(d)
	if err != nil {
		return []byte("{}")
	} else {
		return dataPrkStoreJson
	}
}

func (d *DataPrivateKeyStore) fromJson(jsonData []byte) error {
	err := json.Unmarshal(jsonData, d)
	if err != nil {
		return fmt.Errorf("json parsing error: %w", err)
	}
	return nil
}

type AppParams struct {
	Mode                    string // the mode of operation: none, encrypt and decrypt
	Source                  string // the path of plaintext data
	DsType                  string // the type of data source: stream, online and offline
	Output                  string // path of output file
	SmartPolicy             string // path of smart policy
	Metadata                string // path of metadata
	ZtdoFilePath            string // path of ztdo file when mode is decrypt
	ZtdoId                  string // identifier of ztdo file
	DataPrivateKeyBase64    string
	AccessUrl               string // path of access url of ztdo
	ProviderPublicKeyBase64 string
}

func (a *AppParams) NewSmartPolicy() (common.SmartPolicy, error) {
	file, err := os.Open(a.SmartPolicy)
	if err != nil {
		return common.SmartPolicy{}, fmt.Errorf("could not open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	fileContentByte, err := io.ReadAll(file)
	if err != nil {
		return common.SmartPolicy{}, fmt.Errorf("error reading file: %w", err)
	}

	var config common.SmartPolicy

	err = json.Unmarshal(fileContentByte, &config)
	if err != nil {
		return common.SmartPolicy{}, fmt.Errorf("json parsing error: %w", err)
	}

	spoId, err := utils.GenerateUUIDv4()
	if err != nil {
		return common.SmartPolicy{}, fmt.Errorf("error generating spoId: %w", err)
	}

	config.PolicyId = spoId

	return config, nil
}

func (a *AppParams) GetMetadata() (string, error) {
	if a.Metadata == "" {
		return "", nil
	}

	content, err := os.ReadFile(a.Metadata)
	if err != nil {
		return "", err
	}

	return string(content), nil
}

func (a *AppParams) LoadMetadataAsStruct() (map[string]any, error) {
	var metadata map[string]any

	if a.Metadata == "" {
		return metadata, nil
	}

	content, err := os.ReadFile(a.Metadata)
	if err != nil {
		return metadata, nil
	}

	err = json.Unmarshal(content, &metadata)
	if err != nil {
		return nil, err
	}

	return metadata, nil
}

func (a *UdpDevice) UploadFileToNHPServer(ctx context.Context, filePath string) (string, error) {
	httpHost := fmt.Sprintf("https://%s/", a.GetServerPeer().Host())
	probeReq, err := http.NewRequestWithContext(ctx, http.MethodGet, httpHost, nil)
	if err != nil {
		return "", fmt.Errorf("could not create probe request: %w", err)
	}
	probeClient := &http.Client{Timeout: 5 * time.Second}
	probeResp, err := probeClient.Do(probeReq) //nolint:gosec // G704: host from server peer config (TOML), not user input
	if err != nil {
		if ctx.Err() != nil {
			return "", fmt.Errorf("probe request canceled: %w", ctx.Err())
		}
		log.Warning("[DB] HTTPS probe failed, falling back to HTTP: %v", err)
		httpHost = fmt.Sprintf("http://%s/", a.GetServerPeer().Host())
	} else {
		_ = probeResp.Body.Close()
	}

	file, err := os.Open(filePath)
	if err != nil {
		return "", fmt.Errorf("could not open file: %w", err)
	}
	defer func() { _ = file.Close() }()

	fileInfo, err := file.Stat()
	if err != nil {
		return "", fmt.Errorf("could not get file info: %w", err)
	}

	// create upload progress
	progress := &UploadProgress{
		TotalSize: fileInfo.Size(),
	}

	startTime := time.Now()

	body := &bytes.Buffer{}
	writer := multipart.NewWriter(body)

	part, err := writer.CreateFormFile("file", filepath.Base(filePath))
	if err != nil {
		return "", fmt.Errorf("could not create form file: %w", err)
	}

	progressReader := &ProgressReader{
		Reader:   file,
		Progress: progress,
	}

	_, err = io.Copy(part, progressReader)
	if err != nil {
		return "", fmt.Errorf("could not copy file to server: %w", err)
	}

	err = writer.Close()
	if err != nil {
		return "", fmt.Errorf("could not close writer: %w", err)
	}

	uploadUrl := httpHost + "storage/upload"

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, uploadUrl, body)
	if err != nil {
		return "", fmt.Errorf("could not create request: %w", err)
	}

	req.Header.Set("Content-Type", writer.FormDataContentType())

	client := &http.Client{
		Timeout: 120 * time.Minute,
	}

	resp, err := client.Do(req) //nolint:gosec // G704: URL from server peer config (TOML), not user input
	if err != nil {
		return "", fmt.Errorf("could not send https request: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body)

		return "", fmt.Errorf("unexpected status code: %d, content: %s", resp.StatusCode, string(bodyBytes))
	}

	// read response body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("could not read response body: %w", err)
	}

	// parse response body
	var respBody ServerResponse

	err = json.Unmarshal(bodyBytes, &respBody)
	if err != nil {
		return "", fmt.Errorf("could not parse response body: %w", err)
	}

	duration := time.Since(startTime)
	speed := float64(progress.TotalSize) / duration.Seconds() / (1024 * 1024)

	log.Info("upload completed: src=%s, dst=%s, time=%.2fs, speed=%.2fMB/s",
		filePath, httpHost+respBody.FileURI, duration.Seconds(), speed)

	return httpHost + respBody.FileURI, nil
}

type UploadProgress struct {
	TotalSize   int64
	BytesRead   int64
	UploadID    string
	LastPercent int
}

type ServerResponse struct {
	Message string `json:"message"`
	FileURI string `json:"file_uri"`
	UUID    string `json:"uuid"`
	MD5     string `json:"md5"`
}

type ProgressReader struct {
	Reader   io.Reader
	Progress *UploadProgress
}

func (pr *ProgressReader) Read(p []byte) (n int, err error) {
	n, err = pr.Reader.Read(p)
	if err == nil {
		pr.Progress.BytesRead += int64(n)

		// calculate percent of upload progress
		percent := int(float64(pr.Progress.BytesRead) / float64(pr.Progress.TotalSize) * 100)
		if percent > pr.Progress.LastPercent && percent%5 == 0 {
			pr.Progress.LastPercent = percent
			pr.displayProgress(percent)
		}
	}
	return
}

// displayProgress
func (pr *ProgressReader) displayProgress(percent int) {
	// barLength is the length of progress bar
	const barLength = 50
	completed := int(float64(barLength) * float64(percent) / 100)

	// create progress bar string
	bar := make([]byte, barLength)
	for i := 0; i < barLength; i++ {
		if i < completed {
			bar[i] = '='
		} else if i == completed {
			bar[i] = '>'
		} else {
			bar[i] = ' '
		}
	}

	// calculate uploaded MB and total MB
	uploadedMB := float64(pr.Progress.BytesRead) / (1024 * 1024)
	totalMB := float64(pr.Progress.TotalSize) / (1024 * 1024)

	fmt.Printf("\r[%s] %3d%%  %.2f/%.2f MB",
		string(bar), percent, uploadedMB, totalMB)
}
