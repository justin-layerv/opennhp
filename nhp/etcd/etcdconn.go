package etcd

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"errors"
	"os"
	"time"

	clientv3 "go.etcd.io/etcd/client/v3"

	"github.com/OpenNHP/opennhp/nhp/log"
)

type EtcdConfig struct {
	Key       string
	Endpoints []string
	Username  string
	Password  string
}

type EtcdConn struct {
	Endpoints  []string
	Username   string
	Password   string
	Key        string
	TLS        bool
	CACert     string
	ClientCert string
	ClientKey  string
	client     *clientv3.Client
	ctx        context.Context
	watcher    clientv3.Watcher
	signals    struct {
		stop chan struct{}
	}
}

func (conn *EtcdConn) InitClient() error {
	var err error

	cfg := clientv3.Config{
		Endpoints:   conn.Endpoints,
		DialTimeout: 5 * time.Second,
		Username:    conn.Username,
		Password:    conn.Password,
	}

	// Configure TLS if enabled
	if conn.TLS {
		tlsConfig, err := conn.loadTLSConfig()
		if err != nil {
			return err
		}
		cfg.TLS = tlsConfig
	}

	conn.client, err = clientv3.New(cfg)

	conn.Key = "/" + conn.Key
	if err != nil {
		return err
	}

	// Use background context for connection lifetime
	conn.ctx = context.Background()

	// Verify connectivity with a timeout
	statusCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_, err = conn.client.Status(statusCtx, conn.Endpoints[0])
	if err != nil {
		return err
	}
	return nil
}

func (conn *EtcdConn) GetValue() ([]byte, error) {
	if conn.client == nil {
		return nil, errors.New("etcd client not initialized")
	}
	val, err := conn.client.Get(conn.ctx, conn.Key)
	if err != nil {
		return nil, err
	}

	if len(val.Kvs) == 0 {
		return nil, errors.New("key not found")
	}
	if len(val.Kvs[0].Value) == 0 {
		return nil, errors.New("value not set")
	}
	return val.Kvs[0].Value, nil
}

func (conn *EtcdConn) SetValue(v string) error {
	_, err := conn.client.Put(conn.ctx, conn.Key, v)
	return err
}

func (conn *EtcdConn) WatchValue(callbackFunc func(val []byte)) {
	// create etcd watcher
	conn.watcher = clientv3.NewWatcher(conn.client)

	watchChan := conn.watcher.Watch(context.Background(), conn.Key)

	for {
		select {
		case resp := <-watchChan:
			// handle change events
			for _, ev := range resp.Events {
				switch ev.Type {
				case clientv3.EventTypePut:
					callbackFunc(ev.Kv.Value)
				case clientv3.EventTypeDelete:
					log.Debug("[DELETE] Key: %s\n", string(ev.Kv.Key))
				}
			}
		case <-conn.signals.stop:
			_ = conn.watcher.Close()
			return
		}
	}

}

func (conn *EtcdConn) Close() {
	if conn.client != nil {
		// stop the etcd watcher (only if it was initialized)
		if conn.signals.stop != nil {
			close(conn.signals.stop)
		}
		_ = conn.client.Close()
	}
}

// Client returns the underlying etcd client for direct operations.
// This is primarily used for health checks.
func (conn *EtcdConn) Client() *clientv3.Client {
	return conn.client
}

// GetPrefix retrieves all key-value pairs with the given prefix
func (conn *EtcdConn) GetPrefix(prefix string) (map[string][]byte, error) {
	if conn.client == nil {
		return nil, errors.New("etcd client not initialized")
	}
	resp, err := conn.client.Get(conn.ctx, prefix, clientv3.WithPrefix())
	if err != nil {
		return nil, err
	}

	result := make(map[string][]byte)
	for _, kv := range resp.Kvs {
		result[string(kv.Key)] = kv.Value
	}
	return result, nil
}

// WatchPrefixCallbacks defines callbacks for prefix watching
type WatchPrefixCallbacks struct {
	OnPut    func(key string, value []byte)
	OnDelete func(key string)
}

// WatchPrefix watches all keys with the given prefix for changes
// This is used for dynamic AC registry watching
func (conn *EtcdConn) WatchPrefix(prefix string, callbacks WatchPrefixCallbacks) {
	if conn.client == nil {
		log.Error("etcd client not initialized, cannot watch prefix")
		return
	}
	watcher := clientv3.NewWatcher(conn.client)

	watchChan := watcher.Watch(context.Background(), prefix, clientv3.WithPrefix())

	for {
		select {
		case resp := <-watchChan:
			for _, ev := range resp.Events {
				key := string(ev.Kv.Key)
				switch ev.Type {
				case clientv3.EventTypePut:
					if callbacks.OnPut != nil {
						callbacks.OnPut(key, ev.Kv.Value)
					}
				case clientv3.EventTypeDelete:
					if callbacks.OnDelete != nil {
						callbacks.OnDelete(key)
					}
				}
			}
		case <-conn.signals.stop:
			_ = watcher.Close()
			return
		}
	}
}

// loadTLSConfig creates a TLS configuration for etcd mTLS
func (conn *EtcdConn) loadTLSConfig() (*tls.Config, error) {
	tlsConfig := &tls.Config{
		MinVersion: tls.VersionTLS12,
	}

	// Load CA certificate if provided
	if conn.CACert != "" {
		caCert, err := os.ReadFile(conn.CACert)
		if err != nil {
			return nil, errors.New("failed to read CA certificate: " + err.Error())
		}
		caCertPool := x509.NewCertPool()
		if !caCertPool.AppendCertsFromPEM(caCert) {
			return nil, errors.New("failed to parse CA certificate")
		}
		tlsConfig.RootCAs = caCertPool
		log.Info("etcd TLS: loaded CA certificate from %s", conn.CACert)
	}

	// Load client certificate and key if provided (for mTLS)
	if conn.ClientCert != "" && conn.ClientKey != "" {
		cert, err := tls.LoadX509KeyPair(conn.ClientCert, conn.ClientKey)
		if err != nil {
			return nil, errors.New("failed to load client certificate: " + err.Error())
		}
		tlsConfig.Certificates = []tls.Certificate{cert}
		log.Info("etcd TLS: loaded client certificate from %s", conn.ClientCert)
	}

	return tlsConfig, nil
}
