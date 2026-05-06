package server

import (
	"encoding/json"
	"net"
	"os"
	"sync/atomic"
	"time"

	"github.com/pion/webrtc/v4"

	"github.com/OpenNHP/opennhp/nhp/core"
	"github.com/OpenNHP/opennhp/nhp/log"
)

// WebRTCConfig holds settings for the optional WebRTC transport.
type WebRTCConfig struct {
	Enable      bool
	OfferFile   string
	AnswerFile  string
	StunServers []string
	TurnServers []string
}

// WebRTCServer bridges a WebRTC DataChannel with the UDP server message pipeline.
type WebRTCServer struct {
	us   *UdpServer
	conf *WebRTCConfig
	pc   *webrtc.PeerConnection
}

func NewWebRTCServer(us *UdpServer, conf *WebRTCConfig) *WebRTCServer {
	return &WebRTCServer{us: us, conf: conf}
}

func (w *WebRTCServer) Start() error {
	if w.conf == nil || !w.conf.Enable {
		return nil
	}

	cfg := webrtc.Configuration{}
	for _, u := range w.conf.StunServers {
		cfg.ICEServers = append(cfg.ICEServers, webrtc.ICEServer{URLs: []string{u}})
	}
	for _, u := range w.conf.TurnServers {
		cfg.ICEServers = append(cfg.ICEServers, webrtc.ICEServer{URLs: []string{u}})
	}

	var err error
	w.pc, err = webrtc.NewPeerConnection(cfg)
	if err != nil {
		return err
	}

	w.pc.OnDataChannel(w.setupDataChannel)

	// if an offer file is provided, perform one-shot signaling using files
	if w.conf.OfferFile != "" {
		if err := w.fileSignaling(); err != nil {
			log.Error("[WebRTC] file signaling failed: %v", err)
		}
	}

	return nil
}

// fileSignaling performs one-shot SDP exchange via offer/answer files.
func (w *WebRTCServer) fileSignaling() error {
	offerBytes, err := os.ReadFile(w.conf.OfferFile)
	if err != nil {
		return err
	}

	var offer webrtc.SessionDescription
	if err := json.Unmarshal(offerBytes, &offer); err != nil {
		return err
	}

	if err := w.pc.SetRemoteDescription(offer); err != nil {
		return err
	}

	answer, err := w.pc.CreateAnswer(nil)
	if err != nil {
		return err
	}

	if err := w.pc.SetLocalDescription(answer); err != nil {
		return err
	}

	if w.conf.AnswerFile != "" {
		data, err := json.Marshal(answer)
		if err != nil {
			return err
		}
		if err := os.WriteFile(w.conf.AnswerFile, data, 0600); err != nil {
			return err
		}
	}

	return nil
}

func (w *WebRTCServer) setupDataChannel(dc *webrtc.DataChannel) {
	dc.OnOpen(func() {
		log.Info("WebRTC data channel %d open", dc.ID())
		recvTime := time.Now().UnixNano()
		addr := &net.UDPAddr{IP: net.IPv4zero, Port: int(*dc.ID())}
		// evictSignal is required for connectionRoutine's select to be
		// well-formed but is intentionally unused for WebRTC: WebRTC
		// conns bypass admitNewConnection and never enter the per-IP
		// bucket, so the channel is never closed.
		conn := &UdpConn{isWebRTC: true, dc: dc, evictSignal: make(chan struct{})}
		conn.ConnData = &core.ConnectionData{
			InitTime:             recvTime,
			LastLocalRecvTime:    recvTime,
			Device:               w.us.device,
			LocalAddr:            w.us.listenAddr,
			RemoteAddr:           addr,
			CookieStore:          &core.CookieStore{},
			RemoteTransactionMap: make(map[uint64]*core.RemoteTransaction),
			SendQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
			RecvQueue:            make(chan *core.Packet, PacketQueueSizePerConnection),
			BlockSignal:          make(chan struct{}),
			SetTimeoutSignal:     make(chan struct{}),
			StopSignal:           make(chan struct{}),
		}
		conn.ConnData.InitTimeoutMs(DefaultAgentConnectionTimeoutMs)

		key := addr.String()
		w.us.remoteConnectionMapMutex.Lock()
		w.us.remoteConnectionMap[key] = conn
		w.us.remoteConnectionMapMutex.Unlock()

		w.us.wg.Add(1)
		go w.us.connectionRoutine(conn)
	})

	dc.OnMessage(func(m webrtc.DataChannelMessage) {
		if m.IsString {
			return
		}
		addr := &net.UDPAddr{IP: net.IPv4zero, Port: int(*dc.ID())}
		key := addr.String()
		w.us.remoteConnectionMapMutex.Lock()
		conn, ok := w.us.remoteConnectionMap[key]
		w.us.remoteConnectionMapMutex.Unlock()
		if !ok {
			return
		}
		pkt := w.us.device.AllocatePoolPacket()
		copy(pkt.Buf[:], m.Data)
		pkt.Content = pkt.Buf[:len(m.Data)]
		if len(pkt.Content) < pkt.MinimalLength() {
			w.us.device.ReleasePoolPacket(pkt)
			return
		}
		atomic.AddUint64(&w.us.stats.totalRecvBytes, uint64(len(m.Data)))
		conn.ConnData.ForwardInboundPacket(pkt)
	})

	dc.OnClose(func() {
		addr := &net.UDPAddr{IP: net.IPv4zero, Port: int(*dc.ID())}
		key := addr.String()
		w.us.remoteConnectionMapMutex.Lock()
		conn, ok := w.us.remoteConnectionMap[key]
		if ok {
			delete(w.us.remoteConnectionMap, key)
		}
		w.us.remoteConnectionMapMutex.Unlock()
		if ok {
			conn.Close()
		}
	})
}

func (w *WebRTCServer) Stop() {
	if w.pc != nil {
		_ = w.pc.Close()
	}
}
