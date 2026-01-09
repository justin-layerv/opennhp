package core

import (
	"encoding/base64"
	"fmt"
	"net"
	"sync"
	"time"

	log "github.com/OpenNHP/opennhp/nhp/log"
)

type Peer interface {
	DeviceType() int
	Name() string
	PublicKey() []byte
	PublicKeyBase64() string

	IsExpired() bool

	ResolveHost() string
	ResolvedIps() []string
	Host() string
	SendAddr() net.Addr
	InvalidateDNSCache() // Force DNS re-resolution on next SendAddr() call
	LastSendTime() int64
	UpdateSend(currTime int64)

	RecvAddr() net.Addr
	LastRecvTime() int64
	UpdateRecv(currTime int64, currAddr net.Addr)
	CheckRecvAddress(currTime int64, currAddr net.Addr) bool
}

type UdpPeer struct {
	sync.Mutex

	// immutable fields. Don't change them after creation, so no lock is required
	PubKeyBase64 string `json:"pubKeyBase64"`
	Hostname     string `json:"host,omitempty"`
	Ip           string `json:"ip"` // static ip, it may be different from primaryResolvedIp
	Port         int    `json:"port"`
	Type         int    `json:"type"`
	ExpireTime   int64  `json:"expireTime"`
	name         string
	pubKey       []byte

	// mutable fields
	lastSendTime      int64
	lastRecvTime      int64
	lastNSLookupTime  int64
	resolvedIpArr     []string
	primaryResolvedIp string
	recvAddr          *net.UDPAddr
	teePublicKeyBase64      string
	consumerEphemeralPublicKeyBase64 string
}

func (p *UdpPeer) DeviceType() DeviceTypeEnum {
	return p.Type
}

func (p *UdpPeer) PublicKey() []byte {
	p.Lock()
	defer p.Unlock()

	if p.pubKey == nil {
		var err error
		p.pubKey, err = base64.StdEncoding.DecodeString(p.PubKeyBase64)
		if err != nil {
			log.Error("failed to decode peer public key base64: %v, input=%q", err, p.PubKeyBase64)
		} else {
			log.Debug("decoded peer public key: input=%q, len=%d", p.PubKeyBase64, len(p.pubKey))
		}
	}
	return p.pubKey
}

func (p *UdpPeer) PublicKeyBase64() string {
	return p.PubKeyBase64
}

func (p *UdpPeer) Name() string {
	p.Lock()
	defer p.Unlock()

	if len(p.name) == 0 {
		// Safely handle short or empty PubKeyBase64 strings
		if len(p.PubKeyBase64) >= 43 {
			p.name = fmt.Sprintf("%s...%s", p.PubKeyBase64[0:4], p.PubKeyBase64[39:43])
		} else if len(p.PubKeyBase64) > 0 {
			// For short keys, use what we have
			p.name = p.PubKeyBase64
		} else {
			p.name = "unknown"
		}
	}
	return p.name
}

func (p *UdpPeer) ResolveHost() string {
	if len(p.Hostname) == 0 {
		return p.Ip
	}

	p.Lock()
	defer p.Unlock()

	currTime := time.Now().UnixNano()
	timeSinceLastLookup := currTime - p.lastNSLookupTime
	if timeSinceLastLookup > MinimalNSLookupInterval*int64(time.Second) {
		oldIp := p.primaryResolvedIp
		addrs, err := net.LookupHost(p.Hostname)
		if err == nil {
			p.lastNSLookupTime = currTime
			p.resolvedIpArr = addrs
			p.primaryResolvedIp = addrs[0]
			if oldIp != "" && oldIp != p.primaryResolvedIp {
				log.Info("[DNS] Hostname %s resolved to new IP: %s -> %s (after %ds)",
					p.Hostname, oldIp, p.primaryResolvedIp, timeSinceLastLookup/int64(time.Second))
			} else if oldIp == "" {
				log.Debug("[DNS] Hostname %s initial resolution: %s", p.Hostname, p.primaryResolvedIp)
			} else {
				log.Debug("[DNS] Hostname %s re-resolved to same IP: %s", p.Hostname, p.primaryResolvedIp)
			}
		} else {
			log.Error("[DNS] Failed to resolve hostname %s: %v (keeping cached IP: %s)",
				p.Hostname, err, p.primaryResolvedIp)
		}
	}

	if len(p.primaryResolvedIp) > 0 {
		return p.primaryResolvedIp
	}
	return p.Ip
}

func (p *UdpPeer) Host() string {
	hostAddr := p.Ip
	if len(p.Hostname) > 0 {
		hostAddr = p.Hostname
	}
	if p.Port == 0 {
		return hostAddr
	}
	return fmt.Sprintf("%s:%d", hostAddr, p.Port)
}

func (p *UdpPeer) SendAddr() net.Addr {
	resolvedIp := p.ResolveHost() // happens only when MinimalNSLookupInterval has passed
	ip := net.ParseIP(resolvedIp)

	if ip == nil {
		return nil
	}
	return &net.UDPAddr{
		IP:   ip,
		Port: p.Port,
	}
}

// InvalidateDNSCache forces DNS re-resolution on the next SendAddr() call.
// Call this when connection failures occur to pick up DNS changes faster
// than the normal MinimalNSLookupInterval (5 minutes).
func (p *UdpPeer) InvalidateDNSCache() {
	if len(p.Hostname) == 0 {
		return // No hostname configured, nothing to invalidate
	}
	p.Lock()
	defer p.Unlock()
	oldCacheAge := time.Duration(time.Now().UnixNano()-p.lastNSLookupTime) * time.Nanosecond
	p.lastNSLookupTime = 0
	log.Debug("[DNS] Cache invalidated for %s (was %s old, cached IP: %s)",
		p.Hostname, oldCacheAge.Round(time.Second), p.primaryResolvedIp)
}

func (p *UdpPeer) ResolvedIps() []string {
	p.Lock()
	defer p.Unlock()

	return p.resolvedIpArr
}

func (p *UdpPeer) IsExpired() bool {
	p.Lock()
	defer p.Unlock()

	// p.ExpireTime is in seconds
	return p.ExpireTime > 0 && time.Now().UnixMilli() > p.ExpireTime*1000
}

func (p *UdpPeer) LastSendTime() int64 {
	p.Lock()
	defer p.Unlock()

	return p.lastSendTime
}

func (p *UdpPeer) UpdateSend(currTime int64) {
	p.Lock()
	defer p.Unlock()

	p.lastSendTime = currTime
}

// a peer should not have multiple layer-4 addresses within its hold time
func (p *UdpPeer) CheckRecvAddress(currTime int64, currAddr net.Addr) bool {
	p.Lock()
	defer p.Unlock()

	if currTime > p.lastRecvTime+MinimalPeerAddressHoldTime*int64(time.Second) {
		return true
	}

	if p.recvAddr.String() == currAddr.String() {
		return true
	}

	return false
}

func (p *UdpPeer) RecvAddr() net.Addr {
	p.Lock()
	defer p.Unlock()

	return p.recvAddr
}

func (p *UdpPeer) LastRecvTime() int64 {
	p.Lock()
	defer p.Unlock()

	return p.lastRecvTime
}

func (p *UdpPeer) UpdateRecv(currTime int64, currAddr net.Addr) {
	p.Lock()
	defer p.Unlock()

	p.lastRecvTime = currTime
	p.recvAddr = currAddr.(*net.UDPAddr)
}

func (p *UdpPeer) TeePublicKeyBase64() string {
	p.Lock()
	defer p.Unlock()

	return p.teePublicKeyBase64
}

func (p *UdpPeer) SetTeePublicKeyBase64(teePublicKeyBase64 string) {
	p.Lock()
	defer p.Unlock()

	p.teePublicKeyBase64 = teePublicKeyBase64
}

func (p *UdpPeer) ConsumerEphemeralPublicKeyBase64() string {
	p.Lock()
	defer p.Unlock()

	return p.consumerEphemeralPublicKeyBase64
}

func (p *UdpPeer) SetConsumerEphemeralPublicKeyBase64(consumerEphemeralPublicKeyBase64 string) {
	p.Lock()
	defer p.Unlock()

	p.consumerEphemeralPublicKeyBase64 = consumerEphemeralPublicKeyBase64
}
