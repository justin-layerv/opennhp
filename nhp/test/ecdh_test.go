package test

import (
	"encoding/base64"
	"fmt"
	"testing"

	"github.com/OpenNHP/opennhp/nhp/common"
	core "github.com/OpenNHP/opennhp/nhp/core"
)

func TestCurve25519Keys(t *testing.T) {
	e, err := core.NewECDH(core.ECC_CURVE25519)
	if err != nil {
		t.Fatalf("NewECDH failed: %v", err)
	}

	fmt.Printf("Private key: %s\n", e.PrivateKeyBase64())
	fmt.Printf("Public key: %s\n", e.PublicKeyBase64())
}

func TestPublicKeys(t *testing.T) {
	//prk, err := base64.StdEncoding.DecodeString("kgvvQaBGfHNWCbZMkFWS1K07BgRXlnOo7CHTZF1bsmI=") // server
	//prk, err := base64.StdEncoding.DecodeString("2kRXjwV9zAUMc0Vf0jl984q2p9EiyjbAMUPKNu517z4=") // agent
	prk, err := base64.StdEncoding.DecodeString("D2bieOaJarsM9euBBfSs/Ky8g/X6lBQ73NmP55CMgds=") // ac
	if err != nil {
		fmt.Printf("Private key decode error\n")
		return
	}
	curvee, err2 := core.ECDHFromKey(core.ECC_CURVE25519, prk)
	if err2 != nil {
		fmt.Printf("Wrong private key: %v\n", err2)
		return
	}

	fmt.Printf("Curve25519 public key: %s\n", curvee.PublicKeyBase64())
}

func TestPeer(t *testing.T) {
	server := &core.UdpPeer{
		Ip:           "192.168.2.27",
		Port:         common.DefaultNHPPort,
		PubKeyBase64: "c0HALYy3433SqJmfN0JpRk1Q6H7xh84MAg89jYtRrQM=",
		ExpireTime:   1716345064,
		Type:         core.NHP_SERVER,
	}

	var p *core.UdpPeer = server

	var peer core.Peer = p

	fmt.Printf("Pub key %s, addr %s, name %s\n", peer.PublicKeyBase64(), peer.SendAddr().String(), peer.Name())
}
