//go:build !linux

package ac

import "errors"

// enumerateKernelAllowRules is the non-Linux stub. Real
// implementations live in expiry_enumerate_iptables_linux.go and
// expiry_enumerate_ebpf_linux.go. Returns error so AC startup
// fails closed on non-Linux when L3 flush is enabled.
func (a *UdpAC) enumerateKernelAllowRules() (int, error) {
	return 0, errors.New("L3 flush boot enumeration requires Linux")
}
