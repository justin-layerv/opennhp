//go:build smoke

package smoke

import (
	"errors"
	"fmt"
	"testing"
)

// TestSSMProbeRejectList verifies that every synthetic "bad" command
// strings is rejected by the reject-list. This is a unit-level test
// — no network, no SSM client — but lives under the smoke build tag so
// it runs alongside the rest of the suite whenever we check probe
// invariants.
//
// Adding a probe that trips the reject-list means either (a) the
// reject-list is overreaching and needs tuning, or (b) the probe
// should not exist. Both are good conversations.
func TestSSMProbeRejectList(t *testing.T) {
	bad := []string{
		// state mutation
		"rm -rf /tmp/x",
		"mv /etc/passwd /tmp/p",
		"cp /etc/shadow /tmp/s",
		"dd if=/dev/zero of=/tmp/z",
		"echo hi | tee /tmp/x",
		"chmod 777 /etc/shadow",
		"chown root /tmp/x",
		"echo hi > /tmp/x",
		"echo hi >> /tmp/x",
		// firewall mutation
		"iptables -L",
		"ipset -A defaultset 1.2.3.4,80,5.6.7.8",
		"sysctl -w net.ipv4.ip_forward=1",
		// service mutation
		"systemctl restart nhp-ac",
		"systemctl stop nhp-server",
		"service docker restart",
		// docker mutation
		"docker restart nhp-server",
		"docker stop nhp-server",
		"docker run --rm alpine",
		"docker pull nginx",
		// package install
		"apt-get install curl",
		"apt install wget",
		"yum install httpd",
		"dpkg -i pkg.deb",
		// shell control: chaining and substitution
		"true; rm /tmp/x",
		"echo $(whoami)",
		"echo `whoami`",
		"true && echo bad",
	}

	for _, cmd := range bad {
		t.Run(cmd, func(t *testing.T) {
			err := sendShellScriptRaw(cmd)
			if err == nil {
				t.Fatalf("expected reject for %q, got nil", cmd)
			}
			if !errors.Is(err, errCommandRejected) {
				t.Fatalf("expected errCommandRejected for %q, got %v", cmd, err)
			}
		})
	}
}

// TestSSMProbeNamedCommandsPassRejectList verifies that every named
// probe's command string clears the reject-list. This catches the
// regression where someone tightens the reject-list and accidentally
// breaks an existing probe.
func TestSSMProbeNamedCommandsPassRejectList(t *testing.T) {
	const benignHostname = "internal-api.qurl.layerv.xyz"
	allowed := []string{
		cmdHealthLiveFromHost,
		cmdHealthKnockReadyFromHost,
		cmdDockerNhpServerRunning,
		cmdDockerImageTag,
		cmdSystemdNRestartsNhpServer,
		fmt.Sprintf(cmdDigInternalQurlAPIFmt, benignHostname),
		fmt.Sprintf(cmdCurlInternalQurlAPIFmt, benignHostname),
		fmt.Sprintf(cmdCurlInternalQurlResolveFmt, benignHostname),
	}
	for _, cmd := range allowed {
		t.Run(cmd, func(t *testing.T) {
			if err := sendShellScriptRaw(cmd); err != nil {
				t.Fatalf("named probe command rejected unexpectedly: %q: %v", cmd, err)
			}
		})
	}
}
