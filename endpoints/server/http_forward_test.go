package server

import "testing"

func TestIsPrivateIP(t *testing.T) {
	tests := []struct {
		name string
		ip   string
		want bool
	}{
		{"10.x", "10.0.0.1", true},
		{"172.16", "172.16.0.1", true},
		{"172.31", "172.31.255.255", true},
		{"192.168", "192.168.1.1", true},
		{"loopback", "127.0.0.1", true},
		{"public", "8.8.8.8", false},
		{"empty", "", false},
		{"invalid", "not-an-ip", false},
		{"below RFC1918", "172.15.255.255", false},
		{"above RFC1918", "172.32.0.1", false},
		{"IPv6 loopback", "::1", true},
		{"IPv6 link-local", "fe80::1", false},
		{"IPv6 ULA", "fd00::1", true},
		{"IPv6 public", "2001:db8::1", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := isPrivateIP(tc.ip); got != tc.want {
				t.Fatalf("isPrivateIP(%q) = %v, want %v", tc.ip, got, tc.want)
			}
		})
	}
}

func TestSelectServersForAssignment_IncludesSelf(t *testing.T) {
	s := &UdpServer{instanceID: "srv-1"}
	selected := s.selectServersForAssignment([]ServerInfo{
		{ID: "srv-1", InternalIP: "10.0.0.1", AZ: "a"},
		{ID: "srv-2", InternalIP: "10.0.0.2", AZ: "b"},
		{ID: "srv-3", InternalIP: "10.0.0.3", AZ: "c"},
	}, MaxServersPerAssignment)
	if len(selected) != 3 || selected[0].ID != "srv-1" {
		t.Fatalf("selected = %#v, want three servers with self first", selected)
	}
}

func TestSelectServersForAssignment_AZDistribution(t *testing.T) {
	s := &UdpServer{instanceID: "srv-1"}
	selected := s.selectServersForAssignment([]ServerInfo{
		{ID: "srv-1", AZ: "a"}, {ID: "srv-2", AZ: "a"},
		{ID: "srv-3", AZ: "b"}, {ID: "srv-4", AZ: "b"},
		{ID: "srv-5", AZ: "c"}, {ID: "srv-6", AZ: "c"},
	}, MaxServersPerAssignment)
	azs := make(map[string]bool)
	for _, server := range selected {
		azs[server.AZ] = true
	}
	if len(selected) != MaxServersPerAssignment || len(azs) < 2 {
		t.Fatalf("selected = %#v, want %d servers across at least two AZs", selected, MaxServersPerAssignment)
	}
}

func TestSelectServersForAssignment_DeterministicOrder(t *testing.T) {
	s := &UdpServer{instanceID: "srv-1"}
	servers := []ServerInfo{{ID: "srv-1", AZ: "c"}, {ID: "srv-2", AZ: "a"}, {ID: "srv-3", AZ: "b"}}
	want := s.selectServersForAssignment(servers, MaxServersPerAssignment)
	for i := 0; i < 10; i++ {
		got := s.selectServersForAssignment(servers, MaxServersPerAssignment)
		if len(got) != len(want) {
			t.Fatalf("iteration %d length = %d, want %d", i, len(got), len(want))
		}
		for j := range got {
			if got[j].ID != want[j].ID {
				t.Fatalf("iteration %d server[%d] = %s, want %s", i, j, got[j].ID, want[j].ID)
			}
		}
	}
}

func TestSelectServersForAssignment_FewerThanMax(t *testing.T) {
	s := &UdpServer{instanceID: "srv-1"}
	got := s.selectServersForAssignment([]ServerInfo{{ID: "srv-1", AZ: "a"}, {ID: "srv-2", AZ: "b"}}, MaxServersPerAssignment)
	if len(got) != 2 {
		t.Fatalf("selected %d servers, want 2", len(got))
	}
}

func TestSelectServersForAssignment_SelfNotInList(t *testing.T) {
	s := &UdpServer{instanceID: "absent"}
	got := s.selectServersForAssignment([]ServerInfo{{ID: "srv-1", AZ: "a"}, {ID: "srv-2", AZ: "b"}, {ID: "srv-3", AZ: "c"}}, MaxServersPerAssignment)
	if len(got) != MaxServersPerAssignment {
		t.Fatalf("selected %d servers, want %d", len(got), MaxServersPerAssignment)
	}
}

func TestSelectServersForAssignment_SingleServer(t *testing.T) {
	s := &UdpServer{instanceID: "srv-1"}
	got := s.selectServersForAssignment([]ServerInfo{{ID: "srv-1", AZ: "a"}}, MaxServersPerAssignment)
	if len(got) != 1 || got[0].ID != "srv-1" {
		t.Fatalf("selected = %#v, want srv-1", got)
	}
}

func TestACAssignment_Clone(t *testing.T) {
	ttl := int64(1234567890)
	reassigned := int64(1234567800)
	original := &ACAssignment{
		ACID: "ac-test", ResourceFQDN: "test.example.com", CustomerID: "cust-123",
		AssignedServers: []ServerInfo{{ID: "srv-1", IP: "10.0.0.1"}},
		Version:         3, ReassignedAt: &reassigned, CreatedAt: 1234567000, LastSeen: 1234567800, TTL: &ttl,
	}
	clone := original.Clone()
	if clone == original || clone.ACID != original.ACID || clone.Version != original.Version {
		t.Fatalf("clone = %#v, original = %#v", clone, original)
	}
	clone.Version = 99
	clone.LastSeen = 9999999
	*clone.TTL = 9999
	clone.AssignedServers[0].ID = "mutated"
	if original.Version == 99 || original.LastSeen == 9999999 || *original.TTL != ttl || original.AssignedServers[0].ID != "srv-1" {
		t.Fatalf("clone mutation affected original: %#v", original)
	}
}

func TestMaxInternalKnockRequestSize(t *testing.T) {
	if maxInternalKnockRequestSize != 64<<10 {
		t.Fatalf("maxInternalKnockRequestSize = %d, want 65536", maxInternalKnockRequestSize)
	}
}
