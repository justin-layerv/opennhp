package ac

import (
	"fmt"
	"testing"
)

// Benchmarks substantiating the ipsetHash* builders. The admission path builds
// these entry strings inside per-admission per-src×dst inner loops, so the two
// things worth measuring are:
//
//   - the builder itself vs the fmt.Sprintf it replaced, and
//   - the all-ports call-site shape, where the pre-#3581 pattern built the
//     non-all-ports string and immediately discarded it.
//
// Run with:
//
//	go test -bench=BenchmarkIpsetHash -benchmem ./endpoints/ac/
//
// These are microbenchmarks: the absolute numbers are nanoseconds against
// surrounding kernel/ipset writes that cost orders of magnitude more. They exist
// to show the direction and the allocation count, not to claim admission
// throughput moves.

const (
	benchSrcIP  = "10.1.2.3"
	benchDstIP  = "10.4.5.6"
	benchNetStr = "10.0.0.0/8"
	benchPort   = 443
)

// benchSink defeats dead-store elimination so the compiler cannot delete the
// work being measured.
var benchSink string

func BenchmarkIpsetHashTCP_Sprintf(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchSink = fmt.Sprintf("%s,%d,%s", benchSrcIP, benchPort, benchDstIP)
	}
}

func BenchmarkIpsetHashTCP_Helper(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchSink = ipsetHashTCP(benchSrcIP, benchPort, benchDstIP)
	}
}

func BenchmarkIpsetHashUDP_Sprintf(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchSink = fmt.Sprintf("%s,udp:%d,%s", benchSrcIP, benchPort, benchDstIP)
	}
}

func BenchmarkIpsetHashUDP_Helper(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchSink = ipsetHashUDP(benchSrcIP, benchPort, benchDstIP)
	}
}

func BenchmarkIpsetHashNetPort_Sprintf(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchSink = fmt.Sprintf("%s,%d", benchNetStr, benchPort)
	}
}

func BenchmarkIpsetHashNetPort_Helper(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		benchSink = ipsetHashNetPort(benchNetStr, benchPort)
	}
}

// BenchmarkIpsetHashAllPorts_BuildThenDiscard measures the call-site shape this
// PR removes: build the non-all-ports entry, then overwrite it when
// dstAddr.Port == 0. runtime.concatstring* allocates, and the compiler does not
// elide the dead call, so the throwaway is a real allocation on every all-ports
// admission.
func BenchmarkIpsetHashAllPorts_BuildThenDiscard(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		port := 0
		s := ipsetHashTCP(benchSrcIP, port, benchDstIP)
		if port == 0 {
			s = ipsetHashTCPAllPorts(benchSrcIP, benchDstIP)
		}
		benchSink = s
	}
}

// BenchmarkIpsetHashAllPorts_Branch is the replacement shape: only the entry
// actually written to the kernel gets built.
func BenchmarkIpsetHashAllPorts_Branch(b *testing.B) {
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		port := 0
		var s string
		if port == 0 {
			s = ipsetHashTCPAllPorts(benchSrcIP, benchDstIP)
		} else {
			s = ipsetHashTCP(benchSrcIP, port, benchDstIP)
		}
		benchSink = s
	}
}
