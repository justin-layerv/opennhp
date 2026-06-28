//go:build linux

package ebpf

import (
	// "log"

	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"syscall"
	"time"

	stdlog "log"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/perf"
	"github.com/cilium/ebpf/rlimit"

	"github.com/OpenNHP/opennhp/nhp/log"
)

type bpfObjects struct {
	XdpProg       *ebpf.Program `ebpf:"xdp_white_prog"`
	Whitelist     *ebpf.Map     `ebpf:"spp"`
	Icmpwhitelist *ebpf.Map     `ebpf:"icmpwhitelist"`
	Sdwhitelist   *ebpf.Map     `ebpf:"sdwhitelist"`
	Srcportlist   *ebpf.Map     `ebpf:"src_port"`
	Portlist      *ebpf.Map     `ebpf:"port_list"`
	Protocolport  *ebpf.Map     `ebpf:"protocol_port"`
	Conntrack     *ebpf.Map     `ebpf:"conn_track"`
	Events        *ebpf.Map     `ebpf:"events"`
	EventsV6      *ebpf.Map     `ebpf:"events_v6"`
	// DENY-telemetry rate-limiter maps (#2849). Only the two userspace touches —
	// the config the AC writes and the suppressed counter it reads — need a Go
	// handle; the per-CPU token-bucket state (deny_rl_state) is datapath-only and
	// is kept alive by the loaded program, like the v6 allow-rule maps.
	DenyRlConfig   *ebpf.Map `ebpf:"deny_rl_config"`
	DenySuppressed *ebpf.Map `ebpf:"deny_suppressed"`
}

type tcBpfObjects struct {
	TcEgressProg *ebpf.Program `ebpf:"tc_egress_prog"`
	Whitelist    *ebpf.Map     `ebpf:"spp"`
}

var (
	DenyLogger *log.Logger
	AcLogger   *log.Logger
)

// The v4/v6 event structs (EventV4/EventV6) and their offset-based decoders live
// in event_format.go (build-tag-free, so the C↔Go layout is unit-tested on macOS).

var xdpLink link.Link
var tcLink link.Link
var bootTime time.Time

func init() {
	var info syscall.Sysinfo_t
	if err := syscall.Sysinfo(&info); err != nil {
		panic("Failed to get the system running time: " + err.Error())
	}

	now := time.Now()
	bootTime = now.Add(-time.Duration(info.Uptime) * time.Second)
	log.Info("​​System boot time: %v", bootTime)
}

func EbpfEngineLoad(dirPath string, logLevel int, acId string) error {
	CleanupBPFFiles()
	if err := rlimit.RemoveMemlock(); err != nil {
		log.Error("Failed to remove memlock limit")
	}

	// These three literals are the single source of truth for the eBPF
	// object load path. The build side must ship the objects to match:
	// Makefile EBPF_OBJ_* compile them into release/nhp-ac/etc/, and the
	// docker/Dockerfile.ac.aws runtime guard asserts /nhp-ac/etc/<name>.o
	// exists. If you rename an object or change bpfDir here, update both
	// or the AC boot-fails under FilterMode=EBPFXDP. The drift is caught at
	// PR time by scripts/check-ebpf-load-path-lockstep.sh (wired into
	// `make lint-workflows`), which compares these consts against the
	// Makefile paths and the Dockerfile guard — keep that lint's extractor
	// in step if you change the shape of these declarations.
	const ebpfenginename string = "nhp_ebpf_xdp.o"
	const tcObjName string = "tc_egress.o"
	// bpfDir is relative to the AC's working directory at runtime
	// (prod: nhp-acd systemd WorkingDirectory=/opt/layerv/nhp-ac), NOT
	// joined onto the dirPath arg this func uses for logs below — that is
	// deliberate: the build side ships the objects to a cwd-relative
	// etc/ (Makefile EBPF_OBJ_* / the Dockerfile guard), so resolving
	// them against dirPath instead would look in the wrong place and
	// boot-fail the load. Keep this cwd-relative.
	bpfDir := "etc"
	specPath := filepath.Join(bpfDir, ebpfenginename)
	tcSpecPath := filepath.Join(bpfDir, tcObjName)

	if _, err := os.Stat(specPath); os.IsNotExist(err) {
		log.Error("eBPF object file not found ")
		return err
	}
	if _, err := os.Stat(tcSpecPath); os.IsNotExist(err) {
		log.Error("tc eBPF object file not found ")
		return err
	}

	spec, err := ebpf.LoadCollectionSpec(specPath)
	if err != nil {
		log.Error("failed to load eBPF object")
		return err
	}
	// Load tc eBPF object
	tcSpec, err := ebpf.LoadCollectionSpec(tcSpecPath)
	if err != nil {
		log.Error("failed to load tc eBPF object")
		return err
	}

	var objs bpfObjects
	if err := spec.LoadAndAssign(&objs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf/", // automatically mounted to
		},
	}); err != nil {
		log.Error("Failed to load and assign eBPF objects")
		return err
	}

	var tcObjs tcBpfObjects
	if err := tcSpec.LoadAndAssign(&tcObjs, &ebpf.CollectionOptions{
		Maps: ebpf.MapOptions{
			PinPath: "/sys/fs/bpf/", // automatically mounted to
		},
	}); err != nil {
		log.Error("Failed to load and assign tc eBPF objects")
		return err
	}

	if err := objs.XdpProg.Pin("/sys/fs/bpf/xdp_white_prog"); err != nil {
		log.Error("failed to pin XDP program xdp_white_prog to /sys/fs/bpf/")
		return err
	}
	if err := tcObjs.TcEgressProg.Pin("/sys/fs/bpf/tc_egress_prog"); err != nil {
		log.Error("failed to pin TC egress program tc_egress_prog to /sys/fs/bpf/")
		return err
	}

	ifaceName, err := getDefaultRouteInterface()
	if err != nil {
		log.Error("failed to get default route interface")
		return err
	}
	log.Info("Default route interface: %s", ifaceName)
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		log.Error("failed to find interface %s", ifaceName)
		os.Exit(1)
	}
	//load ebpf nhp_ebpf_xdp.o to net interface which default route exit
	xdpLink, err = link.AttachXDP(link.XDPOptions{
		Program:   objs.XdpProg,
		Interface: iface.Index,
		Flags:     link.XDPGenericMode, // XDPGenericMode and XDPDriverMode
	})
	if err != nil {
		log.Error("failed to attach XDP program to interface: %s", ifaceName)
		return err
	}
	//load tc eBPF tc_egress.o to net interface which default route exit
	tcLink, err = link.AttachTCX(link.TCXOptions{
		Program:   tcObjs.TcEgressProg,
		Interface: iface.Index,
		Attach:    ebpf.AttachTCXEgress,
	})
	if err != nil {
		log.Error("failed to attach TC egress program to interface: %s", ifaceName)
		return err
	}

	// Accessing the Perf Buffer Map named "events" defined in eBPF.
	eventsMap := objs.Events
	if eventsMap == nil {
		log.Error("failed to load 'events' map from eBPF object (nil)")
		return errors.New("'events' map not found")
	}
	// The parallel v6 perf map (E3). Carries IPv6 filter-decision events with
	// full 128-bit addresses. A nil here means the events_v6 map is missing from
	// the loaded object (stale .o that predates E3) — fail closed at load rather
	// than silently dropping all v6 filter telemetry once FilterMode flips.
	eventsV6Map := objs.EventsV6
	if eventsV6Map == nil {
		log.Error("failed to load 'events_v6' map from eBPF object (nil)")
		return errors.New("'events_v6' map not found")
	}

	// DENY-telemetry rate-limiter (#2849). A nil here means the maps are missing
	// from the loaded object (stale .o predating #2849) — fail closed at load
	// rather than silently shipping an unconfigured (fail-open) limiter once
	// FilterMode flips.
	denyRlConfigMap := objs.DenyRlConfig
	if denyRlConfigMap == nil {
		log.Error("failed to load 'deny_rl_config' map from eBPF object (nil)")
		return errors.New("'deny_rl_config' map not found")
	}
	denySuppressedMap := objs.DenySuppressed
	if denySuppressedMap == nil {
		log.Error("failed to load 'deny_suppressed' map from eBPF object (nil)")
		return errors.New("'deny_suppressed' map not found")
	}
	// Activate the limiter by writing the default cap (key 0). Until this write
	// the regular ARRAY is zero-valued (capacity 0 = fail-open / always-emit), so
	// the limiter only ever starts shedding once this succeeds. Retunable at the
	// E5 flip via a single map update, no object regen (#2823).
	denyRlCfg := DenyRlConfig{Capacity: DefaultDenyRlCapacity, RefillPerSec: DefaultDenyRlRefillPerSec}
	if err := denyRlConfigMap.Update(uint32(0), &denyRlCfg, ebpf.UpdateAny); err != nil {
		log.Error("failed to write default deny_rl_config: %v", err)
		return err
	}
	log.Info("eBPF DENY telemetry rate-limiter configured: capacity=%d refill=%d/s per CPU (#2849)", denyRlCfg.Capacity, denyRlCfg.RefillPerSec)

	ExeDirPath := dirPath
	//Set up the DENY logger
	DenyLogger = log.NewLoggerDefine(
		"",
		logLevel,
		filepath.Join(ExeDirPath, "logs"),
		"nhp_deny",
	)
	DenyLogger.SetFlags(stdlog.Lmsgprefix)
	// Set up the ACCEPT logger
	AcLogger = log.NewLoggerDefine(
		"",
		logLevel,
		filepath.Join(ExeDirPath, "logs"),
		"nhp_accept",
	)
	AcLogger.SetFlags(stdlog.Lmsgprefix)
	// Two perf maps, two reader goroutines (the safe pattern — perf.Reader.Read
	// blocks, so one goroutine cannot service both maps). The v4 reader consumes
	// `events` (4-byte addresses); the v6 reader consumes `events_v6` (16-byte
	// addresses). Both write to the SAME nhp_accept-*.log / nhp_deny-*.log files
	// in the SAME line format (formatEventLine), so CloudWatch ingestion +
	// dashboards keep working across both families. The shared AsyncLogWriter
	// (nhp/log) is mutex-guarded and serializes via a single write goroutine, so
	// concurrent Info() calls from the two readers cannot interleave a line.

	// IPv4 perf-event reader.
	go func() {
		perfReader, err := perf.NewReader(eventsMap, os.Getpagesize())
		if err != nil {
			log.Error("failed to create v4 perf reader: %v", err)
			return
		}
		defer perfReader.Close()

		log.Info("Start listening for eBPF events (PERF BUFFER, v4)")

		for {
			record, err := perfReader.Read()
			if err != nil {
				log.Error("Error reading eBPF v4 event: %v", err)
				continue
			}
			// No-silent-loss safety net (E3): the kernel overwrites the oldest
			// samples when the per-CPU ring is full and reports the count here.
			// Active rate-limiting/sampling of the malformed-packet DENY flood is
			// deferred to E4 (#2849), so surfacing LostSamples is the cheap
			// guard that the flood is never silent.
			if record.LostSamples > 0 {
				recordLostSamples(record.LostSamples)
				log.Warning("eBPF v4 perf buffer overflow: lost %d sample(s) (cumulative %d) — filter-decision events were dropped before userspace could read them", record.LostSamples, LostPerfSamples())
			}
			// A PERF_RECORD_LOST record (LostSamples > 0) carries an empty
			// RawSample; skip it so the overflow produces one clean WARN, not a
			// WARN + a spurious decode error. decodeEventV4 guards shorter
			// truncated samples (< 24 bytes); the old inline indexing did not.
			if len(record.RawSample) == 0 {
				continue
			}

			ev, err := decodeEventV4(record.RawSample)
			if err != nil {
				log.Error("Error decoding eBPF v4 event: %v", err)
				continue
			}

			eventTime := bootTime.Add(time.Duration(ev.Timestamp))
			logMsg := formatEventLine(
				eventTime.Format("15:04:05"),
				acId,
				actionString(ev.Action),
				uint32ToIPv4(ev.SrcIP),
				uint32ToIPv4(ev.DstIP),
				int(ev.Len),
				protoToString(ev.Protocol),
				ev.SrcPort,
				ev.DstPort,
			)

			if ev.Action == 0 { // DENY
				DenyLogger.Info("%s", logMsg)
			} else { // ACCEPT
				AcLogger.Info("%s", logMsg)
			}
		}
	}()

	// IPv6 perf-event reader (E3). Decodes events_v6 (struct event_t_v6) and
	// writes the SAME-format line as v4 so the v6 records land in the same
	// nhp_accept/deny streams. Closes the regression where the eBPF datapath
	// emitted v6 ACCEPTs with zeroed addresses and silently dropped v6 DENYs.
	go func() {
		perfReader, err := perf.NewReader(eventsV6Map, os.Getpagesize())
		if err != nil {
			log.Error("failed to create v6 perf reader: %v", err)
			return
		}
		defer perfReader.Close()

		log.Info("Start listening for eBPF events (PERF BUFFER, v6)")

		for {
			record, err := perfReader.Read()
			if err != nil {
				log.Error("Error reading eBPF v6 event: %v", err)
				continue
			}
			if record.LostSamples > 0 {
				recordLostSamples(record.LostSamples)
				log.Warning("eBPF v6 perf buffer overflow: lost %d sample(s) (cumulative %d) — filter-decision events were dropped before userspace could read them", record.LostSamples, LostPerfSamples())
			}
			// A PERF_RECORD_LOST record (LostSamples > 0) carries an empty
			// RawSample; skip it so an overflow produces one clean WARN, not a
			// WARN + a spurious "Error decoding eBPF v6 event" (decodeEventV6
			// would reject the empty slice as too-short). Mirrors the v4 reader's
			// len == 0 guard.
			if len(record.RawSample) == 0 {
				continue
			}

			ev, err := decodeEventV6(record.RawSample)
			if err != nil {
				log.Error("Error decoding eBPF v6 event: %v", err)
				continue
			}

			eventTime := bootTime.Add(time.Duration(ev.Timestamp))
			logMsg := formatEventLine(
				eventTime.Format("15:04:05"),
				acId,
				actionString(ev.Action),
				ipv6BytesToString(ev.SrcIP),
				ipv6BytesToString(ev.DstIP),
				int(ev.Len),
				protoToString(ev.Protocol),
				ev.SrcPort,
				ev.DstPort,
			)

			if ev.Action == 0 { // DENY
				DenyLogger.Info("%s", logMsg)
			} else { // ACCEPT
				AcLogger.Info("%s", logMsg)
			}
		}
	}()

	// DENY rate-limiter suppressed-counter monitor (#2849). The in-kernel token
	// bucket sheds malformed/early-drop DENY events under a flood and counts them
	// per-CPU in deny_suppressed; poll + sum + surface so the shedding is never
	// silent (mirrors the perf-overflow LostSamples WARN). Diagnostic only — it
	// never touches the datapath. INERT until the flip, like the readers above.
	//
	// SuppressedDenyEvents() therefore lags by up to one poll interval (and is
	// unset for the first interval). Fine for this WARN path; the follow-up that
	// wires it into a CloudWatch metric should choose the alarm period/threshold
	// with that staleness in mind.
	const denySuppressedPollInterval = 60 * time.Second
	go func() {
		ticker := time.NewTicker(denySuppressedPollInterval)
		defer ticker.Stop()
		var last uint64
		for range ticker.C {
			var perCPU []uint64
			if err := denySuppressedMap.Lookup(uint32(0), &perCPU); err != nil {
				log.Error("failed to read deny_suppressed map: %v", err)
				continue
			}
			total := sumPerCPUCounter(perCPU)
			recordSuppressedDeny(total)
			if total > last {
				log.Warning("eBPF DENY telemetry rate-limiter shed %d malformed/early-drop event(s) since last poll (cumulative %d) — the malformed-packet flood is being capped as designed (#2849)", total-last, total)
				last = total
			}
		}
	}()

	return nil
}

func getDefaultRouteInterface() (string, error) {
	cmd := exec.Command("ip", "route")
	output, err := cmd.Output()
	if err != nil {
		log.Error("failed to get running ip route:")
		return "", err
	}

	re := regexp.MustCompile(`default via (\S+) dev (\S+)`)
	matches := re.FindStringSubmatch(string(output))
	if len(matches) < 3 {
		log.Error("failed to parse default route")
		return "", errors.New("failed to parse default route")
	}
	interfaceName := matches[2]
	return interfaceName, nil
}

// clean eBPF map file
func CleanupBPFFiles() {
	bpfFiles := []string{
		"/sys/fs/bpf/xdp_white_prog",
		"/sys/fs/bpf/conn_track",
		"/sys/fs/bpf/icmpwhitelist",
		"/sys/fs/bpf/port_list",
		"/sys/fs/bpf/protocol_port",
		"/sys/fs/bpf/sdwhitelist",
		"/sys/fs/bpf/src_port",
		"/sys/fs/bpf/spp",
		"/sys/fs/bpf/tc_egress_prog",
	}

	for _, file := range bpfFiles {
		if err := os.Remove(file); err != nil {
			if !os.IsNotExist(err) {
				log.Error("Failed to remove BPF file %s: %v", file, err)
			}
		} else {
			log.Info("Successfully removed BPF file: %s", file)
		}
	}
	if xdpLink != nil {
		xdpLink.Close()
		log.Info("XDP link detached and closed")
	}
	if tcLink != nil {
		tcLink.Close()
		log.Info("TCX link detached and closed")
	}
}
