package server

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"net"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/containernetworking/cni/libcni"
	"github.com/containernetworking/plugins/pkg/ip"
	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
	"golang.org/x/sys/unix"
)

const (
	cniNetworkName = "fireactions"
	cniIfName      = "eth0"
	cniConfDir     = "/etc/cni/net.d"
	cniBinDir      = "/opt/cni/bin"

	// cniCacheDir and netNSDir are the firecracker-go-sdk defaults; the SDK
	// keeps each VM's libcni cache in cniCacheDir/<VMID> and its network
	// namespace at netNSDir/<VMID>.
	cniCacheDir = "/var/lib/cni"
	netNSDir    = "/var/run/netns"

	hostLocalDefaultDataDir = "/var/lib/cni/networks"
)

// cniSweeper releases CNI state (IPAM leases, firewall and masquerade rules,
// network namespaces, libcni caches) left behind by VMs whose CNI DEL never
// ran, for example because the server crashed.
type cniSweeper struct {
	logger   *zerolog.Logger
	confDir  string
	network  string
	ifName   string
	binPath  []string
	cacheDir string
	netNSDir string

	delNetwork     func(ctx context.Context, cacheDir string, list *libcni.NetworkConfigList, rt *libcni.RuntimeConf) error
	teardownIPMasq func(ipns []*net.IPNet, network, ifName, containerID string) error
	unmountNetNS   func(path string) error
}

func newCNISweeper(logger *zerolog.Logger) *cniSweeper {
	s := &cniSweeper{
		logger:         logger,
		confDir:        cniConfDir,
		network:        cniNetworkName,
		ifName:         cniIfName,
		binPath:        []string{cniBinDir},
		cacheDir:       cniCacheDir,
		netNSDir:       netNSDir,
		teardownIPMasq: ip.TeardownIPMasqForNetworks,
		unmountNetNS: func(path string) error {
			return unix.Unmount(path, unix.MNT_DETACH)
		},
	}

	s.delNetwork = func(
		ctx context.Context, cacheDir string, list *libcni.NetworkConfigList, rt *libcni.RuntimeConf,
	) error {
		return libcni.NewCNIConfigWithCacheDir(s.binPath, cacheDir, nil).DelNetworkList(ctx, list, rt)
	}

	return s
}

// sweep deletes the CNI state of every VM for which owns returns true and
// isLive returns false. It returns the number of VMs it cleaned up.
func (s *cniSweeper) sweep(ctx context.Context, owns, isLive func(vmID string) bool) (int, error) {
	list, err := libcni.LoadConfList(s.confDir, s.network)
	if err != nil {
		return 0, fmt.Errorf("loading CNI network %q from %s: %w", s.network, s.confDir, err)
	}

	pluginConf := parseCNIPluginConf(list)

	leases := map[string][]net.IP{}
	if pluginConf.leaseDir != "" {
		leases, err = readHostLocalLeases(pluginConf.leaseDir)
		if err != nil {
			return 0, fmt.Errorf("reading host-local leases: %w", err)
		}
	}

	vmIDs := map[string]struct{}{}
	for vmID := range leases {
		vmIDs[vmID] = struct{}{}
	}
	for _, dir := range []string{s.cacheDir, s.netNSDir} {
		entries, err := os.ReadDir(dir)
		if err != nil && !errors.Is(err, fs.ErrNotExist) {
			return 0, fmt.Errorf("reading %s: %w", dir, err)
		}
		for _, entry := range entries {
			vmIDs[entry.Name()] = struct{}{}
		}
	}

	candidates := make([]string, 0, len(vmIDs))
	for vmID := range vmIDs {
		if owns(vmID) && !isLive(vmID) {
			candidates = append(candidates, vmID)
		}
	}
	sort.Strings(candidates)

	swept := 0
	for _, vmID := range candidates {
		if ctx.Err() != nil {
			return swept, ctx.Err()
		}

		if s.sweepVM(ctx, list, pluginConf.ipMasq, vmID, leases[vmID]) {
			swept++
		}
	}

	return swept, nil
}

func (s *cniSweeper) sweepVM(ctx context.Context, list *libcni.NetworkConfigList, ipMasq bool, vmID string, addrs []net.IP) bool {
	cacheDir := filepath.Join(s.cacheDir, vmID)
	netNSPath := filepath.Join(s.netNSDir, vmID)

	_, err := os.Lstat(netNSPath)
	hasNetNS := err == nil
	hasState := len(addrs) > 0 || hasNetNS || dirHasFiles(cacheDir)

	if hasState {
		rt := &libcni.RuntimeConf{ContainerID: vmID, IfName: s.ifName}
		if hasNetNS {
			rt.NetNS = netNSPath
		}

		err := s.delNetwork(ctx, cacheDir, list, rt)
		if err != nil {
			s.logger.Warn().Err(err).
				Msgf("Failed to delete CNI network of exited VM %s, keeping its state for the next sweep", vmID)

			return false
		}

		// Without the VM's network namespace the bridge plugin cannot tell
		// which addresses it masqueraded, so it skips that part of DEL.
		if ipMasq && len(addrs) > 0 {
			err := s.teardownIPMasq(hostIPNets(addrs), s.network, s.ifName, vmID)
			if err != nil {
				s.logger.Warn().Err(err).Msgf("Failed to remove masquerade rules of exited VM %s", vmID)
			}
		}
	}

	if hasNetNS {
		s.removeNetNS(netNSPath)
	}

	err = os.RemoveAll(cacheDir)
	if err != nil {
		s.logger.Warn().Err(err).Msgf("Failed to remove CNI cache directory %s", cacheDir)
	}

	if hasState {
		s.logger.Info().Msgf("Removed CNI leftovers of exited VM %s (addresses: %s, network namespace: %t)",
			vmID, formatIPs(addrs), hasNetNS)
	} else {
		s.logger.Debug().Msgf("Removed empty CNI cache directory %s", cacheDir)
	}

	return true
}

func (s *cniSweeper) removeNetNS(path string) {
	err := s.unmountNetNS(path)
	if err != nil && !errors.Is(err, unix.EINVAL) {
		s.logger.Warn().Err(err).Msgf("Failed to unmount network namespace %s", path)
	}

	err = os.Remove(path)
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		s.logger.Warn().Err(err).Msgf("Failed to remove network namespace %s", path)
	}
}

func hostIPNets(addrs []net.IP) []*net.IPNet {
	ipns := make([]*net.IPNet, 0, len(addrs))
	for _, addr := range addrs {
		if v4 := addr.To4(); v4 != nil {
			addr = v4
		}

		bits := len(addr) * 8
		ipns = append(ipns, &net.IPNet{IP: addr, Mask: net.CIDRMask(bits, bits)})
	}

	return ipns
}

type cniPluginConf struct {
	leaseDir string
	ipMasq   bool
}

// parseCNIPluginConf finds the host-local lease directory and whether the
// bridge plugin masquerades, the two pieces of state DEL cannot clean up
// without the VM's network namespace.
func parseCNIPluginConf(list *libcni.NetworkConfigList) cniPluginConf {
	var conf cniPluginConf

	for _, plugin := range list.Plugins {
		var raw struct {
			Type   string `json:"type"`
			IPMasq bool   `json:"ipMasq"`
			IPAM   struct {
				Type    string `json:"type"`
				DataDir string `json:"dataDir"`
			} `json:"ipam"`
		}
		if err := json.Unmarshal(plugin.Bytes, &raw); err != nil {
			continue
		}

		if raw.Type == "bridge" && raw.IPMasq {
			conf.ipMasq = true
		}

		if raw.IPAM.Type == "host-local" && conf.leaseDir == "" {
			dataDir := raw.IPAM.DataDir
			if dataDir == "" {
				dataDir = hostLocalDefaultDataDir
			}
			conf.leaseDir = filepath.Join(dataDir, list.Name)
		}
	}

	return conf
}

// readHostLocalLeases maps each lease owner to its addresses. A host-local
// lease is a file named after the address whose first line is the owner's
// container ID. A missing directory has no leases.
func readHostLocalLeases(dir string) (map[string][]net.IP, error) {
	leases := map[string][]net.IP{}

	entries, err := os.ReadDir(dir)
	if errors.Is(err, fs.ErrNotExist) {
		return leases, nil
	}
	if err != nil {
		return nil, err
	}

	for _, entry := range entries {
		if !entry.Type().IsRegular() {
			continue
		}

		addr := net.ParseIP(entry.Name())
		if addr == nil {
			continue
		}

		data, err := os.ReadFile(filepath.Join(dir, entry.Name()))
		if err != nil {
			continue
		}

		owner, _, _ := strings.Cut(string(data), "\n")
		owner = strings.TrimSpace(owner)
		if owner == "" {
			continue
		}

		leases[owner] = append(leases[owner], addr)
	}

	return leases, nil
}

// removeEmptyCNICacheDir removes a VM's libcni cache directory once a
// successful CNI DEL has emptied it. A directory that still holds a cached
// result is kept so the startup sweep can finish the DEL.
func removeEmptyCNICacheDir(dir string) error {
	if dirHasFiles(dir) {
		return nil
	}

	return os.RemoveAll(dir)
}

// dirHasFiles reports whether dir contains anything but directories. A
// directory it cannot fully read counts as having files.
func dirHasFiles(dir string) bool {
	hasFiles := false
	err := filepath.WalkDir(dir, func(_ string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		if !d.IsDir() {
			hasFiles = true

			return fs.SkipAll
		}

		return nil
	})

	return hasFiles || (err != nil && !errors.Is(err, fs.ErrNotExist))
}

func formatIPs(addrs []net.IP) string {
	if len(addrs) == 0 {
		return "none"
	}

	s := make([]string, 0, len(addrs))
	for _, addr := range addrs {
		s = append(s, addr.String())
	}

	return strings.Join(s, ",")
}

// logrusWarnHook forwards firecracker-go-sdk warnings and errors, such as a
// failed CNI DEL after a VM exits, to the server's logger.
type logrusWarnHook struct {
	logger *zerolog.Logger
	vmID   string
}

func (h *logrusWarnHook) Levels() []logrus.Level {
	return []logrus.Level{logrus.PanicLevel, logrus.FatalLevel, logrus.ErrorLevel, logrus.WarnLevel}
}

func (h *logrusWarnHook) Fire(entry *logrus.Entry) error {
	level := zerolog.WarnLevel
	if entry.Level <= logrus.ErrorLevel {
		level = zerolog.ErrorLevel
	}

	err, _ := entry.Data[logrus.ErrorKey].(error)
	h.logger.WithLevel(level).Err(err).Str("vm", h.vmID).Msgf("firecracker-go-sdk: %s", entry.Message)

	return nil
}
