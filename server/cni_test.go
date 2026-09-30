package server

import (
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"sync"
	"testing"

	"github.com/containernetworking/cni/libcni"
	"github.com/rs/zerolog"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const testConflist = `{
  "cniVersion": "0.4.0",
  "name": "fireactions",
  "plugins": [
    {
      "type": "bridge",
      "bridge": "fireactions-br0",
      "ipMasq": true,
      "ipam": {"type": "host-local", "dataDir": "%DATADIR%", "subnet": "192.168.128.0/23"}
    },
    {"type": "firewall"},
    {"type": "tc-redirect-tap"}
  ]
}`

func newTestPool() *Pool {
	const name = "amuse"

	logger := zerolog.Nop()
	ctx, cancel := context.WithCancel(context.Background())
	doneCh := make(chan struct{})
	close(doneCh)

	return &Pool{
		config:     &PoolConfig{Name: name, Runner: &RunnerConfig{Name: name}},
		machinesMu: &sync.Mutex{},
		machines:   make(map[string]*Machine),
		logger:     &logger,
		stopCh:     make(chan struct{}, 1),
		doneCh:     doneCh,
		ctx:        ctx,
		cancel:     cancel,
	}
}

func TestPoolStopLeavesVMMContextUsable(t *testing.T) {
	p := newTestPool()

	vmmCtx, vmmCancel := p.newVMMContext()
	defer vmmCancel()
	poolDerivedCtx, poolDerivedCancel := context.WithCancel(p.ctx)
	defer poolDerivedCancel()

	p.Stop()

	// firecracker-go-sdk runs the CNI plugins for DEL with exec.CommandContext
	// on the VMM context once the VM has exited.
	require.ErrorIs(t, exec.CommandContext(poolDerivedCtx, "true").Run(), context.Canceled)
	require.NoError(t, vmmCtx.Err())
	require.NoError(t, exec.CommandContext(vmmCtx, "true").Run())
}

func TestPoolOwnsVM(t *testing.T) {
	p := newTestPool()

	assert.True(t, p.ownsVM("amuse-d8e2f0832e649f7cee851cb6"))
	assert.False(t, p.ownsVM("agents-d8e2f0832e649f7cee851cb6"))
	assert.False(t, p.ownsVM("amuse-big-d8e2f0832e649f7cee851cb6"))
	assert.False(t, p.ownsVM("amuse-d8e2f0832e649f7cee851cb"))
	assert.False(t, p.ownsVM("amuse-zzzzf0832e649f7cee851cb6"))
	assert.False(t, p.ownsVM("results"))
}

type sweepFixture struct {
	sweeper  *cniSweeper
	leaseDir string

	dels      []libcni.RuntimeConf
	delErr    map[string]error
	masq      map[string][]string
	unmounted []string
}

func newSweepFixture(t *testing.T) *sweepFixture {
	t.Helper()

	root := t.TempDir()
	confDir := filepath.Join(root, "net.d")
	dataDir := filepath.Join(root, "run-cni")
	require.NoError(t, os.MkdirAll(confDir, 0o750))

	conflist := bytes.ReplaceAll([]byte(testConflist), []byte("%DATADIR%"), []byte(dataDir))
	require.NoError(t, os.WriteFile(filepath.Join(confDir, "10-fireactions.conflist"), conflist, 0o600))

	logger := zerolog.Nop()
	f := &sweepFixture{
		leaseDir: filepath.Join(dataDir, "fireactions"),
		delErr:   map[string]error{},
		masq:     map[string][]string{},
	}

	f.sweeper = &cniSweeper{
		logger:   &logger,
		confDir:  confDir,
		network:  "fireactions",
		ifName:   "eth0",
		cacheDir: filepath.Join(root, "cache"),
		netNSDir: filepath.Join(root, "netns"),
		delNetwork: func(_ context.Context, cacheDir string, list *libcni.NetworkConfigList, rt *libcni.RuntimeConf) error {
			assert.Equal(t, "fireactions", list.Name)
			assert.Equal(t, filepath.Join(root, "cache", rt.ContainerID), cacheDir)
			f.dels = append(f.dels, *rt)
			return f.delErr[rt.ContainerID]
		},
		teardownIPMasq: func(ipns []*net.IPNet, network, ifName, containerID string) error {
			assert.Equal(t, "fireactions", network)
			assert.Equal(t, "eth0", ifName)
			for _, ipn := range ipns {
				f.masq[containerID] = append(f.masq[containerID], ipn.String())
			}
			return nil
		},
		unmountNetNS: func(path string) error {
			f.unmounted = append(f.unmounted, path)
			return nil
		},
	}

	return f
}

func (f *sweepFixture) writeLease(t *testing.T, addr, content string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(f.leaseDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(f.leaseDir, addr), []byte(content), 0o600))
}

func (f *sweepFixture) writeCachedResult(t *testing.T, vmID string) {
	t.Helper()
	dir := filepath.Join(f.sweeper.cacheDir, vmID, "results")
	require.NoError(t, os.MkdirAll(dir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "fireactions-"+vmID+"-eth0"), []byte("{}"), 0o600))
}

func TestCNISweeperSweep(t *testing.T) {
	f := newSweepFixture(t)
	p := newTestPool()

	const (
		leaked    = "amuse-00000000000000000000000a"
		oldFormat = "amuse-00000000000000000000000b"
		live      = "amuse-00000000000000000000000c"
		emptyDir  = "amuse-00000000000000000000000d"
		withNetNS = "amuse-00000000000000000000000e"
		delFails  = "amuse-00000000000000000000000f"
		otherPool = "agents-00000000000000000000000a"
	)

	f.writeLease(t, "192.168.128.10", leaked+"\r\neth0")
	f.writeLease(t, "192.168.128.11", oldFormat)
	f.writeLease(t, "192.168.128.12", live+"\r\neth0")
	f.writeLease(t, "192.168.128.13", otherPool+"\r\neth0")
	f.writeLease(t, "192.168.128.14", delFails+"\r\neth0")
	f.writeLease(t, "last_reserved_ip.0", "192.168.128.14")
	f.writeLease(t, "lock", "")

	f.writeCachedResult(t, leaked)
	f.writeCachedResult(t, live)
	f.writeCachedResult(t, otherPool)
	f.writeCachedResult(t, delFails)
	require.NoError(t, os.MkdirAll(filepath.Join(f.sweeper.cacheDir, emptyDir, "results"), 0o750))
	require.NoError(t, os.MkdirAll(filepath.Join(f.sweeper.cacheDir, "results"), 0o750))

	require.NoError(t, os.MkdirAll(f.sweeper.netNSDir, 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(f.sweeper.netNSDir, withNetNS), nil, 0o600))

	f.delErr[delFails] = errors.New("plugin failed")

	isLive := func(vmID string) bool { return vmID == live }

	swept, err := f.sweeper.sweep(context.Background(), p.ownsVM, isLive)
	require.NoError(t, err)
	assert.Equal(t, 4, swept)

	assert.Equal(t, []libcni.RuntimeConf{
		{ContainerID: leaked, IfName: "eth0"},
		{ContainerID: oldFormat, IfName: "eth0"},
		{ContainerID: withNetNS, IfName: "eth0", NetNS: filepath.Join(f.sweeper.netNSDir, withNetNS)},
		{ContainerID: delFails, IfName: "eth0"},
	}, f.dels)

	assert.Equal(t, map[string][]string{
		leaked:    {"192.168.128.10/32"},
		oldFormat: {"192.168.128.11/32"},
	}, f.masq)

	assert.Equal(t, []string{filepath.Join(f.sweeper.netNSDir, withNetNS)}, f.unmounted)
	assert.NoFileExists(t, filepath.Join(f.sweeper.netNSDir, withNetNS))

	for _, vmID := range []string{leaked, oldFormat, emptyDir} {
		assert.NoDirExists(t, filepath.Join(f.sweeper.cacheDir, vmID))
	}
	for _, vmID := range []string{live, otherPool, delFails} {
		assert.DirExists(t, filepath.Join(f.sweeper.cacheDir, vmID))
	}
	assert.DirExists(t, filepath.Join(f.sweeper.cacheDir, "results"))
}

func TestCNISweeperSweepWithoutState(t *testing.T) {
	f := newSweepFixture(t)
	p := newTestPool()

	swept, err := f.sweeper.sweep(context.Background(), p.ownsVM, func(string) bool { return false })
	require.NoError(t, err)
	assert.Equal(t, 0, swept)
	assert.Empty(t, f.dels)
}

func TestCNISweeperSweepWithoutConfig(t *testing.T) {
	f := newSweepFixture(t)
	f.sweeper.confDir = filepath.Join(t.TempDir(), "missing")
	p := newTestPool()

	_, err := f.sweeper.sweep(context.Background(), p.ownsVM, func(string) bool { return false })
	require.Error(t, err)
	assert.Empty(t, f.dels)
}

func TestReadHostLocalLeases(t *testing.T) {
	dir := t.TempDir()
	require.NoError(t, os.WriteFile(filepath.Join(dir, "192.168.128.10"), []byte("vm-a\r\neth0"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "192.168.128.11"), []byte("vm-a\r\neth1"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "192.168.128.12"), []byte("vm-b"), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "192.168.128.13"), []byte(""), 0o600))
	require.NoError(t, os.WriteFile(filepath.Join(dir, "last_reserved_ip.0"), []byte("192.168.128.12"), 0o600))
	require.NoError(t, os.Mkdir(filepath.Join(dir, "192.168.128.14"), 0o750))

	leases, err := readHostLocalLeases(dir)
	require.NoError(t, err)
	assert.Equal(t, map[string][]net.IP{
		"vm-a": {net.ParseIP("192.168.128.10"), net.ParseIP("192.168.128.11")},
		"vm-b": {net.ParseIP("192.168.128.12")},
	}, leases)

	leases, err = readHostLocalLeases(filepath.Join(dir, "missing"))
	require.NoError(t, err)
	assert.Empty(t, leases)
}

func TestRemoveEmptyCNICacheDir(t *testing.T) {
	root := t.TempDir()

	empty := filepath.Join(root, "empty")
	require.NoError(t, os.MkdirAll(filepath.Join(empty, "results"), 0o750))
	require.NoError(t, removeEmptyCNICacheDir(empty))
	assert.NoDirExists(t, empty)

	withResult := filepath.Join(root, "with-result")
	require.NoError(t, os.MkdirAll(filepath.Join(withResult, "results"), 0o750))
	require.NoError(t, os.WriteFile(filepath.Join(withResult, "results", "fireactions-vm-eth0"), []byte("{}"), 0o600))
	require.NoError(t, removeEmptyCNICacheDir(withResult))
	assert.DirExists(t, withResult)

	require.NoError(t, removeEmptyCNICacheDir(filepath.Join(root, "missing")))
}

func TestLogrusWarnHook(t *testing.T) {
	var buf bytes.Buffer
	logger := zerolog.New(&buf)

	sdkLogger := logrus.New()
	sdkLogger.SetLevel(logrus.WarnLevel)
	sdkLogger.SetOutput(&bytes.Buffer{})
	sdkLogger.AddHook(&logrusWarnHook{logger: &logger, vmID: "amuse-00000000000000000000000a"})

	sdkLogger.Info("not forwarded")
	sdkLogger.Errorf("failed to cleanup after VM exit: %v", errors.New("failed to delete CNI network list"))

	out := buf.String()
	assert.NotContains(t, out, "not forwarded")
	assert.Contains(t, out, `"level":"error"`)
	assert.Contains(t, out, `"vm":"amuse-00000000000000000000000a"`)
	assert.Contains(t, out, "failed to cleanup after VM exit: failed to delete CNI network list")
}
