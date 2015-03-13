package daemon

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"

	"github.com/docker/docker/pkg/reexec"
	"github.com/docker/docker/pkg/symlink"
	"github.com/docker/docker/pkg/ulimit"
	"github.com/docker/docker/utils"
	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/apparmor"
	"github.com/docker/libcontainer/configs"
	"github.com/docker/libcontainer/devices"
	lutils "github.com/docker/libcontainer/utils"
)

const initCommand = "libcontainer_init"

// terminal in an interface for drivers to implement
// if they want to support Close and Resize calls from
// the core
type terminal interface {
	io.Closer
	Resize(height, width int) error
}

type ttyTerminal interface {
	Master() libcontainer.Console
}

// pipes is a wrapper around a containers output for
// stdin, stdout, stderr
type pipes struct {
	Stdin          io.ReadCloser
	Stdout, Stderr io.Writer
}

func newPipes(stdin io.ReadCloser, stdout, stderr io.Writer, useStdin bool) *pipes {
	p := &pipes{
		Stdout: stdout,
		Stderr: stderr,
	}
	if useStdin {
		p.Stdin = stdin
	}
	return p
}

func (pi *pipes) attach(c *configs.Config, p *libcontainer.Process, tty bool) (terminal, error) {
	if tty {
		rootuid, err := c.HostUID()
		if err != nil {
			return nil, err
		}
		cons, err := p.NewConsole(rootuid)
		if err != nil {
			return nil, err
		}
		term, err := NewTtyConsole(cons, pi, rootuid)
		if err != nil {
			return nil, err
		}
		return term, nil
	}
	p.Stdout = pi.Stdout
	p.Stderr = pi.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		return nil, err
	}
	if pi.Stdin != nil {
		go func() {
			io.Copy(w, pi.Stdin)
			w.Close()
		}()
		p.Stdin = r
	}
	return nil, nil
}

func getEnv(key string, env []string) string {
	for _, pair := range env {
		parts := strings.Split(pair, "=")
		if parts[0] == key {
			return parts[1]
		}
	}
	return ""
}

func (c *Container) initConfig(env []string) {
	c.ctConfig = NewLibcontainerConfig()
	config := c.ctConfig
	config.Hostname = getEnv("HOSTNAME", env)
	config.Cgroups.Name = c.ID
	config.Readonlyfs = c.hostConfig.ReadonlyRootfs
	config.Rootfs = c.RootfsPath()
	if c.hostConfig.CgroupParent != "" {
		config.Cgroups.Parent = c.hostConfig.CgroupParent
	}

	// check to see if we are running in ramdisk to disable pivot root
	config.NoPivotRoot = os.Getenv("DOCKER_RAMDISK") != ""
}

func generateIfaceName() (string, error) {
	for i := 0; i < 10; i++ {
		name, err := lutils.GenerateRandomName("veth", 7)
		if err != nil {
			continue
		}
		if _, err := net.InterfaceByName(name); err != nil {
			if strings.Contains(err.Error(), "no such") {
				return name, nil
			}
			return "", err
		}
	}
	return "", errors.New("Failed to find name for new interface")
}

func (c *Container) fillConfigNetwork() error {
	config := c.ctConfig
	parts := strings.SplitN(string(c.hostConfig.NetworkMode), ":", 2)
	config.Networks = []*configs.Network{
		{
			Type: "loopback",
		},
	}
	switch parts[0] {
	case "none":
	case "host":
		config.Namespaces.Remove(configs.NEWNET)
		config.Networks = nil
	case "bridge", "": // empty string to support existing containers
		if !c.Config.NetworkDisabled {
			iName, err := generateIfaceName()
			if err != nil {
				return err
			}
			network := c.NetworkSettings
			vethNetwork := configs.Network{
				Name:              "eth0",
				HostInterfaceName: iName,
				Mtu:               c.daemon.config.Mtu,
				Address:           fmt.Sprintf("%s/%d", network.IPAddress, network.IPPrefixLen),
				MacAddress:        network.MacAddress,
				Gateway:           network.Gateway,
				Bridge:            network.Bridge,
				Type:              "veth",
			}
			if network.GlobalIPv6Address != "" {
				vethNetwork.IPv6Address = fmt.Sprintf("%s/%d", network.GlobalIPv6Address, network.GlobalIPv6PrefixLen)
				vethNetwork.IPv6Gateway = network.IPv6Gateway
			}
			config.Networks = append(config.Networks, &vethNetwork)
		}
	case "container":
		nc, err := c.getNetworkedContainer()
		if err != nil {
			return err
		}
		state, err := nc.ct.State()
		if err != nil {
			return err
		}
		config.Namespaces.Add(configs.NEWNET, state.NamespacePaths[configs.NEWNET])
	default:
		return fmt.Errorf("invalid network mode: %s", c.hostConfig.NetworkMode)
	}
	return nil
}

func (c *Container) fillConfigIPC() error {
	config := c.ctConfig
	if c.hostConfig.IpcMode.IsHost() {
		config.Namespaces.Remove(configs.NEWIPC)
		return nil
	}
	if c.hostConfig.IpcMode.IsContainer() {
		ic, err := c.getIpcContainer()
		if err != nil {
			return err
		}
		state, err := ic.ct.State()
		if err != nil {
			return err
		}
		config.Namespaces.Add(configs.NEWIPC, state.NamespacePaths[configs.NEWIPC])
		return nil
	}
	return nil
}

func (c *Container) fillConfigResources() {
	c.ctConfig.Cgroups.CpuShares = c.Config.CpuShares
	c.ctConfig.Cgroups.Memory = c.Config.Memory
	c.ctConfig.Cgroups.MemoryReservation = c.Config.Memory
	c.ctConfig.Cgroups.MemorySwap = c.Config.MemorySwap
	c.ctConfig.Cgroups.CpusetCpus = c.Config.Cpuset
}

func (c *Container) fillConfigRlimits() error {
	ulimits := c.hostConfig.Ulimits

	// Merge ulimits with daemon defaults
	ulIdx := make(map[string]*ulimit.Ulimit)
	for _, ul := range ulimits {
		ulIdx[ul.Name] = ul
	}
	for name, ul := range c.daemon.config.Ulimits {
		if _, exists := ulIdx[name]; !exists {
			ulimits = append(ulimits, ul)
		}
	}

	for _, limit := range ulimits {
		rl, err := limit.GetRlimit()
		if err != nil {
			return err
		}
		c.ctConfig.Rlimits = append(c.ctConfig.Rlimits, configs.Rlimit{
			Type: rl.Type,
			Hard: rl.Hard,
			Soft: rl.Soft,
		})
	}
	return nil
}

func (c *Container) fillConfigDevices() error {
	// Build lists of devices allowed and created within the container.
	userSpecifiedDevices := make([]*configs.Device, len(c.hostConfig.Devices))
	for i, deviceMapping := range c.hostConfig.Devices {
		device, err := devices.DeviceFromPath(deviceMapping.PathOnHost, deviceMapping.CgroupPermissions)
		if err != nil {
			return fmt.Errorf("error gathering device information while adding custom device %q: %s", deviceMapping.PathOnHost, err)
		}
		device.Path = deviceMapping.PathInContainer
		userSpecifiedDevices[i] = device
	}
	c.ctConfig.Cgroups.AllowedDevices = append(configs.DefaultAllowedDevices, userSpecifiedDevices...)

	c.ctConfig.Devices = append(configs.DefaultAutoCreatedDevices, userSpecifiedDevices...)
	return nil
}

func (c *Container) fillConfigPID() {
	if c.hostConfig.PidMode.IsHost() {
		c.ctConfig.Namespaces.Remove(configs.NEWPID)
	}
}

var allCaps = []string{
	"SETPCAP",
	"SYS_MODULE",
	"SYS_RAWIO",
	"SYS_PACCT",
	"SYS_ADMIN",
	"SYS_NICE",
	"SYS_RESOURCE",
	"SYS_TIME",
	"SYS_TTY_CONFIG",
	"MKNOD",
	"AUDIT_WRITE",
	"AUDIT_CONTROL",
	"MAC_OVERRIDE",
	"MAC_ADMIN",
	"NET_ADMIN",
	"SYSLOG",
	"CHOWN",
	"NET_RAW",
	"DAC_OVERRIDE",
	"FOWNER",
	"DAC_READ_SEARCH",
	"FSETID",
	"KILL",
	"SETGID",
	"SETUID",
	"LINUX_IMMUTABLE",
	"NET_BIND_SERVICE",
	"NET_BROADCAST",
	"IPC_LOCK",
	"IPC_OWNER",
	"SYS_CHROOT",
	"SYS_PTRACE",
	"SYS_BOOT",
	"LEASE",
	"SETFCAP",
	"WAKE_ALARM",
	"BLOCK_SUSPEND",
}

func (c *Container) fillCapPrivileged() error {
	config := c.ctConfig
	// clear readonly for /sys
	for i := range config.Mounts {
		if config.Mounts[i].Destination == "/sys" {
			config.Mounts[i].Flags &= ^syscall.MS_RDONLY
		}
	}
	config.ReadonlyPaths = nil
	config.MaskPaths = nil
	config.Capabilities = allCaps
	config.Cgroups.AllowAllDevices = true

	hostDevices, err := devices.HostDevices()
	if err != nil {
		return err
	}
	config.Devices = hostDevices

	if apparmor.IsEnabled() {
		config.AppArmorProfile = "unconfined"
	}
	return nil
}

func (c *Container) fillCapUnprivileged() error {
	var (
		newCaps []string
	)

	adds := c.hostConfig.CapAdd
	drops := c.hostConfig.CapDrop
	// look for invalid cap in the drop list
	for _, cap := range adds {
		if strings.ToLower(cap) == "all" {
			continue
		}
		if !utils.StringsContainsNoCase(allCaps, cap) {
			return fmt.Errorf("Unknown capability drop: %q", cap)
		}
	}

	// look for invalid cap in the add list
	for _, cap := range drops {
		if strings.ToLower(cap) == "all" {
			continue
		}
		if !utils.StringsContainsNoCase(allCaps, cap) {
			return fmt.Errorf("Unknown capability add: %q", cap)
		}
	}

	// handle --cap-add=all
	if utils.StringsContainsNoCase(adds, "all") {
		c.ctConfig.Capabilities = allCaps
	}

	if !utils.StringsContainsNoCase(drops, "all") {
		for _, cap := range c.ctConfig.Capabilities {
			// if we don't drop `all`, add back all the non-dropped caps
			if !utils.StringsContainsNoCase(drops, cap) {
				newCaps = append(newCaps, strings.ToUpper(cap))
			}
		}
	}

	for _, cap := range adds {
		// skip `all` aready handled above
		if strings.ToLower(cap) == "all" {
			continue
		}

		// add cap if not already in the list
		if !utils.StringsContainsNoCase(newCaps, cap) {
			newCaps = append(newCaps, strings.ToUpper(cap))
		}
	}
	c.ctConfig.Capabilities = newCaps
	return nil
}

func (c *Container) fillConfigCap() error {
	if c.hostConfig.Privileged {
		return c.fillCapPrivileged()
	}
	return c.fillCapUnprivileged()
}

func (c *Container) fillConfigLabels() {
	c.ctConfig.ProcessLabel = c.GetProcessLabel()
	c.ctConfig.MountLabel = c.GetMountLabel()
	c.ctConfig.AppArmorProfile = c.AppArmorProfile
}

func (c *Container) fillConfigProcess(env []string) {
	c.ctInitProcess = &libcontainer.Process{
		Args: append([]string{c.Path}, c.Args...),
		Env:  env,
		Cwd:  c.Config.WorkingDir,
		User: c.Config.User,
	}
}

func (c *Container) fillConfigMounts() error {
	config := c.ctConfig
	type mount struct {
		Source      string
		Destination string
		Writable    bool
		Slave       bool
	}
	var mounts []mount
	// for filtering existing mounts, which should be overriden
	userMounts := make(map[string]bool)
	// Mount user specified volumes
	// Note, these are not private because you may want propagation of (un)mounts from host
	// volumes. For instance if you use -v /usr:/usr and the host later mounts /usr/share you
	// want this new mount in the container
	// These mounts must be ordered based on the length of the path that it is being mounted to (lexicographic)
	for _, path := range c.sortedVolumeMounts() {
		mounts = append(mounts, mount{
			Source:      c.Volumes[path],
			Destination: path,
			Writable:    c.VolumesRW[path],
		})
		userMounts[path] = true
	}

	// Filter out mounts that are overriden by user supplied mounts
	var defaultMounts []*configs.Mount
	_, mountDev := userMounts["/dev"]
	for _, m := range config.Mounts {
		if !userMounts[m.Destination] {
			if mountDev && strings.HasPrefix(m.Destination, "/dev/") {
				continue
			}
			defaultMounts = append(defaultMounts, m)
		}
	}
	config.Mounts = defaultMounts

	if c.ResolvConfPath != "" {
		mounts = append(mounts, mount{
			Source:      c.ResolvConfPath,
			Destination: "/etc/resolv.conf",
			Writable:    true})
	}

	if c.HostnamePath != "" {
		mounts = append(mounts, mount{
			Source:      c.HostnamePath,
			Destination: "/etc/hostname",
			Writable:    true})
	}

	if c.HostsPath != "" {
		mounts = append(mounts, mount{
			Source:      c.HostsPath,
			Destination: "/etc/hosts",
			Writable:    true})
	}

	for _, m := range mounts {
		dest, err := symlink.FollowSymlinkInScope(filepath.Join(config.Rootfs, m.Destination), config.Rootfs)
		if err != nil {
			return err
		}
		flags := syscall.MS_BIND | syscall.MS_REC
		if !m.Writable {
			flags |= syscall.MS_RDONLY
		}
		if m.Slave {
			flags |= syscall.MS_SLAVE
		}

		config.Mounts = append(config.Mounts, &configs.Mount{
			Source:      m.Source,
			Destination: dest,
			Device:      "bind",
			Flags:       flags,
		})
	}
	return nil
}

func (c *Container) fillConfig(env []string) error {
	c.initConfig(env)
	c.fillConfigResources()
	c.fillConfigPID()
	c.fillConfigLabels()
	c.fillConfigProcess(env)

	if err := c.fillConfigDevices(); err != nil {
		return err
	}
	if err := c.fillConfigRlimits(); err != nil {
		return err
	}
	if err := c.fillConfigCap(); err != nil {
		return err
	}
	if err := c.fillConfigNetwork(); err != nil {
		return err
	}
	if err := c.fillConfigIPC(); err != nil {
		return err
	}
	if err := c.fillConfigMounts(); err != nil {
		return err
	}

	// TODO: this can be removed after lxc-conf is fully deprecated
	// XXX: lxc stub
	// XXX: lxc stub
	// XXX: lxc stub
	// XXX: lxc stub
	// XXX: lxc stub
	//lxcConfig, err := mergeLxcConfIntoOptions(c.hostConfig)
	//if err != nil {
	//return err
	//}
	return nil
}

func fatal(err error) {
	if lerr, ok := err.(libcontainer.Error); ok {
		lerr.Detail(os.Stderr)
		os.Exit(1)
	}

	fmt.Fprintln(os.Stderr, err)
	os.Exit(1)
}

func init() { reexec.Register(initCommand, initializer) }
func initializer() {
	runtime.GOMAXPROCS(1)
	runtime.LockOSThread()
	factory, err := libcontainer.New("")
	if err != nil {
		fatal(err)
	}
	if err := factory.StartInitialization(3); err != nil {
		fatal(err)
	}

	panic("unreachable")
}

func writeError(err error) {
	fmt.Fprint(os.Stderr, err)
	os.Exit(1)
}
