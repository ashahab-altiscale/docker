package lxc

import (
	"fmt"
	"sync"
	"os"
	"os/exec"
	"io/ioutil"
	"encoding/json"
	"path"
	"path/filepath"
	"strconv"
	"regexp"
	"time"
	"syscall"
	"github.com/docker/docker/daemon/execdriver"
	log "github.com/Sirupsen/logrus"
	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/configs"
	"github.com/docker/libcontainer/cgroups"
	"github.com/docker/docker/pkg/version"
	"strings"
	"bytes"
	"github.com/docker/docker/utils"
)

// network is an internal struct used to setup container networks.
type network struct {
	configs.Network

	// TempVethPeerName is a unique tempory veth peer name that was placed into
	// the container's namespace.
	TempVethPeerName string `json:"temp_veth_peer_name"`
}

// initConfig is used for transferring parameters from Exec() to Init()
type initConfig struct {
	Args     []string        `json:"args"`
	Env      []string        `json:"env"`
	Cwd      string          `json:"cwd"`
	User     string          `json:"user"`
	Config   *configs.Config `json:"config"`
	Console  string          `json:"console"`
	Networks []*network      `json:"network"`
}

type initProcess struct {
	cmd        *exec.Cmd
	parentPipe *os.File
	childPipe  *os.File
	config     *initConfig
	manager    cgroups.Manager
}

type parentProcess interface {
	// pid returns the pid for the running process.                            n
	pid() int

	// start starts the process execution.
	start() error

	// send a SIGKILL to the process and wait for the exit.
	terminate() error

	// wait waits on the process returning the process state.
	wait() (*os.ProcessState, error)

	// startTime return's the process start time.
	startTime() (string, error)

	signal(os.Signal) error
}

type Container struct {
	m     sync.Mutex
	id     string
	config *configs.Config
	cgroupManager cgroups.Manager
	initPath      string
	initArgs      []string
	initProcess   parentProcess
	root   string
	sharedRoot bool
	LxcConf []utils.KeyValuePair
}

type ipc struct {
	HostIpc bool
	ContainerPID int
}

func (c *Container) ID() string {
	return c.id
}

func (c *Container) Status() (libcontainer.Status, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.currentStatus()
}

func (c *Container) State() (*libcontainer.State, error) {
	c.m.Lock()
	defer c.m.Unlock()
	return c.currentState()
}

func (c *Container) Config() configs.Config {
	return *c.config
}

func (c *Container) Processes() ([]int, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *Container) Stats() (*libcontainer.Stats, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *Container) Set(config configs.Config) error {
	c.m.Lock()
	c.config = &config
	c.m.Unlock()
	return nil
}

func (c *Container) version() string {
	var (
		version string
		output  []byte
		err     error
	)
	if _, errPath := exec.LookPath("lxc-version"); errPath == nil {
		output, err = exec.Command("lxc-version").CombinedOutput()
	} else {
		output, err = exec.Command("lxc-start", "--version").CombinedOutput()
	}
	if err == nil {
		version = strings.TrimSpace(string(output))
		if parts := strings.SplitN(version, ":", 2); len(parts) == 2 {
			version = strings.TrimSpace(parts[1])
		}
	}
	return version
}

func (c *Container) getNamespace(t configs.NamespaceType) (*configs.Namespace, error) {
	for _, ns := range c.config.Namespaces{
		if ns.Type == t {
			return &ns, nil
		}
    }
	return nil, fmt.Errorf("%v not found.", t)
}

func getNsPid(ns *configs.Namespace) (int,error) {
	re, err := regexp.Compile(`/proc/(\d+)/ns/`)
	if err != nil {
		return -1, err
	}
	log.Debugf("network namespace path %s", ns.Path)
	res := re.FindAllStringSubmatch(ns.Path, -1)
	return strconv.Atoi(res[1][0])
}

func (c *Container) ipc() (*ipc, error) {
	namespaces := c.config.Namespaces
	if namespaces.Contains(configs.NEWIPC) {
		 ns, err := c.getNamespace(configs.NEWIPC)
		 if err != nil {
			 return nil, err
		 }

		 if ns.Path == "" {
		   // have to create new namespace, return nothing
			 return nil, nil
		 }
		// NEWIPC exists and has a path, find pid
		pid, err := getNsPid(ns)
		if err != nil {
			return nil, err
		}
		return &ipc {
			ContainerPID: pid,
		}, nil
	} else {
		//no NEWIPC, shared with host
		return &ipc{
          HostIpc: true,
        }, nil
	}
      return nil, nil
}

func (c *Container) Start(process *libcontainer.Process) error {
	c.m.Lock()
	defer c.m.Unlock()
	log.Debugf("Container root %s", c.root)
	status, err := c.currentStatus()
	if err != nil {
		return err
	}
	doInit := status == libcontainer.Destroyed
	initMount := &configs.Mount{
		Device: "bind",
		Flags:  syscall.MS_BIND | syscall.MS_REC,
	}
	initMount.Flags  |= syscall.MS_RDONLY
	initMount.Source = c.initPath
	initMount.Destination = "/.dockerinit"

	c.config.Mounts = append(c.config.Mounts, initMount)
	if err := c.generateEnvConfig(process.Env); err != nil {
		return err
	}
	configPath, err := c.generateLXCConfig(c.newInitConfig(process))


	params := []string{
		"lxc-start",
		"-n", c.ID(),
		"-f", configPath,
		"-q",
	}
	network := c.config.Networks[0]

	// From lxc>=1.1 the default behavior is to daemonize containers after start
	lxcVersion := version.Version(c.version())
	if lxcVersion.GreaterThanOrEqualTo(version.Version("1.1")) {
		params = append(params, "-F")
	}

	networkNs, err := c.getNamespace(configs.NEWNET)

	if networkNs != nil && networkNs.Path != ""{
		nspid, err := getNsPid(networkNs)
		if err != nil {
			return err
		}
		params = append(params,
			"--share-net", strconv.Itoa(nspid),
		)
	}

	ipc, err := c.ipc();
	if err != nil {
	  return err
    }

	if ipc != nil {
		if ipc.ContainerPID != -1 {
			params = append(params,
				"--share-ipc", strconv.Itoa(ipc.ContainerPID),
			)
		} else if ipc.HostIpc {
			params = append(params,
				"--share-ipc", "1",
			)
		}
	}

	params = append(params,
		"--",
		c.initPath,
	)

	if network.Address != "" {
		params = append(params,
			"-g", network.Gateway,
			"-i", network.Address,
		)
	}
	params = append(params,
		"-mtu", strconv.Itoa(network.Mtu),
	)

	if process.User != "" {
		params = append(params, "-u", process.User)
	}
	privileged := c.config.Cgroups.AllowAllDevices
	if privileged {
		if c.config.AppArmorProfile == "unconfined" {
			params[0] = path.Join(c.root, "lxc-start-unconfined")

		}
		params = append(params, "-privileged")
	}

	if process.Cwd != "" {
		params = append(params, "-w", process.Cwd)
	}

	params = append(params, "--")
	params = append(params, process.Args...)

	if c.sharedRoot {
		// lxc-start really needs / to be non-shared, or all kinds of stuff break
		// when lxc-start unmount things and those unmounts propagate to the main
		// mount namespace.
		// What we really want is to clone into a new namespace and then
		// mount / MS_REC|MS_SLAVE, but since we can't really clone or fork
		// without exec in go we have to do this horrible shell hack...
		shellString :=
			"mount --make-rslave /; exec " +
					shellQuoteArguments(params)

		params = []string{
			"unshare", "-m", "--", "/bin/sh", "-c", shellString,
		}
	}
	log.Debugf("lxc params %s", params)
	var (
		name = params[0]
		arg  = params[1:]
	)

	aname, err := exec.LookPath(name)
	if err != nil {
		aname = name
	}
	process.Args = append([]string{aname, name}, arg...)
	parent, err := c.newParentProcess(process, doInit)

	if err := createDeviceNodes(c.config.Rootfs, c.config.Devices); err != nil {
		return err
    }

	if err := parent.start(); err != nil {
		return err
	}

var (
	waitLock = make(chan struct{})
)

//go func() {
//	if err := lxc_command.Wait(); err != nil {
//		if _, ok := err.(*exec.ExitError); !ok { // Do not propagate the error if it's simply a status code != 0
//			waitErr = err
//		}
//	}
//	close(waitLock)
//}()

//terminate := func(terr error) (error) {
//	if process.cmd.Process != nil {
//		process.cmd.Process.Kill()
//		process.cmd.Process.Wait()
//	}
//	return terr
//}

if _, err := c.waitForStart(waitLock); err != nil {
	return err
}

	return nil
}

func quote(word string, buf *bytes.Buffer) {
	// Bail out early for "simple" strings
	if word != "" && !strings.ContainsAny(word, "\\'\"`${[|&;<>()~*?! \t\n") {
		buf.WriteString(word)
		return
	}

	buf.WriteString("'")

	for i := 0; i < len(word); i++ {
		b := word[i]
		if b == '\'' {
			// Replace literal ' with a close ', a \', and a open '
			buf.WriteString("'\\''")
		} else {
			buf.WriteByte(b)
		}
	}

	buf.WriteString("'")
}


// Take a list of strings and escape them so they will be handled right
// when passed as arguments to an program via a shell
func shellQuoteArguments(args []string) string {
	var buf bytes.Buffer
	for i, arg := range args {
		if i != 0 {
			buf.WriteByte(' ')
		}
		quote(arg, &buf)
	}
	return buf.String()
}

// Return an map of susbystem -> container cgroup
func cgroupPaths(containerId string) (map[string]string, error) {
	subsystems, err := cgroups.GetAllSubsystems()
	if err != nil {
		return nil, err
	}
	log.Debugf("subsystems: %s", subsystems)
	paths := make(map[string]string)
	for _, subsystem := range subsystems {
		cgroupRoot, cgroupDir, err := findCgroupRootAndDir(subsystem)
		log.Debugf("cgroup path %s %s", cgroupRoot, cgroupDir)
		if err != nil {
			//unsupported subystem
			continue
		}
		path := filepath.Join(cgroupRoot, cgroupDir, "lxc", containerId)
		paths[subsystem] = path
	}

	return paths, nil
}

func findCgroupRootAndDir(subsystem string) (string, string, error) {
	cgroupRoot, err := cgroups.FindCgroupMountpoint(subsystem)
	if err != nil {
		return "", "", err
	}

	cgroupDir, err := cgroups.GetThisCgroupDir(subsystem)
	if err != nil {
		return "", "", err
	}
	return cgroupRoot, cgroupDir, nil
}

// this is copy from old libcontainer nodes.go
func createDeviceNodes(rootfs string, nodesToCreate []*configs.Device) error {
	oldMask := syscall.Umask(0000)
	defer syscall.Umask(oldMask)

	for _, node := range nodesToCreate {
		if err := createDeviceNode(rootfs, node); err != nil {
			return err
		}
	}
	return nil
}

// Creates the device node in the rootfs of the container.
func createDeviceNode(rootfs string, node *configs.Device) error {
	var (
		dest   = filepath.Join(rootfs, node.Path)
		parent = filepath.Dir(dest)
	)

	if err := os.MkdirAll(parent, 0755); err != nil {
		return err
	}

	fileMode := node.FileMode
	switch node.Type {
	case 'c':
		fileMode |= syscall.S_IFCHR
	case 'b':
		fileMode |= syscall.S_IFBLK
	default:
		return fmt.Errorf("%c is not a valid device type for device %s", node.Type, node.Path)
	}

	if err := syscall.Mknod(dest, uint32(fileMode), node.Mkdev()); err != nil && !os.IsExist(err) {
		return fmt.Errorf("mknod %s %s", node.Path, err)
	}

	if err := syscall.Chown(dest, int(node.Uid), int(node.Gid)); err != nil {
		return fmt.Errorf("chown %s to %d:%d", node.Path, node.Uid, node.Gid)
	}

	return nil
}

/// Return the exit code of the process
// if the process has not exited -1 will be returned
func getExitCode(cmd exec.Cmd) int {
	if cmd.ProcessState == nil {
		return -1
	}
	return cmd.ProcessState.Sys().(syscall.WaitStatus).ExitStatus()
}


func (c *Container) containerDir() string {
	return c.root
}

// wait for the process to start and return the pid for the process
func (c *Container) waitForStart(waitLock chan struct{}) (int, error) {
	var (
		err    error
		output []byte
	)
	// We wait for the container to be fully running.
	// Timeout after 5 seconds. In case of broken pipe, just retry.
	// Note: The container can run and finish correctly before
	// the end of this loop
	for now := time.Now(); time.Since(now) < 5*time.Second; {
		select {
		case <-waitLock:
			// If the process dies while waiting for it, just return
			return -1, nil
		default:
		}

		output, err = c.getInfo(c.ID())
		if err == nil {
			info, err := parseLxcInfo(string(output))
			if err != nil {
				return -1, err
			}
			if info.Running {
				return info.Pid, nil
			}
		}
		time.Sleep(50 * time.Millisecond)
	}
	return -1, execdriver.ErrNotRunning
}

func newPipe() (parent *os.File, child *os.File, err error) {
	fds, err := syscall.Socketpair(syscall.AF_LOCAL, syscall.SOCK_STREAM|syscall.SOCK_CLOEXEC, 0)
	if err != nil {
		return nil, nil, err
	}
	return os.NewFile(uintptr(fds[1]), "parent"), os.NewFile(uintptr(fds[0]), "child"), nil
}

func (c *Container) commandTemplate(p *libcontainer.Process, childPipe *os.File) (*exec.Cmd, error) {
	cmd := &exec.Cmd{
		Path: c.initPath,
		Args: c.initArgs,
	}
	cmd.Stdin = p.Stdin
	cmd.Stdout = p.Stdout
	cmd.Stderr = p.Stderr
	cmd.Dir = c.config.Rootfs
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.ExtraFiles = []*os.File{childPipe}
	cmd.SysProcAttr.Pdeathsig = syscall.SIGKILL
	if c.config.ParentDeathSignal > 0 {
		cmd.SysProcAttr.Pdeathsig = syscall.Signal(c.config.ParentDeathSignal)
	}
	return cmd, nil
}

func (c *Container) newInitProcess(p *libcontainer.Process, cmd *exec.Cmd, parentPipe, childPipe *os.File) (*initProcess, error) {
	return &initProcess{
		cmd:        cmd,
		childPipe:  childPipe,
		parentPipe: parentPipe,
		manager:    c.cgroupManager,
		config:     c.newInitConfig(p),
	}, nil
}

func (c *Container) newParentProcess(p *libcontainer.Process, doInit bool) (parentProcess, error) {
	parentPipe, childPipe, err := newPipe()
	if err != nil {
		return nil, err
	}
	cmd, err := c.commandTemplate(p, childPipe)
	if err != nil {
		return nil, err
	}
	return c.newInitProcess(p, cmd, parentPipe, childPipe)
}

func (c *Container) generateLXCConfig(i *initConfig) (string, error) {
	root := path.Join(c.root, "config.lxc")

	fo, err := os.Create(root)
	if err != nil {
		return "", err
	}
	defer fo.Close()
	lxcConf := make([]string, len(c.LxcConf))
	for ind, conf := range c.LxcConf  {
		lxcStr := fmt.Sprintf("%s = %s", conf.Key, conf.Value)
		lxcConf[ind] = lxcStr
	}
	if err := LxcTemplateCompiled.Execute(fo, struct {
			*configs.Config
			AppArmor bool
			Privileged bool
			Env []string
			Console string
		    LxcConf []string

	}{
		Config:  i.Config,
		AppArmor: (c.config.AppArmorProfile == "unconfined"),
		Privileged: c.config.Cgroups.AllowAllDevices,
		Env: i.Env,
		Console: i.Console,
		LxcConf: lxcConf,
	}); err != nil {
		return "", err
	}

	return root, nil
}

func (c *Container) generateEnvConfig(env []string) error {
	data, err := json.Marshal(env)
	if err != nil {
		return err
	}
	p := path.Join(c.containerDir(), "config.env")

	c.config.Mounts = append(c.config.Mounts, &configs.Mount{
			Device: "bind",
			Flags:  syscall.MS_BIND | syscall.MS_REC | syscall.MS_RDONLY,
			Source:      p,
			Destination: "/.dockerenv",
		})

return ioutil.WriteFile(p, data, 0600)
}

func (c *Container) Destroy() error {
	return fmt.Errorf("not implemented")
}

func (c *Container) Pause() error {
	return fmt.Errorf("not implemented")
}

func (c *Container) Resume() error {
	return fmt.Errorf("not implemented")
}

func (c *Container) NotifyOOM() (<-chan struct{}, error) {
	paths, err := cgroupPaths(c.ID())
	if err != nil {
		return nil, err
	}
	return notifyOnOOM(paths)
}

// copy from libcontainer
func notifyOnOOM(paths map[string]string) (<-chan struct{}, error) {
	dir := paths["memory"]
	if dir == "" {
		return nil, fmt.Errorf("There is no path for %q in state", "memory")
	}
	oomControl, err := os.Open(filepath.Join(dir, "memory.oom_control"))
	if err != nil {
		return nil, err
	}
	fd, _, syserr := syscall.RawSyscall(syscall.SYS_EVENTFD2, 0, syscall.FD_CLOEXEC, 0)
	if syserr != 0 {
		oomControl.Close()
		return nil, syserr
	}

	eventfd := os.NewFile(fd, "eventfd")

	eventControlPath := filepath.Join(dir, "cgroup.event_control")
	data := fmt.Sprintf("%d %d", eventfd.Fd(), oomControl.Fd())
	if err := ioutil.WriteFile(eventControlPath, []byte(data), 0700); err != nil {
		eventfd.Close()
		oomControl.Close()
		return nil, err
	}
	ch := make(chan struct{})
	go func() {
		defer func() {
			close(ch)
			eventfd.Close()
			oomControl.Close()
		}()
		buf := make([]byte, 8)
		for {
			if _, err := eventfd.Read(buf); err != nil {
				return
			}
			// When a cgroup is destroyed, an event is sent to eventfd.
			// So if the control path is gone, return instead of notifying.
			if _, err := os.Lstat(eventControlPath); os.IsNotExist(err) {
				return
			}
			ch <- struct{}{}
		}
	}()
	return ch, nil
}

func (d *Container) getInfo(id string) ([]byte, error) {
	return exec.Command("lxc-info", "-s", "-n", id).CombinedOutput()
}

func (c *Container) currentState() (*libcontainer.State, error) {
	status, err := c.currentStatus()
	if err != nil {
		return nil, err
	}
	if status == libcontainer.Destroyed {
		return nil, fmt.Errorf("container destroyed")
	}
	startTime, err := c.initProcess.startTime()
	if err != nil {
		return nil, err
	}
	paths, err := cgroupPaths(c.ID())
	state := &libcontainer.State{
		ID:                   c.ID(),
		Config:               *c.config,
		InitProcessPid:       c.initProcess.pid(),
		InitProcessStartTime: startTime,
		CgroupPaths:          paths,
		NamespacePaths:       make(map[configs.NamespaceType]string),
	}
	for _, ns := range c.config.Namespaces {
		state.NamespacePaths[ns.Type] = ns.GetPath(c.initProcess.pid())
	}
	return state, nil
}

func (c *Container) currentStatus() (libcontainer.Status, error) {
	if c.initProcess == nil {
		return libcontainer.Destroyed, nil
	}

	output, err := c.getInfo(c.ID())
	if err != nil {
		log.Errorf("Error getting info for lxc container %s: %s (%s)", c.ID(), err, output)
		if err == syscall.ESRCH {
			return libcontainer.Destroyed, nil
		}
		return 0, err
	}
	if strings.Contains(string(output), "RUNNING") {
		return libcontainer.Running, nil
	}

	if c.config.Cgroups != nil && c.config.Cgroups.Freezer == configs.Frozen {
		return libcontainer.Paused, nil
	}

	if strings.Contains(string(output), "PAUSED") {
		return libcontainer.Paused, nil
	}

	return libcontainer.Destroyed, nil
}

func (c *Container) newInitConfig(process *libcontainer.Process) *initConfig {
	return &initConfig{
		Config:  c.config,
		Args:    process.Args,
		Env:     process.Env,
		User:    process.User,
		Cwd:     process.Cwd,
		Console: process.ConsolePath,
	}
}
