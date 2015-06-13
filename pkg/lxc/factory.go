package lxc

import (
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path"
	"path/filepath"
	"io/ioutil"
	"strings"
	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/configs"
	"github.com/docker/libcontainer/configs/validate"
	"github.com/docker/libcontainer/cgroups"
	"github.com/docker/libcontainer/cgroups/fs"
	"github.com/docker/libcontainer/cgroups/systemd"
	log "github.com/Sirupsen/logrus"
)

const (
	stateFilename = "state.json"
)

type Factory struct {
	Root      string
	Validator validate.Validator
	// InitPath is the absolute path to the init binary.
	InitPath string

	// InitArgs are arguments for calling the init responsibilities for spawning
	// a container.
	InitArgs []string

	// NewCgroupsManager returns an initialized cgroups manager for a single container.
	NewCgroupsManager func(config *configs.Cgroup, paths map[string]string) cgroups.Manager
}

// InitPath returns an options func to configure a LinuxFactory with the
// provided absolute path to the init binary and arguements.
func InitPath(path string, args ...string) func(*Factory) error {
	return func(l *Factory) error {
		l.InitPath = path
		l.InitArgs = args
		return nil
	}
}

// InitArgs returns an options func to configure a LinuxFactory with the
// provided init arguments.
func InitArgs(args ...string) func(*Factory) error {
	return func(l *Factory) error {
		name := args[0]
		if filepath.Base(name) == name {
			if lp, err := exec.LookPath(name); err == nil {
				name = lp
			}
		}
		l.InitPath = name
		l.InitArgs = append([]string{name}, args[1:]...)
		return nil
	}
}

// SystemdCgroups is an options func to configure a LinuxFactory to return
// containers that use systemd to create and manage cgroups.
func SystemdCgroups(l *Factory) error {
	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		return &systemd.Manager{
	Cgroups: config,
	Paths:   paths,
	}
}
return nil
}

// Cgroupfs is an options func to configure a LinuxFactory to return
// containers that use the native cgroups filesystem implementation to
// create and manage cgroups.
func Cgroupfs(l *Factory) error {
	l.NewCgroupsManager = func(config *configs.Cgroup, paths map[string]string) cgroups.Manager {
		return &fs.Manager{
	Cgroups: config,
	Paths:   paths,
	}
}
return nil
}

func rootIsShared() bool {
	if data, err := ioutil.ReadFile("/proc/self/mountinfo"); err == nil {
		for _, line := range strings.Split(string(data), "\n") {
			cols := strings.Split(line, " ")
			if len(cols) >= 6 && cols[4] == "/" {
				return strings.HasPrefix(cols[6], "shared")
			}
		}
	}

	// No idea, probably safe to assume so
	return true
}

// New returns a linux based container factory based in the root directory and
// configures the factory with the provided option funcs.
func New(root string, options ...func(*Factory) error) (libcontainer.Factory, error) {
	if root != "" {
		if err := os.MkdirAll(root, 0700); err != nil {
			return nil, err
		}
	}
	f := &Factory{
		Root:      root,
		Validator: validate.New(),
	}
	InitArgs(os.Args[0], "init")(f)
	Cgroupfs(f)
	for _, opt := range options {
		if err := opt(f); err != nil {
			return nil, err
		}
	}
	// setup unconfined symlink
	if err := linkLxcStart(root); err != nil {
		return nil, err
	}
	log.Debugf("Factory root %s", root)
	return f, nil
}

func linkLxcStart(root string) error {
	sourcePath, err := exec.LookPath("lxc-start")
	if err != nil {
		return err
	}
	targetPath := path.Join(root, "lxc-start-unconfined")

	if _, err := os.Lstat(targetPath); err != nil && !os.IsNotExist(err) {
		return err
	} else if err == nil {
		if err := os.Remove(targetPath); err != nil {
			return err
		}
	}
	return os.Symlink(sourcePath, targetPath)
}

func (f *Factory) Create(id string, config *configs.Config) (libcontainer.Container, error) {
	if f.Root == "" {
		return nil, fmt.Errorf("invalid root")
	}
	if err := f.Validator.Validate(config); err != nil {
		return nil, err
	}
	containerRoot := filepath.Join(f.Root, id)
	if _, err := os.Stat(containerRoot); err == nil {
		return nil, fmt.Errorf("Container with id exists: %v", id)
	} else if !os.IsNotExist(err) {
		return nil, err
	}
	if err := os.MkdirAll(containerRoot, 0700); err != nil {
		return nil, err
	}
	return &Container{
		id:     id,
		root:   containerRoot,
		config: config,
		initPath:      f.InitPath,
		initArgs:      f.InitArgs,
		cgroupManager: f.NewCgroupsManager(config.Cgroups, nil),
		sharedRoot:    rootIsShared(),
	}, nil
}

func (f *Factory) Load(id string) (libcontainer.Container, error) {
	if f.Root == "" {
		return nil, fmt.Errorf("invalid root")
	}
	containerRoot := filepath.Join(f.Root, id)
	state, err := f.loadState(containerRoot)
	if err != nil {
		return nil, err
	}
	return &Container{
		id:     id,
		config: &state.Config,
		root:   containerRoot,
	}, nil
}

func (f *Factory) StartInitialization(pipefd uintptr) error {
	return fmt.Errorf("Not implemented")
}

func (f *Factory) Type() string {
	return "lxc"
}

func (l *Factory) loadState(root string) (*libcontainer.State, error) {
	f, err := os.Open(filepath.Join(root, stateFilename))
	if err != nil {
		if os.IsNotExist(err) {
			return nil, err
		}
		return nil, err
	}
	defer f.Close()
	var state *libcontainer.State
	if err := json.NewDecoder(f).Decode(&state); err != nil {
		return nil, err
	}
	return state, nil
}
