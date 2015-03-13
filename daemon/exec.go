package daemon

import (
	"fmt"
	"io"
	"io/ioutil"
	"os/exec"
	"strings"
	"sync"
	"syscall"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/engine"
	"github.com/docker/docker/pkg/broadcastwriter"
	"github.com/docker/docker/pkg/common"
	"github.com/docker/docker/pkg/ioutils"
	"github.com/docker/docker/runconfig"
	"github.com/docker/libcontainer"
	_ "github.com/docker/libcontainer/nsenter"
	"github.com/docker/libcontainer/utils"
)

type execConfig struct {
	sync.Mutex
	ID          string
	Running     bool
	ExitCode    int
	ExecProcess *libcontainer.Process
	StreamConfig
	OpenStdin  bool
	OpenStderr bool
	OpenStdout bool
	Container  *Container
	Tty        bool
	terminal   terminal
}

type execStore struct {
	s map[string]*execConfig
	sync.RWMutex
}

func newExecStore() *execStore {
	return &execStore{s: make(map[string]*execConfig, 0)}
}

func (e *execStore) Add(id string, execConfig *execConfig) {
	e.Lock()
	e.s[id] = execConfig
	e.Unlock()
}

func (e *execStore) Get(id string) *execConfig {
	e.RLock()
	res := e.s[id]
	e.RUnlock()
	return res
}

func (e *execStore) Delete(id string) {
	e.Lock()
	delete(e.s, id)
	e.Unlock()
}

func (e *execStore) List() []string {
	var IDs []string
	e.RLock()
	for id := range e.s {
		IDs = append(IDs, id)
	}
	e.RUnlock()
	return IDs
}

func (execConfig *execConfig) Resize(h, w int) error {
	if execConfig.terminal != nil {
		return execConfig.terminal.Resize(h, w)
	}
	return nil
}

func (d *Daemon) registerExecCommand(execConfig *execConfig) {
	// Storing execs in container in order to kill them gracefully whenever the container is stopped or removed.
	execConfig.Container.execCommands.Add(execConfig.ID, execConfig)
	// Storing execs in daemon for easy access via remote API.
	d.execCommands.Add(execConfig.ID, execConfig)
}

func (d *Daemon) getExecConfig(name string) (*execConfig, error) {
	if execConfig := d.execCommands.Get(name); execConfig != nil {
		if !execConfig.Container.IsRunning() {
			return nil, fmt.Errorf("Container %s is not running", execConfig.Container.ID)
		}
		return execConfig, nil
	}

	return nil, fmt.Errorf("No such exec instance '%s' found in daemon", name)
}

func (d *Daemon) unregisterExecCommand(execConfig *execConfig) {
	execConfig.Container.execCommands.Delete(execConfig.ID)
	d.execCommands.Delete(execConfig.ID)
}

func (d *Daemon) getActiveContainer(name string) (*Container, error) {
	container, err := d.Get(name)
	if err != nil {
		return nil, err
	}

	if !container.IsRunning() {
		return nil, fmt.Errorf("Container %s is not running", name)
	}
	if container.IsPaused() {
		return nil, fmt.Errorf("Container %s is paused, unpause the container before exec", name)
	}
	return container, nil
}

func (d *Daemon) ContainerExecCreate(job *engine.Job) engine.Status {
	if len(job.Args) != 1 {
		return job.Errorf("Usage: %s [options] container command [args]", job.Name)
	}

	if strings.HasPrefix(d.FactoryType(), "lxc") {
		return job.Error(fmt.Errorf("Exec is not supported for lxc exec driver"))
	}

	var name = job.Args[0]

	container, err := d.getActiveContainer(name)
	if err != nil {
		return job.Error(err)
	}

	config, err := runconfig.ExecConfigFromJob(job)
	if err != nil {
		return job.Error(err)
	}

	execProcess := &libcontainer.Process{
		Args: config.Cmd,
		Env:  container.ctInitProcess.Env,
		User: container.ctInitProcess.User,
		Cwd:  container.ctInitProcess.Cwd,
	}

	execConfig := &execConfig{
		ID:           common.GenerateRandomID(),
		OpenStdin:    config.AttachStdin,
		OpenStdout:   config.AttachStdout,
		OpenStderr:   config.AttachStderr,
		StreamConfig: StreamConfig{},
		ExecProcess:  execProcess,
		Container:    container,
		Running:      false,
		Tty:          config.Tty,
	}

	container.LogEvent("exec_create: " + strings.Join(execProcess.Args, " "))

	d.registerExecCommand(execConfig)

	job.Printf("%s\n", execConfig.ID)

	return engine.StatusOK
}

func (d *Daemon) ContainerExecStart(job *engine.Job) engine.Status {
	if len(job.Args) != 1 {
		return job.Errorf("Usage: %s [options] exec", job.Name)
	}

	var (
		cStdin           io.ReadCloser
		cStdout, cStderr io.Writer
		execName         = job.Args[0]
	)

	execConfig, err := d.getExecConfig(execName)
	if err != nil {
		return job.Error(err)
	}

	func() {
		execConfig.Lock()
		defer execConfig.Unlock()
		if execConfig.Running {
			err = fmt.Errorf("Error: Exec command %s is already running", execName)
		}
		execConfig.Running = true
	}()
	if err != nil {
		return job.Error(err)
	}

	log.Debugf("starting exec command %s in container %s", execConfig.ID, execConfig.Container.ID)
	container := execConfig.Container

	container.LogEvent("exec_start: " + strings.Join(execConfig.ExecProcess.Args, " "))

	if execConfig.OpenStdin {
		r, w := io.Pipe()
		go func() {
			defer w.Close()
			defer log.Debugf("Closing buffered stdin pipe")
			io.Copy(w, job.Stdin)
		}()
		cStdin = r
	}
	if execConfig.OpenStdout {
		cStdout = job.Stdout
	}
	if execConfig.OpenStderr {
		cStderr = job.Stderr
	}

	execConfig.StreamConfig.stderr = broadcastwriter.New()
	execConfig.StreamConfig.stdout = broadcastwriter.New()
	// Attach to stdin
	if execConfig.OpenStdin {
		execConfig.StreamConfig.stdin, execConfig.StreamConfig.stdinPipe = io.Pipe()
	} else {
		execConfig.StreamConfig.stdinPipe = ioutils.NopWriteCloser(ioutil.Discard) // Silently drop stdin
	}

	attachErr := d.Attach(&execConfig.StreamConfig, execConfig.OpenStdin, true, execConfig.Tty, cStdin, cStdout, cStderr)

	execErr := make(chan error)

	// Note, the execConfig data will be removed when the container
	// itself is deleted.  This allows us to query it (for things like
	// the exitStatus) even after the cmd is done running.

	go func() {
		err := container.Exec(execConfig)
		if err != nil {
			execErr <- fmt.Errorf("Cannot run exec command %s in container %s: %s", execName, container.ID, err)
		}
	}()

	select {
	case err := <-attachErr:
		if err != nil {
			return job.Errorf("attach failed with error: %s", err)
		}
		break
	case err := <-execErr:
		return job.Error(err)
	}

	return engine.StatusOK
}

func (container *Container) GetExecIDs() []string {
	return container.execCommands.List()
}

func (container *Container) Exec(execConfig *execConfig) error {
	container.Lock()
	defer container.Unlock()

	if !container.Running {
		return fmt.Errorf("Container %s is not running", container.ID)
	}

	p := execConfig.ExecProcess
	pipes := newPipes(execConfig.StreamConfig.stdin, execConfig.StreamConfig.stdout, execConfig.StreamConfig.stderr, execConfig.OpenStdin)
	term, err := pipes.attach(execConfig.Container.ctConfig, p, execConfig.Tty)
	if err != nil {
		return err
	}
	execConfig.terminal = term

	if err := container.ct.Start(p); err != nil {
		return err
	}

	go container.monitorExec(execConfig)

	return nil
}

func (container *Container) monitorExec(e *execConfig) error {
	exitCode := -1
	p := e.ExecProcess
	ps, err := p.Wait()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			log.Errorf("Error running command in existing container %s: %s", container.ID, err)
		} else {
			ps = exitErr.ProcessState
		}
	}
	if ps != nil {
		exitCode = utils.ExitStatus(ps.Sys().(syscall.WaitStatus))
	}
	e.ExitCode = exitCode
	e.Running = false

	log.Debugf("Exec task in container %s exited with code %d", container.ID, exitCode)
	if e.OpenStdin {
		if err := e.StreamConfig.stdin.Close(); err != nil {
			log.Errorf("Error closing stdin while running in %s: %s", container.ID, err)
		}
	}
	if err := e.StreamConfig.stdout.Clean(); err != nil {
		log.Errorf("Error closing stdout while running in %s: %s", container.ID, err)
	}
	if err := e.StreamConfig.stderr.Clean(); err != nil {
		log.Errorf("Error closing stderr while running in %s: %s", container.ID, err)
	}
	if e.terminal != nil {
		if err := e.terminal.Close(); err != nil {
			log.Errorf("Error closing terminal while running in container %s: %s", container.ID, err)
		}
	}

	return err
}
