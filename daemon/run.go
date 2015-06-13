package daemon

import (
	"io"
	"os"
	"os/exec"
	"syscall"

	"github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/term"
	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/configs"
	"github.com/docker/libcontainer/utils"
	"github.com/docker/docker/pkg/lxc"
)

// ExitStatus provides exit reasons for a container.
type ExitStatus struct {
	// The exit code with which the container exited.
	ExitCode int

	// Whether the container encountered an OOM.
	OOMKilled bool
}

type TtyConsole struct {
	console libcontainer.Console
}

func NewTtyConsole(console libcontainer.Console, pipes *pipes, rootuid int) (*TtyConsole, error) {
	tty := &TtyConsole{
		console: console,
	}

	if err := tty.AttachPipes(pipes); err != nil {
		tty.Close()
		return nil, err
	}

	return tty, nil
}

func (t *TtyConsole) Master() libcontainer.Console {
	return t.console
}

func (t *TtyConsole) Resize(h, w int) error {
	return term.SetWinsize(t.console.Fd(), &term.Winsize{Height: uint16(h), Width: uint16(w)})
}

func (t *TtyConsole) AttachPipes(pipes *pipes) error {
	go func() {
		if wb, ok := pipes.Stdout.(interface {
			CloseWriters() error
		}); ok {
			defer wb.CloseWriters()
		}

		io.Copy(pipes.Stdout, t.console)
	}()

	if pipes.Stdin != nil {
		go func() {
			io.Copy(t.console, pipes.Stdin)

			pipes.Stdin.Close()
		}()
	}

	return nil
}

func (t *TtyConsole) Close() error {
	return t.console.Close()
}

func (c *Container) ctRun() error {
	pipes := newPipes(c.stdin, c.stdout, c.stderr, c.Config.OpenStdin)
	term, err := pipes.attach(c.ctConfig, c.ctInitProcess, c.Config.Tty)
	if err != nil {
		return err
	}
	c.terminal = term

	cont, err := c.daemon.factory.Create(c.ID, c.ctConfig)
	if err != nil {
		return err
	}
	c.ct = cont
	lxcCt, ok := c.ct.(*lxc.Container); if ok {
		lxcCt.LxcConf = c.hostConfig.LxcConf
	}
	return cont.Start(c.ctInitProcess)
}

func (c *Container) ctWait() (*ExitStatus, error) {
	defer c.ct.Destroy()
	oomKillNotification, err := c.ct.NotifyOOM()
	if err != nil {
		oomKillNotification = nil
		logrus.Warnf("WARNING: Your kernel does not support OOM notifications: %s", err)
	}
	waitF := c.ctInitProcess.Wait
	if nss := c.ct.Config().Namespaces; !nss.Contains(configs.NEWPID) {
		// we need such hack for tracking processes with inerited fds,
		// because cmd.Wait() waiting for all streams to be copied
		waitF = waitInPIDHost(c.ctInitProcess, c.ct)
	}
	ps, err := waitF()
	if err != nil {
		exitErr, ok := err.(*exec.ExitError)
		if !ok {
			c.ct.Destroy()
			return &ExitStatus{ExitCode: -1}, err
		}
		ps = exitErr.ProcessState
	}
	c.ct.Destroy()

	_, oomKill := <-oomKillNotification

	return &ExitStatus{ExitCode: utils.ExitStatus(ps.Sys().(syscall.WaitStatus)), OOMKilled: oomKill}, nil
}

func waitInPIDHost(p *libcontainer.Process, c libcontainer.Container) func() (*os.ProcessState, error) {
	return func() (*os.ProcessState, error) {
		pid, err := p.Pid()
		if err != nil {
			return nil, err
		}

		// get processes for later kill
		processes, err := c.Processes()
		if err != nil {
			return nil, err
		}

		process, err := os.FindProcess(pid)
		s, err := process.Wait()
		if err != nil {
			exitErr, ok := err.(*exec.ExitError)
			if !ok {
				return s, err
			}
			s = exitErr.ProcessState
		}

		for _, pid := range processes {
			process, err := os.FindProcess(pid)
			if err != nil {
				logrus.Errorf("Failed to kill process: %d", pid)
				continue
			}
			process.Kill()
		}

		p.Wait()
		return s, err
	}
}
