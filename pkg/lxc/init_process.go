// +build linux

package lxc

import (
	"io"
	"os"
	"os/exec"
	"syscall"
	"encoding/json"
	"github.com/docker/libcontainer/system"
)

type setnsProcess struct {
	cmd         *exec.Cmd
	parentPipe  *os.File
	childPipe   *os.File
	cgroupPaths map[string]string
	config      *initConfig
}

func (p *setnsProcess) startTime() (string, error) {
	return system.GetProcessStartTime(p.pid())
}

func (p *setnsProcess) signal(s os.Signal) error {
	return p.cmd.Process.Signal(s)
}

func (p *setnsProcess) start() (err error) {

	return nil
}

// execSetns runs the process that executes C code to perform the setns calls
// because setns support requires the C process to fork off a child and perform the setns
// before the go runtime boots, we wait on the process to die and receive the child's pid
// over the provided pipe.
func (p *setnsProcess) execSetns() error {

	return nil
}

// terminate sends a SIGKILL to the forked process for the setns routine then waits to
// avoid the process becomming a zombie.
func (p *setnsProcess) terminate() error {

	return nil
}

func (p *setnsProcess) wait() (*os.ProcessState, error) {

	return nil, nil
}

func (p *setnsProcess) pid() int {
	return p.cmd.Process.Pid
}

func (p *initProcess) pid() int {
	return p.cmd.Process.Pid
}

func (p *initProcess) start() error {
	defer p.parentPipe.Close()
	err := p.cmd.Start()
	p.childPipe.Close()
	if err != nil {
		return newSystemError(err)
	}
	// Do this before syncing with child so that no children
	// can escape the cgroup

	if err := p.sendConfig(); err != nil {
		return newSystemError(err)
	}
	// wait for the child process to fully complete and receive an error message
	// if one was encoutered
	var ierr *genericError
	if err := json.NewDecoder(p.parentPipe).Decode(&ierr); err != nil && err != io.EOF {
		return newSystemError(err)
	}
	if ierr != nil {
		return newSystemError(ierr)
	}
	return nil
}

func (p *initProcess) wait() (*os.ProcessState, error) {
	err := p.cmd.Wait()
	if err != nil {
		return p.cmd.ProcessState, err
	}

	return p.cmd.ProcessState, nil
}

func (p *initProcess) terminate() error {

	return nil
}

func (p *initProcess) startTime() (string, error) {
	return system.GetProcessStartTime(p.pid())
}

func (p *initProcess) sendConfig() error {
	// send the state to the container's init process then shutdown writes for the parent
	if err := json.NewEncoder(p.parentPipe).Encode(p.config); err != nil {
		return err
	}
	// shutdown writes for the parent side of the pipe
	return syscall.Shutdown(int(p.parentPipe.Fd()), syscall.SHUT_WR)
}


func (p *initProcess) signal(s os.Signal) error {
	return p.cmd.Process.Signal(s)
}
