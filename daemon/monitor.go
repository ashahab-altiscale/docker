package daemon

import (
	"io"
	"os"
	"sync"
	"time"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/pkg/common"
	"github.com/docker/docker/runconfig"
	"github.com/docker/libcontainer"
)

const defaultTimeIncrement = 100

var failStatus = &ExitStatus{ExitCode: -1}

// containerMonitor monitors the execution of a container's main process.
// If a restart policy is specified for the container the monitor will ensure that the
// process is restarted based on the rules of the policy.  When the container is finally stopped
// the monitor will reset and cleanup any of the container resources such as networking allocations
// and the rootfs
type containerMonitor struct {
	mux sync.Mutex

	// container is the container being monitored
	container *Container

	// restartPolicy is the current policy being applied to the container monitor
	restartPolicy runconfig.RestartPolicy

	// failureCount is the number of times the container has failed to
	// start in a row
	failureCount int

	// shouldStop signals the monitor that the next time the container exits it is
	// either because docker or the user asked for the container to be stopped
	shouldStop bool

	// startSignal is a channel that is closes after the container initially starts
	startSignal chan struct{}

	// stopChan is used to signal to the monitor whenever there is a wait for the
	// next restart so that the timeIncrement is not honored and the user is not
	// left waiting for nothing to happen during this time
	stopChan chan struct{}

	// timeIncrement is the amount of time to wait between restarts
	// this is in milliseconds
	timeIncrement int

	// lastStartTime is the time which the monitor last exec'd the container's process
	lastStartTime time.Time
}

// newContainerMonitor returns an initialized containerMonitor for the provided container
// honoring the provided restart policy
func newContainerMonitor(container *Container, policy runconfig.RestartPolicy) *containerMonitor {
	return &containerMonitor{
		container:     container,
		restartPolicy: policy,
		timeIncrement: defaultTimeIncrement,
		stopChan:      make(chan struct{}),
		startSignal:   make(chan struct{}),
	}
}

// Stop signals to the container monitor that it should stop monitoring the container
// for exits the next time the process dies
func (m *containerMonitor) ExitOnNext() {
	m.mux.Lock()

	// we need to protect having a double close of the channel when stop is called
	// twice or else we will get a panic
	if !m.shouldStop {
		m.shouldStop = true
		close(m.stopChan)
	}

	m.mux.Unlock()
}

// Close closes the container's resources such as networking allocations and
// unmounts the contatiner's root filesystem
func (m *containerMonitor) Close() error {
	// Cleanup networking and mounts
	m.container.cleanup()

	// FIXME: here is race condition between two RUN instructions in Dockerfile
	// because they share same runconfig and change image. Must be fixed
	// in builder/builder.go
	if err := m.container.toDisk(); err != nil {
		log.Errorf("Error dumping container %s state to disk: %s", m.container.ID, err)

		return err
	}
	return nil
}

// Start starts the containers process and monitors it according to the restart policy
func (m *containerMonitor) Start() error {
	// reset the restart count
	m.container.RestartCount = -1

	for {
		err := m.step()
		if err != nil {
			m.setRestart(failStatus, err)
			if m.clientAttached() {
				// only on initial start
				m.container.ExitCode = -1
				m.resetContainer()
				return err
			}
			log.Errorf("Error running container: %s", err)
		}
		if !m.wait() {
			m.container.LogEvent("die")
			return nil
		}
		m.container.LogEvent("die")
	}
}

func (m *containerMonitor) clientAttached() bool {
	select {
	case <-m.startSignal:
		return false
	default:
		return true
	}
}

func (m *containerMonitor) step() error {
	if !m.clientAttached() {
		// outer mutex already unlocked
		m.container.Lock()
		defer m.container.Unlock()
	}
	m.container.RestartCount++

	if err := m.container.startLogging(); err != nil {
		return err
	}

	m.container.LogEvent("start")

	m.lastStartTime = time.Now()

	err := m.container.ctRun()
	if err != nil {
		return err
	}

	if err := m.notifyStart(); err != nil {
		return err
	}
	return nil
}

func (m *containerMonitor) wait() bool {
	es, err := m.container.ctWait()
	if err != nil {
		log.Errorf("Process exited with error: %s", err)
	}
	m.container.Lock()
	defer m.container.Unlock()
	return m.setRestart(es, err)
}

// every time when we return false from here - we exiting restarting loop
func (m *containerMonitor) setRestart(es *ExitStatus, err error) bool {
	m.resetMonitor(err == nil && es.ExitCode == 0)
	if m.shouldRestart(es.ExitCode) {
		m.container.setRestarting(es)
		if es.OOMKilled {
			m.container.LogEvent("oom")
		}
		m.resetContainer()

		// sleep with a small time increment between each restart to help avoid issues cased by quickly
		// restarting the container because of some types of errors ( networking cut out, etc... )
		m.waitForNextRestart()

		// we need to check this before reentering the loop because the waitForNextRestart could have
		// been terminated by a request from a user
		if m.shouldStop {
			m.Close()
			m.container.setStopped(es)
			return false
		}
		return true
	}

	if es.OOMKilled {
		m.container.LogEvent("oom")
	}
	m.resetContainer()
	m.Close()
	m.container.setStopped(es)
	return false
}

// resetMonitor resets the stateful fields on the containerMonitor based on the
// previous runs success or failure.  Regardless of success, if the container had
// an execution time of more than 10s then reset the timer back to the default
func (m *containerMonitor) resetMonitor(successful bool) {
	executionTime := time.Now().Sub(m.lastStartTime).Seconds()

	if executionTime > 10 {
		m.timeIncrement = defaultTimeIncrement
	} else {
		// otherwise we need to increment the amount of time we wait before restarting
		// the process.  We will build up by multiplying the increment by 2
		m.timeIncrement *= 2
	}

	// the container exited successfully so we need to reset the failure counter
	if successful {
		m.failureCount = 0
	} else {
		m.failureCount++
	}
}

// waitForNextRestart waits with the default time increment to restart the container unless
// a user or docker asks for the container to be stopped
func (m *containerMonitor) waitForNextRestart() {
	select {
	case <-time.After(time.Duration(m.timeIncrement) * time.Millisecond):
	case <-m.stopChan:
	}
}

// shouldRestart checks the restart policy and applies the rules to determine if
// the container's process should be restarted
func (m *containerMonitor) shouldRestart(exitCode int) bool {
	m.mux.Lock()
	defer m.mux.Unlock()

	// do not restart if the user or docker has requested that this container be stopped
	if m.shouldStop {
		return false
	}

	switch m.restartPolicy.Name {
	case "always":
		return true
	case "on-failure":
		// the default value of 0 for MaximumRetryCount means that we will not enforce a maximum count
		if max := m.restartPolicy.MaximumRetryCount; max != 0 && m.failureCount > max {
			log.Debugf("stopping restart of container %s because maximum failure could of %d has been reached",
				common.TruncateID(m.container.ID), max)
			return false
		}

		return exitCode != 0
	}

	return false
}

// callback ensures that the container's state is properly updated after we
// received ack from the execution drivers
func (m *containerMonitor) notifyStart() error {
	if m.container.Config.Tty {
		// The callback is called after the process Start()
		// so we are in the parent process. In TTY mode, stdin/out/err is the PtySlave
		// which we close here.
		if c, ok := m.container.ctInitProcess.Stdout.(io.Closer); ok {
			c.Close()
		}

	}

	p := m.container.ctInitProcess
	pid, err := p.Pid()
	if err != nil {
		p.Signal(os.Kill)
		p.Wait()
		return err
	}

	m.container.setRunning(pid)

	if err := m.container.toDisk(); err != nil {
		return err
	}

	// signal that the process has started
	// close channel only if not closed
	select {
	case <-m.startSignal:
	default:
		close(m.startSignal)
	}
	return nil
}

// resetContainer resets the container's IO and ensures that the command is able to be executed again
// by copying the data into a new struct
func (m *containerMonitor) resetContainer() {
	container := m.container

	if container.Config.OpenStdin {
		if err := container.stdin.Close(); err != nil {
			log.Errorf("%s: Error close stdin: %s", container.ID, err)
		}
	}

	if err := container.stdout.Clean(); err != nil {
		log.Errorf("%s: Error close stdout: %s", container.ID, err)
	}

	if err := container.stderr.Clean(); err != nil {
		log.Errorf("%s: Error close stderr: %s", container.ID, err)
	}

	if container.terminal != nil {
		if err := container.terminal.Close(); err != nil {
			log.Errorf("%s: Error closing terminal: %s", container.ID, err)
		}
	}

	// Re-create a brand new stdin pipe once the container exited
	if container.Config.OpenStdin {
		container.stdin, container.stdinPipe = io.Pipe()
	}

	if container.logDriver != nil {
		if container.logCopier != nil {
			exit := make(chan struct{})
			go func() {
				container.logCopier.Wait()
				close(exit)
			}()
			select {
			case <-time.After(1 * time.Second):
				log.Warnf("Logger didn't exit in time: logs may be truncated")
			case <-exit:
			}
		}
		container.logDriver.Close()
		container.logCopier = nil
		container.logDriver = nil
	}

	p := container.ctInitProcess

	container.ctInitProcess = &libcontainer.Process{
		Args: p.Args,
		Env:  p.Env,
		User: p.User,
		Cwd:  p.Cwd,
	}
}
