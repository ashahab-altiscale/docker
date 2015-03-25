package lxc

import (
	"fmt"
	"sync"

	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/configs"
)

type Container struct {
	mu     sync.Mutex
	id     string
	config *configs.Config
	root   string
}

func (c *Container) ID() string {
	return c.id
}

func (c *Container) Status() (libcontainer.Status, error) {
	return 0, fmt.Errorf("not implemented")
}

func (c *Container) State() (*libcontainer.State, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *Container) Config() configs.Config {
	cfg := *c.config
	return cfg
}

func (c *Container) Processes() ([]int, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *Container) Stats() (*libcontainer.Stats, error) {
	return nil, fmt.Errorf("not implemented")
}

func (c *Container) Set(config configs.Config) error {
	c.mu.Lock()
	c.config = &config
	c.mu.Unlock()
	return nil
}

func (c *Container) Start(process *libcontainer.Process) error {
	return fmt.Errorf("not implemented")
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
	return nil, fmt.Errorf("not implemented")
}
