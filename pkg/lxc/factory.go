package lxc

import (
	"fmt"
	"os"

	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/configs"
)

type Factory struct {
	Root string
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
		Root: root,
	}
	for _, opt := range options {
		if err := opt(f); err != nil {
			return nil, err
		}
	}
	return f, nil
}

func (f *Factory) Create(id string, config *configs.Config) (libcontainer.Container, error) {
	return &Container{}, fmt.Errorf("Not implemented")
}

func (f *Factory) Load(id string) (libcontainer.Container, error) {
	return nil, fmt.Errorf("Not implemented")
}

func (f *Factory) StartInitialization(pipefd uintptr) error {
	return fmt.Errorf("Not implemented")
}

func (f *Factory) Type() string {
	return "lxc"
}
