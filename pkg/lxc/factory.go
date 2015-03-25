package lxc

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"

	"github.com/docker/libcontainer"
	"github.com/docker/libcontainer/configs"
	"github.com/docker/libcontainer/configs/validate"
)

const (
	stateFilename = "state.json"
)

type Factory struct {
	Root      string
	Validator validate.Validator
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
	for _, opt := range options {
		if err := opt(f); err != nil {
			return nil, err
		}
	}
	return f, nil
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
