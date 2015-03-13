package execdrivers

import (
	"fmt"

	"github.com/docker/docker/daemon/execdriver"
	"github.com/docker/docker/daemon/execdriver/lxc"
	"github.com/docker/docker/pkg/sysinfo"
)

func NewDriver(name, root, libPath, initPath string, sysInfo *sysinfo.SysInfo) (execdriver.Driver, error) {
	switch name {
	case "lxc":
		// we want to give the lxc driver the full docker root because it needs
		// to access and write config and template files in /var/lib/docker/containers/*
		// to be backwards compatible
		return lxc.NewDriver(root, libPath, initPath, sysInfo.AppArmor)
	}
	return nil, fmt.Errorf("unknown exec driver %s", name)
}
