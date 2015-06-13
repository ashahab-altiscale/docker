package lxc

import (
	"fmt"
	"syscall"
	"os"
	"github.com/docker/libcontainer/system"
	"github.com/docker/libcontainer/user"
	"github.com/docker/libcontainer/utils"
)

func finalizeNamespace(args *Init_Args) error {
	if err := utils.CloseExecFrom(3); err != nil {
		return err
	}
	if err := setupUser(args.User); err != nil {
		return fmt.Errorf("setup user %s", err)
	}
	if err := setupWorkingDirectory(args); err != nil {
		return err
	}
	return nil
}


// setupUser changes the groups, gid, and uid for the user inside the container
// copy from libcontainer, cause not it's private
func setupUser(userSpec string) error {
	// Set up defaults.
	defaultExecUser := user.ExecUser{
		Uid:  syscall.Getuid(),
		Gid:  syscall.Getgid(),
		Home: "/",
	}
	passwdPath, err := user.GetPasswdPath()
	if err != nil {
		return err
	}
	groupPath, err := user.GetGroupPath()
	if err != nil {
		return err
	}
	execUser, err := user.GetExecUserPath(userSpec, &defaultExecUser, passwdPath, groupPath)
	if err != nil {
		return err
	}
	if err := syscall.Setgroups(execUser.Sgids); err != nil {
		return err
	}
	if err := system.Setgid(execUser.Gid); err != nil {
		return err
	}
	if err := system.Setuid(execUser.Uid); err != nil {
		return err
	}
	// if we didn't get HOME already, set it based on the user's HOME
	if envHome := os.Getenv("HOME"); envHome == "" {
		if err := os.Setenv("HOME", execUser.Home); err != nil {
			return err
		}
	}
	return nil
}