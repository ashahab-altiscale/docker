package lxc

import (
	"fmt"
	"os"
	"strings"
	"text/template"

	log "github.com/Sirupsen/logrus"
	"github.com/docker/docker/daemon/execdriver"
	"github.com/docker/docker/utils"
	"github.com/docker/libcontainer/label"
)

const LxcTemplate = `
{{$NETWORK := index .NETWORK 0}}
{{if $NETWORK.Interface}}
# network configuration
lxc.network.type = veth
lxc.network.link = {{$NETWORK.Interface.Bridge}}
lxc.network.name = eth0
lxc.network.mtu = {{$NETWORK.Mtu}}
lxc.network.flags = up
{{else if $NETWORK.HostNetworking}}
lxc.network.type = none
{{else}}
# network is disabled (-n=false)
lxc.network.type = empty
lxc.network.flags = up
lxc.network.mtu = {{$NETWORK.Mtu}}
{{end}}

# root filesystem
{{$ROOTFS := .Rootfs}}
lxc.rootfs = {{$ROOTFS}}

# use a dedicated pts for the container (and limit the number of pseudo terminal
# available)
lxc.pts = 1024

# disable the main console
lxc.console = none

# no controlling tty at all
lxc.tty = 1

{{if .Privileged}}
lxc.cgroup.devices.allow = a
{{else}}
# no implicit access to devices
lxc.cgroup.devices.deny = a
#Allow the devices passed to us in the AllowedDevices list.
{{range $allowedDevice := .Devices}}
lxc.cgroup.devices.allow = {{$allowedDevice.CgroupString}}
{{end}}
{{end}}

# standard mount point
# Use mnt.putold as per https://bugs.launchpad.net/ubuntu/+source/lxc/+bug/986385
lxc.pivotdir = lxc_putold

# NOTICE: These mounts must be applied within the namespace
{{if .Privileged}}
# WARNING: mounting procfs and/or sysfs read-write is a known attack vector.
# See e.g. http://blog.zx2c4.com/749 and http://bit.ly/T9CkqJ
# We mount them read-write here, but later, dockerinit will call the Restrict() function to remount them read-only.
# We cannot mount them directly read-only, because that would prevent loading AppArmor profiles.
lxc.mount.entry = proc {{escapeFstabSpaces $ROOTFS}}/proc proc nosuid,nodev,noexec 0 0
lxc.mount.entry = sysfs {{escapeFstabSpaces $ROOTFS}}/sys sysfs nosuid,nodev,noexec 0 0
	{{if .AppArmor}}
lxc.aa_profile = unconfined
	{{end}}
{{else}}
# In non-privileged mode, lxc will automatically mount /proc and /sys in readonly mode
# for security. See: http://man7.org/linux/man-pages/man5/lxc.container.conf.5.html
lxc.mount.auto = proc sys
	{{if .AppArmorProfile}}
lxc.aa_profile = {{.AppArmorProfile}}
	{{end}}
{{end}}

{{if .Console}}
lxc.mount.entry = {{.Console}} {{escapeFstabSpaces $ROOTFS}}/dev/console none bind,rw 0 0
{{end}}

lxc.mount.entry = devpts {{escapeFstabSpaces $ROOTFS}}/dev/pts devpts {{formatMountLabel "newinstance,ptmxmode=0666,nosuid,noexec" ""}} 0 0
lxc.mount.entry = shm {{escapeFstabSpaces $ROOTFS}}/dev/shm tmpfs {{formatMountLabel "size=65536k,nosuid,nodev,noexec" ""}} 0 0

{{range $value := .Mounts}}
{{$createVal := isDirectory $value.Source}}
{{if $value.Writable}}
lxc.mount.entry = {{$value.Source}} {{escapeFstabSpaces $ROOTFS}}/{{escapeFstabSpaces $value.Destination}} none rbind,rw,create={{$createVal}} 0 0
{{else}}
lxc.mount.entry = {{$value.Source}} {{escapeFstabSpaces $ROOTFS}}/{{escapeFstabSpaces $value.Destination}} none rbind,ro,create={{$createVal}} 0 0
{{end}}
{{end}}

# limits
{{if .Resources}}
{{if .Resources.Memory}}
lxc.cgroup.memory.limit_in_bytes = {{.Resources.Memory}}
lxc.cgroup.memory.soft_limit_in_bytes = {{.Resources.Memory}}
{{with $memSwap := getMemorySwap .Resources}}
lxc.cgroup.memory.memsw.limit_in_bytes = {{$memSwap}}
{{end}}
{{end}}
{{if .Resources.CpuShares}}
lxc.cgroup.cpu.shares = {{.Resources.CpuShares}}
{{end}}
{{if .Resources.CpusetCpus}}
lxc.cgroup.cpuset.cpus = {{.Resources.CpusetCpus}}
{{end}}
{{end}}

{{if .LxcConfig}}
{{range $value := .LxcConfig}}
lxc.{{$value}}
{{end}}
{{end}}

{{if $NETWORK.Interface}}
{{if $NETWORK.Interface.IPAddress}}
lxc.network.ipv4 = {{$NETWORK.Interface.IPAddress}}/{{$NETWORK.Interface.IPPrefixLen}}
{{end}}
{{if $NETWORK.Interface.Gateway}}
lxc.network.ipv4.gateway = {{$NETWORK.Interface.Gateway}}
{{end}}
{{if $NETWORK.Interface.MacAddress}}
lxc.network.hwaddr = {{$NETWORK.Interface.MacAddress}}
{{end}}
{{if .Env}}
lxc.utsname = {{getHostname .Env}}
{{end}}

{{if .Privileged}}
# No cap values are needed, as lxc is starting in privileged mode
{{else}}
	{{ with .Capabilities }}
		{{range .}}
lxc.cap.keep = {{.}}
		{{end}}
	{{else}}
		{{ with dropList .Capabilities }}
		{{range .}}
lxc.cap.drop = {{.}}
		{{end}}
		{{end}}
	{{end}}
{{end}}
{{end}}
`

var LxcTemplateCompiled *template.Template

// Escape spaces in strings according to the fstab documentation, which is the
// format for "lxc.mount.entry" lines in lxc.conf. See also "man 5 fstab".
func escapeFstabSpaces(field string) string {
	return strings.Replace(field, " ", "\\040", -1)
}

func keepCapabilities(caps []string) ([]string, error) {
	log.Debugf("caps %s \n", caps)
	var newCaps []string
	for _, cap := range caps {
		log.Debugf("cap %s\n", cap)
		realCap := execdriver.GetCapability(cap)
		numCap := fmt.Sprintf("%d", realCap.Value)
		newCaps = append(newCaps, numCap)
	}

	return newCaps, nil
}

func dropList(caps []string) ([]string, error) {
	if len(caps) > 0 && !utils.StringsContainsNoCase(drops, "all"){
		return []string{}, nil
	}
	var newCaps []string
	for _, capName := range execdriver.GetAllCapabilities() {
		cap := execdriver.GetCapability(capName)
		log.Debugf("drop cap %s\n", cap.Key)
		numCap := fmt.Sprintf("%d", cap.Value)
		newCaps = append(newCaps, numCap)
	}
	return newCaps, nil
}

func isDirectory(source string) string {
	f, err := os.Stat(source)
	log.Debugf("dir: %s\n", source)
	if err != nil {
		if os.IsNotExist(err) {
			return "dir"
		}
		return ""
	}
	if f.IsDir() {
		return "dir"
	}
	return "file"
}

func getMemorySwap(v *execdriver.Resources) int64 {
	// By default, MemorySwap is set to twice the size of RAM.
	// If you want to omit MemorySwap, set it to `-1'.
	if v.MemorySwap < 0 {
		return 0
	}
	return v.Memory * 2
}

func getLabel(c map[string][]string, name string) string {
	label := c["label"]
	for _, l := range label {
		parts := strings.SplitN(l, "=", 2)
		if strings.TrimSpace(parts[0]) == name {
			return strings.TrimSpace(parts[1])
		}
	}
	return ""
}

func getHostname(env []string) string {
	for _, kv := range env {
		parts := strings.SplitN(kv, "=", 2)
		if parts[0] == "HOSTNAME" && len(parts) == 2 {
			return parts[1]
		}
	}
	return ""
}

func init() {
	var err error
	funcMap := template.FuncMap{
		"getMemorySwap":     getMemorySwap,
		"escapeFstabSpaces": escapeFstabSpaces,
		"formatMountLabel":  label.FormatMountLabel,
		"isDirectory":       isDirectory,
		"keepCapabilities":  keepCapabilities,
		"dropList":          dropList,
		"getHostname":       getHostname,
	}
	LxcTemplateCompiled, err = template.New("lxc").Funcs(funcMap).Parse(LxcTemplate)
	if err != nil {
		panic(err)
	}
}
