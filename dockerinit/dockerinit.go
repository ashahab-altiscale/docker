package main

import (
	"github.com/docker/docker/pkg/reexec"
)

func main() {
	// Running in init mode
	reexec.Init()
}
