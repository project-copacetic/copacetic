package common

import (
	"fmt"
	"os"
	"strings"
	"sync"
)

type AddrWrapper struct {
	m       sync.Mutex
	address *string
}

var DockerDINDAddress AddrWrapper

func (w *AddrWrapper) Addr() string {
	w.m.Lock()
	defer w.m.Unlock()

	if w.address != nil {
		return *w.address
	}

	w.address = new(string)
	if addr := os.Getenv("COPA_BUILDKIT_ADDR"); addr != "" && strings.HasPrefix(addr, "docker://") {
		*w.address = strings.TrimPrefix(addr, "docker://")
	}

	return *w.address
}

func (w *AddrWrapper) Set(val string) {
	w.m.Lock()
	defer w.m.Unlock()
	w.address = &val
}

func (w *AddrWrapper) Env() []string {
	val := w.Addr()
	if val == "" {
		return []string{}
	}

	return []string{fmt.Sprintf("DOCKER_HOST=%s", val)}
}
