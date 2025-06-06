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
	if w.address == nil {
		return ""
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
		return nil
	}
	v := strings.TrimPrefix(val, "docker://")
	if v == val {
		// not a docker address
		return nil
	}
	// if no host is provided, default to the default docker host
	// on Linux, this is normally unix:///var/run/docker.sock
	if v == "" {
		endpoint, ok := os.LookupEnv("DOCKER_HOST")
		if ok {
			v = endpoint
		}
	}
	return []string{fmt.Sprintf("DOCKER_HOST=%s", v)}
}
