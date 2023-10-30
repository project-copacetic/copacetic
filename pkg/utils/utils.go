/*
Copyright (c) Project Copacetic authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

	http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package utils

import (
	"io/fs"
	"os"
	"path/filepath"

	"github.com/moby/buildkit/client/llb"
)

func EnsurePath(path string, perm fs.FileMode) (bool, error) {
	createdPath := false
	st, err := os.Stat(path)
	if err != nil && os.IsNotExist(err) {
		err = os.MkdirAll(path, perm)
		createdPath = (err == nil)
	} else {
		if !st.IsDir() {
			return false, fs.ErrExist
		}
		if st.Mode().Perm() != perm {
			return false, fs.ErrPermission
		}
	}
	return createdPath, err
}

func IsNonEmptyFile(dir, file string) bool {
	p := filepath.Join(dir, file)
	info, err := os.Stat(p)
	if os.IsNotExist(err) {
		return false
	}
	return !info.IsDir() && info.Size() > 0
}

func getEnvAny(names ...string) string {
	for _, n := range names {
		if val := os.Getenv(n); val != "" {
			return val
		}
	}
	return ""
}

func GetProxy() llb.ProxyEnv {
	proxy := llb.ProxyEnv{
		HTTPProxy:  getEnvAny("HTTP_PROXY"),
		HTTPSProxy: getEnvAny("HTTPS_PROXY"),
		NoProxy:    getEnvAny("NO_PROXY"),
		AllProxy:   getEnvAny("HTTP_PROXY"),
	}
	return proxy
}
