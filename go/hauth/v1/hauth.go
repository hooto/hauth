// Copyright 2020 Eryx <evorui аt gmail dοt com>, All rights reserved.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package hauth

import (
	"encoding/base64"
	"strings"
	"sync"

	"github.com/lessos/lessgo/crypto/idhash"
)

var (
	authKeyDefault = &AuthKey{
		AccessKey: "00000000",
		SecretKey: idhash.RandBase64String(40),
	}
	base64Std = base64.StdEncoding.WithPadding(base64.NoPadding)
	base64Url = base64.URLEncoding.WithPadding(base64.NoPadding)
)

type AuthKeyManager struct {
	mu    sync.RWMutex
	items map[string]*AuthKey
}

func NewAuthKeyManager() *AuthKeyManager {
	return &AuthKeyManager{
		items: map[string]*AuthKey{},
	}
}

func (it *AuthKeyManager) KeySet(k *AuthKey) error {

	it.mu.Lock()
	defer it.mu.Unlock()

	it.items[k.AccessKey] = k

	return nil
}

func (it *AuthKeyManager) KeyGet(ak string) *AuthKey {

	it.mu.RLock()
	defer it.mu.RUnlock()

	key, ok := it.items[ak]
	if ok {
		return key
	}
	return nil
}

func base64nopad(s string) string {
	if i := strings.IndexByte(s, '='); i > 0 {
		return s[:i]
	}
	return s
}

func base64pad(s string) string {
	if n := len(s) % 4; n > 0 {
		s += strings.Repeat("=", 4-n)
	}
	return s
}

func NewAuthKey() *AuthKey {
	return &AuthKey{
		AccessKey: idhash.RandHexString(16),
		SecretKey: idhash.RandBase64String(40),
	}
}
