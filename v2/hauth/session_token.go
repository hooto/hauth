// Copyright 2020 Eryx <evorui at gmail dot com>, All rights reserved.
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
	"errors"
	"sync"
	"time"

	hauth1 "github.com/hooto/hauth/go/hauth/v1"
)

func NewSessionTokenManager(keyMgr *hauth1.AccessKeyManager) SessionTokenManager {
	return &sessionTokenManager{
		keyMgr: keyMgr,
		items:  map[string]*IdentityToken{},
	}
}

type sessionTokenManager struct {
	mu      sync.RWMutex
	keyMgr  *hauth1.AccessKeyManager
	items   map[string]*IdentityToken
	cleared int64
}

func (it *sessionTokenManager) Token(id string) *IdentityToken {
	it.clear()
	it.mu.RLock()
	defer it.mu.RUnlock()
	if token, ok := it.items[id]; ok {
		return token
	}
	return nil
}

func (it *sessionTokenManager) RefreshToken(token IdentityToken) {
	if token.Jti == "" {
		return
	}
	it.mu.Lock()
	defer it.mu.Unlock()
	it.items[token.Jti] = &token
}

func (it *sessionTokenManager) ReSign(accessToken string, token IdentityToken) (string, error) {
	//
	if token.Jti == "" {
		return "", errors.New("invalid key")
	}

	ak := it.keyMgr.KeyRand()

	header := TokenHeader{
		Kid: ak.Id,
	}

	claims := AccessTokenClaims{
		Jti: token.Jti,
		Sub: token.Sub,
		Iat: token.Iat,
		Exp: token.Exp,
	}

	accessToken, err := Sign(header, claims, []byte(ak.Secret))
	if err != nil {
		return "", err
	}

	it.mu.Lock()
	defer it.mu.Unlock()

	it.items[token.Jti] = &token

	return accessToken, nil
}

func (it *sessionTokenManager) clear() {
	t := time.Now().Unix()
	if (it.cleared + 600) > t {
		return
	}

	it.mu.Lock()
	defer it.mu.Unlock()

	it.cleared = t
	dels := []string{}

	for k, v := range it.items {
		if v.Exp <= t {
			dels = append(dels, k)
		}
	}
	for _, k := range dels {
		delete(it.items, k)
	}
}
