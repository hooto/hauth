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
	"slices"
	"time"

	hauth1 "github.com/hooto/hauth/go/hauth/v1"
)

type IdentityToken struct {
	Jti string `json:"jti,omitempty"` // JWT ID

	Sub string `json:"sub,omitempty"`

	Iat int64 `json:"iat"` // Issued At Time
	Exp int64 `json:"exp"`

	Roles  []uint32 `json:"roles,omitempty"`
	Groups []string `json:"groups,omitempty"`

	Type string `json:"type,omitempty"`

	Scopes []*hauth1.ScopeFilter `json:"scopes,omitempty"`
}

func (it *IdentityToken) IsExpired() bool {
	return it == nil || it.Exp <= time.Now().Unix()
}

func (it *IdentityToken) Allow(user string, args ...any) bool {
	if it == nil || user == "" {
		return false
	}

	if it.IsExpired() {
		return false
	}

	if user == it.Sub ||
		slices.Contains(it.Groups, user) {

		return true
	}

	if it.Type == "App" {

		if len(it.Scopes) > 0 && len(args) > 0 {

			for _, arg := range args {
				if arg == nil {
					continue
				}
				switch arg.(type) {
				case *hauth1.ScopeFilter:
					scope := arg.(*hauth1.ScopeFilter)
					if scopesAllow(it.Scopes, scope) {
						return true
					}
				}
			}
		}
	}

	return false
}
