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

import hauth1 "github.com/hooto/hauth/go/hauth/v1"

func NewScopeFilter(name, value string) *hauth1.ScopeFilter {
	return &hauth1.ScopeFilter{
		Name:  name,
		Value: value,
	}
}

func scopesAllow(scopes []*hauth1.ScopeFilter, scope *hauth1.ScopeFilter) bool {
	for _, v := range scopes {
		if scope.Name != v.Name {
			continue
		}
		if v.Value == "*" || v.Value == scope.Value {
			return true
		}
	}
	return false
}
