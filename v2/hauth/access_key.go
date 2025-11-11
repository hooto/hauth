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
	hauth1 "github.com/hooto/hauth/go/hauth/v1"
)

func NewUserAccessKey() *hauth1.AccessKey {
	return &hauth1.AccessKey{
		Id:     RandHexString(16),
		Secret: randBase64String(40),
		Type:   "User",
	}
}

func NewAppAccessKey() *hauth1.AccessKey {
	return &hauth1.AccessKey{
		Id:     RandHexString(16),
		Secret: randBase64String(40),
		Type:   "App",
	}
}
