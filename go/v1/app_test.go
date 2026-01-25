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
	"testing"
)

var (
	tAppAccessKey = &AccessKey{
		User:   "guest",
		Id:     "be2c1fcf532baaa9",
		Secret: "c9a1a8ca13740018f1dd840a073ffc2e",
	}
	tAppAccessKeyErr = &AccessKey{
		User:   "guest",
		Id:     "be2c1fcf532baaa9",
		Secret: "c9a1a8ca13740018",
	}
	tAppKeyMgr    = NewAccessKeyManager()
	tAppKeyMgrErr = NewAccessKeyManager()
	tAppData      = []byte(`{"id": "1234", "data": "hello world"}`)
)

func init() {
	tAppKeyMgr.KeySet(tAppAccessKey)
	tAppKeyMgrErr.KeySet(tAppAccessKeyErr)
}

func Test_AppMain(t *testing.T) {

	pl := NewAppCredential(tAppAccessKey)

	token := pl.SignToken(tAppData)

	t.Logf("AppSignToken %s", token)

	rs, err := NewAppValidator(token, tAppKeyMgr)
	if rs == nil || err != nil {
		t.Fatal("Failed on AppValid")
	}

	if rs.User != tAppAccessKey.User {
		t.Fatal("Failed on Token Decode")
	}

	if err := rs.SignValid(tAppData); err != nil {
		t.Fatal("Failed on AppValid")
	}

	rs, err = NewAppValidator(token, tAppKeyMgrErr)
	if err := rs.SignValid(tAppData); err == nil {
		t.Fatal("Failed on AppValid")
	}
}

func Benchmark_AppCredential_SignToken(b *testing.B) {
	ac := NewAppCredential(tAppAccessKey)
	for i := 0; i < b.N; i++ {
		ac.SignToken(tAppData)
	}
}

func Benchmark_AppValidator_SignValid(b *testing.B) {
	token := NewAppCredential(tAppAccessKey).SignToken(tAppData)
	for i := 0; i < b.N; i++ {
		rs, _ := NewAppValidator(token, tAppKeyMgr)
		rs.SignValid(tAppData)
	}
}
