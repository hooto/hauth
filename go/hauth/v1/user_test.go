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
	"time"
)

var (
	tKeyMgr = &AccessKeyManager{
		items: map[string]*AccessKey{
			"be2c1fcf532baaa9": {Id: "be2c1fcf532baaa9", Secret: "c9a1a8ca13740018f1dd840a073ffc2e"},
			"d4d7d973aa8d3c70": {Id: "d4d7d973aa8d3c70", Secret: "ec1f6f37c8d81b7bdb855b651523367e"},
		},
	}
	tKeyErrs = &AccessKeyManager{
		items: map[string]*AccessKey{
			"be2c1fcf532baaa9": {Id: "be2c1fcf532baaa9", Secret: "c9a1a8ca13740018f"},
		},
	}
	tKeyNull     = NewAccessKeyManager()
	tPayloadItem = &UserPayload{
		Id:      "guest",
		Roles:   []uint32{100, 200},
		Groups:  []string{"staff"},
		Expired: 2012345678,
	}
	tToken = "" // tPayloadItem.SignToken(tKeyMgr)
)

func init() {
	tToken = tPayloadItem.SignToken(tKeyMgr)
}

func Test_UserMain(t *testing.T) {

	pl := NewUserPayload(
		"guest",
		"Guest",
		[]uint32{100, 200},
		[]string{"guest"},
		86400)

	pl.Expired = time.Now().Unix() + 1

	token := pl.SignToken(tKeyMgr)
	t.Logf("SignToken keys %d, token %s", len(tKeyMgr.items), token)

	rs, err := NewUserValidator(token)
	if rs == nil || err != nil {
		t.Fatal("Failed on UserValid")
	}
	if rs.Id != tPayloadItem.Id {
		t.Fatal("Failed on Token Decode")
	}

	if err := rs.SignValid(tKeyErrs); err == nil {
		t.Fatal("Failed on UserValid")
	}

	if err := rs.SignValid(tKeyNull); err == nil {
		t.Fatal("Failed on UserValid")
	}

	time.Sleep(2e9) // expired

	if err := rs.SignValid(tKeyMgr); err == nil {
		t.Fatal("Failed on UserValid")
	}
}

func Benchmark_UserPayload_SignToken(b *testing.B) {
	for i := 0; i < b.N; i++ {
		tPayloadItem.SignToken(tKeyMgr)
	}
}

func Benchmark_UserValidator_SignValid(b *testing.B) {
	for i := 0; i < b.N; i++ {
		rs, _ := NewUserValidator(tToken)
		rs.SignValid(tKeyMgr)
	}
}
