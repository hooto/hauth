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
	"bytes"
	"encoding/json"
	"testing"

	"github.com/hooto/htoml4g/htoml"
)

var (
	tKeysV0 = []*AccessKey{
		{AccessKey: "be2c1fcf532baaa9", SecretKey: "c9a1a8ca13740018f1dd840a073ffc2e"},
		{AccessKey: "d4d7d973aa8d3c70", SecretKey: "ec1f6f37c8d81b7bdb855b651523367e"},
	}
	tKeysV0Json = []string{
		`{"access_key":"be2c1fcf532baaa9","secret_key":"c9a1a8ca13740018f1dd840a073ffc2e"}`,
		`{"access_key":"d4d7d973aa8d3c70","secret_key":"ec1f6f37c8d81b7bdb855b651523367e"}`,
	}
	tKeysV0Toml = []string{
		`access_key = "be2c1fcf532baaa9"
secret_key = "c9a1a8ca13740018f1dd840a073ffc2e"
roles = ["sa"]
[[scopes]]
name = "name1"
value = "value1"
`,
		`access_key = "d4d7d973aa8d3c70"
secret_key = "ec1f6f37c8d81b7bdb855b651523367e"
roles = ["sa"]
[[scopes]]
name = "name1"
value = "value1"
`,
	}
)

func Test_AccessKey_JsonDecode(t *testing.T) {

	for i, js := range tKeysV0Json {
		var ak AccessKey
		if err := json.Unmarshal([]byte(js), &ak); err != nil {
			t.Fatalf("Decode %v", err)
		} else {
			if ak.Id != tKeysV0[i].AccessKey ||
				ak.Secret != tKeysV0[i].SecretKey {
				t.Fatalf("Decode v0 -> v1")
			}
		}
	}
}

func Test_AccessKey_JsonEncode(t *testing.T) {

	for _, ak := range tKeysV0 {

		if bs, err := json.Marshal(ak); err != nil {
			t.Fatalf("Encode %v", err)
		} else {

			if !bytes.Contains(bs, []byte(ak.AccessKey)) ||
				bytes.Contains(bs, []byte("access_key")) {
				t.Fatalf("Encode v0 -> v1 %v", string(bs))
			} else {
				t.Logf("Encode v0 -> v1 OK")
			}
		}
	}
}

func Test_AccessKey_TomlDecode(t *testing.T) {

	for i, js := range tKeysV0Toml {
		var ak AccessKey
		if err := htoml.Decode(&ak, []byte(js)); err != nil {
			t.Fatalf("Decode %v", err)
		} else {
			if ak.Id != tKeysV0[i].AccessKey ||
				ak.Secret != tKeysV0[i].SecretKey ||
				len(ak.Roles) != 1 || ak.Roles[0] != "sa" ||
				len(ak.Scopes) != 1 || ak.Scopes[0].Name != "name1" {
				t.Fatalf("Decode v0 -> v1")
			} else {

				if bs, err := htoml.Encode(ak, nil); err != nil {
					t.Fatalf("Encode %v", err)
				} else {

					if !bytes.Contains(bs, []byte(ak.AccessKey)) ||
						!bytes.Contains(bs, []byte("id = ")) {
						t.Fatalf("Encode v0 -> v1 %v", string(bs))
					} else {
						t.Logf("Encode v0 -> v1 OK")
					}
				}
			}
		}
	}
}
