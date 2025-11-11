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
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
)

func jsonEncode(o any) []byte {
	if o == nil {
		return []byte("{}")
	}
	js, _ := json.Marshal(o)
	return js
}

func jsonDecode(b []byte, o any) error {
	return json.Unmarshal(b, o)
}

func bytesEncode(b []byte) string {
	return base64.RawURLEncoding.EncodeToString(b)
}

func bytesDecode(s string) ([]byte, error) {
	return base64.RawURLEncoding.DecodeString(s)
}

func randGen(siz int) []byte {
	bs := make([]byte, siz)
	rand.Read(bs)
	return bs
}

func RandHexString(siz int) string {
	return hex.EncodeToString(randGen(siz / 2))
}

func randBase64String(siz int) string {

	if siz < 4 {
		siz = 1
	} else if siz%4 > 0 {
		siz = siz/4 + 1
	} else {
		siz = siz / 4
	}

	return base64.RawStdEncoding.EncodeToString(randGen(3 * siz))
}

func absInt64(a int64) int64 {
	if a < 0 {
		return -a
	}
	return a
}
