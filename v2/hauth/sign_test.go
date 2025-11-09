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

package hauth_test

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"

	hauth1 "github.com/hooto/hauth/go/hauth/v1"
	hauth2 "github.com/hooto/hauth/v2/hauth"
)

var (
	signingString = "eyJhbGciOiJIUzI1NiIsImtpZCI6IjA3YWFkMGQ2NmJlYzQwODMifQ.eyJpYXQiOjE3NjIzOTY2MTMsInN0YXRlIjoiYTFkMWMyNjktOGRhNS00ZGFhLTgxNWMtNDE4ZjYwODQzZGEzIn0"

	hs256 = hauth2.Signers.Signer("HS256")
	hs512 = hauth2.Signers.Signer("HS512")

	rs256 = hauth2.Signers.Signer("RS256")
	rs512 = hauth2.Signers.Signer("RS512")

	es256 = hauth2.Signers.Signer("ES256")
	es512 = hauth2.Signers.Signer("ES512")
)

func Benchmark_Signer_Sign_HS256(b *testing.B) {
	ak := hauth1.NewAccessKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hs256.Sign(signingString, ak.Secret)
	}
}

func Benchmark_Signer_Sign_HS512(b *testing.B) {
	ak := hauth1.NewAccessKey()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		hs512.Sign(signingString, ak.Secret)
	}
}

func Benchmark_Signer_Sign_RS256(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs256.Sign(signingString, privateKey)
	}
}

func Benchmark_Signer_Sign_RS512(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		rs512.Sign(signingString, privateKey)
	}
}

func Benchmark_Signer_Sign_ES256(b *testing.B) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		es256.Sign(signingString, privateKey)
	}
}

func Benchmark_Signer_Sign_ES512(b *testing.B) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		es512.Sign(signingString, privateKey)
	}
}

func Test_Signer_Sign_ES256(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	bs, err := es256.Sign(signingString, privateKey)
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Logf("Signer_Sign_ES256 len %d", len(bs))
}

func Test_Signer_Sign_ES512(t *testing.T) {
	privateKey, _ := ecdsa.GenerateKey(elliptic.P521(), rand.Reader)
	bs, err := es512.Sign(signingString, privateKey)
	if err != nil {
		t.Fatal(err.Error())
	}
	t.Logf("Signer_Sign_ES512 len %d", len(bs))
}
