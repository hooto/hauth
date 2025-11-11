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

const (
	appHttpHeaderName = "x-hauth2"

	userAppAuthTtlMin int64 = 600        // seconds
	userAppAuthTtlMax int64 = 86400 * 30 // seconds
)

type AuthConnector interface {
	AccessKey() *hauth1.AccessKey
	LoginToken() string
	AccessToken() string
	RefreshAccessToken(at string) error
}

type IdentityAuthService interface {
	AuthLogin(*AuthLoginRequest) (*AuthLoginResponse, error)
}

type SessionTokenManager interface {
	RefreshToken(token IdentityToken)
	ReSign(accessToken string, identityToken IdentityToken) (string, error)
	Token(id string) *IdentityToken
}

type AppValidator interface {
	Verify(keyMgr *hauth1.AccessKeyManager) error
}

type TokenHeader struct {
	Alg string `json:"alg"`
	Typ string `json:"typ,omitempty"`
	Kid string `json:"kid,omitempty"`
}

type AuthLoginRequest struct {
	LoginToken string `json:"login_token"`
}

type AuthLoginResponse struct {
	Error         string        `json:"error,omitempty"`
	AccessToken   string        `json:"access_token"`
	IdentityToken IdentityToken `json:"identity_token"`
}

type AuthClaims struct {
	Jti   string `json:"jti,omitempty"` // JWT ID
	Iat   int64  `json:"iat"`           // Issued At Time
	Exp   int64  `json:"exp"`
	State string `json:"state,omitempty"`
}
