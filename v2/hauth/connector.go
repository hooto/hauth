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
	"time"

	"github.com/google/uuid"

	hauth1 "github.com/hooto/hauth/go/hauth/v1"
)

func NewAuthConnectorWithAccessKey(
	ak *hauth1.AccessKey,
	args ...any,
) AuthConnector {
	ac := &authConnector{
		ak: ak,
	}
	for _, arg := range args {
		if arg == nil {
			continue
		}
		switch arg.(type) {
		case Signer:
			ac.signer = arg.(Signer)
		}
	}
	if ac.signer == nil {
		ac.signer = DefaultSigner
	}
	return ac
}

type authConnector struct {
	ak *hauth1.AccessKey

	signer Signer

	loginHeader        TokenHeader
	loginClaims        AuthLoginClaims
	loginSigningString string
	loginSignString    string

	accessToken *AccessToken
}

func (it *authConnector) AccessKey() *hauth1.AccessKey {
	return it.ak
}

func (it *authConnector) LoginToken() string {

	tn := time.Now().Unix()

	it.loginHeader = TokenHeader{
		Alg: it.signer.Name(),
		Kid: it.ak.Id,
	}

	it.loginClaims = AuthLoginClaims{
		Iat:   tn,
		Exp:   tn + 10,
		State: uuid.NewString(),
	}

	it.loginSigningString = bytesEncode(jsonEncode(it.loginHeader)) + "." +
		bytesEncode(jsonEncode(it.loginClaims))

	bs, _ := it.signer.Sign(it.loginSigningString, []byte(it.ak.Secret))

	it.loginSignString = bytesEncode(bs)

	return it.loginSigningString + "." + it.loginSignString
}

func (it *authConnector) AccessToken() string {
	if it.accessToken != nil {
		return it.accessToken.raw
	}
	return ""
}

func (it *authConnector) RefreshAccessToken(accessToken string) error {

	token, err := NewAccessToken(accessToken)
	if err != nil {
		return err
	}

	if token.IsExpired() {
		return errors.New("access-token expired")
	}

	it.accessToken = token

	return nil
}
