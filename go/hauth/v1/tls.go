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
	"bufio"
	"bytes"
	crand "crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"math/big"
	mrand "math/rand"
	"os"
	"time"

	"github.com/hooto/htoml4g/htoml"
)

func (opts *TLSKeyOptions) newX509Certificate() *x509.Certificate {

	if len(opts.Country) == 0 {
		// opts.Country = []string{""}
	}

	if opts.CommonName == "" {
		opts.CommonName = "hauth CA"
	}

	if len(opts.Organization) == 0 {
		opts.Organization = []string{"hooto"}
	}

	if len(opts.OrganizationalUnit) == 0 {
		// opts.OrganizationalUnit = []string{"hauth"}
	}

	tn := time.Now()

	crt := &x509.Certificate{
		SerialNumber: big.NewInt(mrand.Int63()),
		Subject: pkix.Name{
			Country:            opts.Country,
			Organization:       opts.Organization,
			OrganizationalUnit: opts.OrganizationalUnit,
			CommonName:         opts.CommonName,
		},
		NotBefore:             tn,
		NotAfter:              tn.AddDate(10, 0, 0), // 10 years
		BasicConstraintsValid: true,
		IsCA:                  opts.IsCA,
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign, // | x509.KeyUsageKeyEncipherment,
		// KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage: []x509.ExtKeyUsage{
			x509.ExtKeyUsageClientAuth,
			x509.ExtKeyUsageServerAuth,
		},
	}

	return crt
}

func DecodeFromFile(file string) (*TLSKey, error) {
	var key TLSKey
	if err := htoml.DecodeFromFile(file, &key); err != nil {
		return nil, err
	}
	return &key, nil
}

func pemDecode(txt, typ string) ([]byte, error) {
	block, _ := pem.Decode([]byte(txt))
	if block == nil || block.Type != typ {
		return nil, errors.New("failed to decode PEM block containing public key " + typ)
	}
	return block.Bytes, nil
}

func (it *TLSKey) CertDecode(txt string) (*x509.Certificate, error) {
	bs, err := pemDecode(txt, "CERTIFICATE")
	if err != nil {
		return nil, err
	}
	return x509.ParseCertificate(bs)
}

func (it *TLSKey) KeyDecode(txt string) (*rsa.PrivateKey, error) {
	bs, err := pemDecode(txt, "RSA PRIVATE KEY")
	if err != nil {
		return nil, err
	}
	return x509.ParsePKCS1PrivateKey(bs)
}

func NewTLSKey(opts *TLSKeyOptions) (*TLSKey, error) {

	if opts == nil {
		opts = &TLSKeyOptions{}
	}

	opts.IsCA = true

	var (
		crt    = opts.newX509Certificate()
		key, _ = rsa.GenerateKey(crand.Reader, 2048)
	)

	buf, err := x509.CreateCertificate(crand.Reader, crt, crt, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}

	return &TLSKey{
		Cert:    pemEncode("CERTIFICATE", buf),
		Key:     pemEncode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)),
		Options: opts,
	}, nil
}

func (it *TLSKey) Export(obj interface{}, fpath string) error {
	switch obj.(type) {
	case string:
		return fileFlush([]byte(obj.(string)), fpath)

	case TLSKey, *TLSKey:
		return htoml.EncodeToFile(obj, fpath)
	}
	return errors.New("invalid object type")
}

func (it *TLSKey) ClientKey(name string) *TLSKeyPair {
	for _, v := range it.Clients {
		if name == v.Name {
			return v
		}
	}
	return nil
}

func (it *TLSKey) NewClientKey(name string) error {

	if c := it.ClientKey(name); c != nil {
		return nil
	}

	//
	cakey, err := it.KeyDecode(it.Key)
	if err != nil {
		return err
	}
	//
	cacert, err := it.CertDecode(it.Cert)
	if err != nil {
		return err
	}

	opts := it.Options // &TLSKeyOptions{}
	opts.IsCA = false

	if name == "node" {
		opts.CommonName = "node"
	} else {
		opts.CommonName = "root"
	}

	var (
		crt    = opts.newX509Certificate()
		key, _ = rsa.GenerateKey(crand.Reader, 2048)
	)

	if name == "node" {
		crt.DNSNames = []string{"local"}
	}

	buf, err := x509.CreateCertificate(crand.Reader, crt, cacert, &key.PublicKey, cakey)
	if err != nil {
		return err
	}

	kp := &TLSKeyPair{
		Name: name,
		Cert: pemEncode("CERTIFICATE", buf),
		Key:  pemEncode("RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key)),
	}

	it.Clients = append(it.Clients, kp)

	return nil
}

func fileFlush(bs []byte, file string) error {

	fpo, err := os.OpenFile(file, os.O_RDWR|os.O_CREATE, 0640)
	if err != nil {
		return err
	}
	defer fpo.Close()

	fpo.Seek(0, 0)
	fpo.Truncate(0)

	var wbuf = bufio.NewWriter(fpo)
	wbuf.Write(bs)

	return wbuf.Flush()
}

func pemEncode(name string, bs []byte) string {

	var (
		buf   bytes.Buffer
		block = &pem.Block{
			Bytes: bs,
			Type:  name,
		}
	)

	pem.Encode(&buf, block)

	return string(buf.Bytes())
}
