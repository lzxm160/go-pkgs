// Copyright (c) 2019 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package crypto

import (
	"crypto/ecdsa"
	"encoding/hex"
	"io/ioutil"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/pkg/errors"
)

const (
	secp256pubKeyLength = 65
	secp256prvKeyLength = 32
)

var (
	// ErrInvalidKey is the error that the key format is invalid
	ErrInvalidKey = errors.New("invalid key format")
	// ErrPublicKey indicates the error of public key
	ErrPublicKey = errors.New("invalid public key")
	// ErrPrivateKey indicates the error of private key
	ErrPrivateKey = errors.New("invalid private key")
)

type (
	// PublicKey represents a public key
	PublicKey interface {
		Bytes() []byte
		HexString() string
		EcdsaPublicKey() *ecdsa.PublicKey
		Hash() []byte
		Verify([]byte, []byte) bool
	}
	// PrivateKey represents a private key
	PrivateKey interface {
		Bytes() []byte
		HexString() string
		EcdsaPrivateKey() *ecdsa.PrivateKey
		PublicKey() PublicKey
		Sign([]byte) ([]byte, error)
		Zero()
	}
)

// GenerateKey generates a SECP256K1 PrivateKey
func GenerateKey(sm2 bool) (PrivateKey, error) {
	if sm2 {
		return newSm2PrvKey()
	}
	return newSecp256k1PrvKey()
}

// HexStringToPublicKey decodes a string to SECP256K1 PublicKey
func HexStringToPublicKey(pubKey string, sm2 bool) (PublicKey, error) {
	b, err := hex.DecodeString(pubKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode public key %s", pubKey)
	}
	return BytesToPublicKey(b, sm2)
}

// HexStringToPrivateKey decodes a string to SECP256K1 PrivateKey
func HexStringToPrivateKey(prvKey string, sm2 bool) (PrivateKey, error) {
	b, err := hex.DecodeString(prvKey)
	if err != nil {
		return nil, errors.Wrapf(err, "failed to decode public key %s", prvKey)
	}
	return BytesToPrivateKey(b, sm2)
}

// BytesToPublicKey converts a byte slice to SECP256K1 PublicKey
func BytesToPublicKey(pubKey []byte, sm2 bool) (PublicKey, error) {
	if sm2 {
		return newSm2PubKeyFromBytes(pubKey)
	}
	if len(pubKey) == 64 {
		pubKey = append([]byte{4}, pubKey...)
	}
	return newSecp256k1PubKeyFromBytes(pubKey)
}

// BytesToPrivateKey converts a byte slice to SECP256K1 PrivateKey
func BytesToPrivateKey(prvKey []byte, sm2 bool) (PrivateKey, error) {
	if sm2 {
		return newSm2PrvKeyFromBytes(prvKey)
	}
	return newSecp256k1PrvKeyFromBytes(prvKey)
}

// KeystoreToPrivateKey generates PrivateKey from Keystore account
func KeystoreToPrivateKey(account accounts.Account, password string) (PrivateKey, error) {
	// load the key from the keystore
	keyJSON, err := ioutil.ReadFile(account.URL.Path)
	if err != nil {
		return nil, err
	}
	key, err := keystore.DecryptKey(keyJSON, password)
	if err != nil {
		return nil, err
	}
	return &secp256k1PrvKey{
		PrivateKey: key.PrivateKey,
	}, nil
}

// StringToPubKeyBytes converts a string of public key to byte slice
func StringToPubKeyBytes(pubKey string, sm2 bool) ([]byte, error) {
	pubKeyBytes, err := hex.DecodeString(pubKey)
	if err != nil {
		return nil, err
	}
	if sm2 {
		if len(pubKeyBytes) != 33 {
			return nil, errors.Wrap(ErrPublicKey, "Invalid public key length")
		}
	} else if len(pubKeyBytes) != secp256pubKeyLength {
		return nil, errors.Wrap(ErrPublicKey, "Invalid public key length")
	}
	return pubKeyBytes, nil
}
