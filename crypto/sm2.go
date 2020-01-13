// Copyright (c) 2019 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package crypto

import (
	"crypto/ecdsa"
	"encoding/hex"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
	"github.com/tjfoc/gmsm/sm2"

	"github.com/iotexproject/go-pkgs/hash"
)

type (
	// sm2PrvKey implements the sm2 private key
	sm2PrvKey struct {
		*sm2.PrivateKey
	}
	// sm2PubKey implements the sm2 public key
	sm2PubKey struct {
		*sm2.PublicKey
	}
)

//======================================
// PrivateKey function
//======================================

// newSm2PrvKey generates a new Sm2 private key
func newSm2PrvKey() (PrivateKey, error) {
	sk, err := sm2.GenerateKey()
	if err != nil {
		return nil, errors.Wrap(err, "failed to create secp256k1 private key")
	}
	return &sm2PrvKey{
		PrivateKey: sk,
	}, nil
}

// newSm2PrvKeyFromBytes converts bytes format to PrivateKey
func newSm2PrvKeyFromBytes(b []byte) (PrivateKey, error) {
	c := sm2.P256Sm2()
	priv := &sm2PrvKey{
		PrivateKey: new(sm2.PrivateKey),
	}
	priv.PrivateKey.PublicKey.Curve = c
	priv.PrivateKey.D = big.NewInt(0).SetBytes(b)
	priv.PrivateKey.PublicKey.X, priv.PrivateKey.PublicKey.Y = c.ScalarBaseMult(b)
	return priv, nil
}

// Bytes returns the private key in bytes representation
func (k *sm2PrvKey) Bytes() []byte {
	return k.PrivateKey.D.Bytes()
}

// HexString returns the private key in hex string
func (k *sm2PrvKey) HexString() string {
	return hex.EncodeToString(k.Bytes())
}

// EcdsaPrivateKey returns the embedded ecdsa private key
func (k *sm2PrvKey) EcdsaPrivateKey() *ecdsa.PrivateKey {
	return nil
}

// PublicKey returns the public key corresponding to private key
func (k *sm2PrvKey) PublicKey() PublicKey {
	return &sm2PubKey{
		PublicKey: &k.PrivateKey.PublicKey,
	}
}

// Sign signs the message/hash
func (k *sm2PrvKey) Sign(hash []byte) ([]byte, error) {
	r, s, err := sm2.Sign(k.PrivateKey, hash)
	if err != nil {
		return nil, err
	}
	//ret, err := sm2.SignDigitToSignData(r, s)
	//if err != nil {
	//	return nil, err
	//}
	//ret = append(ret, 0)
	rb := r.Bytes()
	sb := s.Bytes()
	fmt.Println(r.Bytes())
	fmt.Println(s.Bytes())
	ret := make([]byte, len(rb)+len(sb)+1)
	copy(ret[:len(rb)], rb)
	copy(ret[len(rb):], sb)
	ret[64] = 0
	return ret, nil
}

// Zero zeroes the private key data
func (k *sm2PrvKey) Zero() {
	b := k.D.Bits()
	for i := range b {
		b[i] = 0
	}
}

//======================================
// PublicKey function
//======================================

// newSm2PubKeyFromBytes converts bytes format to PublicKey
func newSm2PubKeyFromBytes(b []byte) (PublicKey, error) {
	return &sm2PubKey{
		PublicKey: sm2.Decompress(b),
	}, nil
}

// Bytes returns the public key in bytes representation
func (k *sm2PubKey) Bytes() []byte {
	return sm2.Compress(k.PublicKey)
}

// HexString returns the public key in hex string
func (k *sm2PubKey) HexString() string {
	return hex.EncodeToString(k.Bytes())
}

// EcdsaPublicKey returns the embedded ecdsa publick key
func (k *sm2PubKey) EcdsaPublicKey() *ecdsa.PublicKey {
	return nil
}

// Hash is the last 20-byte of keccak hash of public key bytes, same as Ethereum address generation
func (k *sm2PubKey) Hash() []byte {
	h := hash.Hash160b(k.Bytes()[1:])
	return h[:]
}

// Verify verifies the signature
func (k *sm2PubKey) Verify(hash, sig []byte) bool {
	r := big.NewInt(0).SetBytes(sig[:secp256prvKeyLength])
	s := big.NewInt(0).SetBytes(sig[secp256prvKeyLength : secp256pubKeyLength-1])
	fmt.Println(r.Bytes())
	fmt.Println(s.Bytes())

	return sm2.Verify(k.PublicKey, hash, r, s)
}
