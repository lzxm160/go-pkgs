// Copyright (c) 2019 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package crypto

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

const (
	publicKey  = "04403d3c0dbd3270ddfc248c3df1f9aafd60f1d8e7456961c9ef26292262cc68f0ea9690263bef9e197a38f06026814fc70912c2b98d2e90a68f8ddc5328180a01"
	privateKey = "82a1556b2dbd0e3615e367edf5d3b90ce04346ec4d12ed71f67c70920ef9ac90"

	sm2publicKey  = "0490aca9f9b0184b1fd8960a358a8496444bf9ae1858619b6d5f2e23436d180464e355d65758e1980ad94645b3654845f4add0fc5a5fd48e11795a36192f76a5d9"
	sm2privateKey = "b051d4a19248b1838e7101f4a7899513b305318972c4b818f09b87b9da926104"
)

func TestKeypair(t *testing.T) {
	require := require.New(t)

	_, err := HexStringToPublicKey("", false)
	require.True(strings.Contains(err.Error(), "invalid secp256k1 public key"))
	_, err = HexStringToPrivateKey("", false)
	require.True(strings.Contains(err.Error(), "invalid length, need 256 bits"))

	pubKey, err := HexStringToPublicKey(publicKey, false)
	require.NoError(err)

	pubKey2, err := HexStringToPublicKey(publicKey[2:], false)
	require.NoError(err)
	require.Equal(pubKey, pubKey2)

	priKey, err := HexStringToPrivateKey(privateKey, false)
	require.NoError(err)

	require.Equal(publicKey, pubKey.HexString())
	require.Equal(privateKey, priKey.HexString())

	pubKeyBytes := pubKey.Bytes()
	priKeyBytes := priKey.Bytes()

	_, err = BytesToPublicKey([]byte{1, 2, 3}, false)
	require.Error(err)
	_, err = BytesToPrivateKey([]byte{4, 5, 6}, false)
	require.Error(err)

	pk, err := BytesToPublicKey(pubKeyBytes, false)
	require.NoError(err)
	sk, err := BytesToPrivateKey(priKeyBytes, false)
	require.NoError(err)

	require.Equal(publicKey, pk.HexString())
	require.Equal(privateKey, sk.HexString())

	_, err = StringToPubKeyBytes("", false)
	require.Error(err)

	_, err = StringToPubKeyBytes(publicKey, false)
	require.NoError(err)
}

func TestSm2Keypair(t *testing.T) {
	require := require.New(t)

	_, err := HexStringToPublicKey("", true)
	require.True(strings.Contains(err.Error(), "invalid secp256k1 public key"))
	_, err = HexStringToPrivateKey("", true)
	require.True(strings.Contains(err.Error(), "invalid length, need 256 bits"))

	pubKey, err := HexStringToPublicKey(sm2publicKey, true)
	require.NoError(err)

	pubKey2, err := HexStringToPublicKey(sm2publicKey[2:], true)
	require.NoError(err)
	require.Equal(pubKey, pubKey2)

	priKey, err := HexStringToPrivateKey(sm2privateKey, true)
	require.NoError(err)

	require.Equal(sm2publicKey, pubKey.HexString())
	require.Equal(sm2privateKey, priKey.HexString())

	pubKeyBytes := pubKey.Bytes()
	priKeyBytes := priKey.Bytes()

	_, err = BytesToPublicKey([]byte{1, 2, 3}, true)
	require.Error(err)
	_, err = BytesToPrivateKey([]byte{4, 5, 6}, true)
	require.Error(err)

	pk, err := BytesToPublicKey(pubKeyBytes, true)
	require.NoError(err)
	sk, err := BytesToPrivateKey(priKeyBytes, true)
	require.NoError(err)

	require.Equal(sm2publicKey, pk.HexString())
	require.Equal(sm2privateKey, sk.HexString())

	_, err = StringToPubKeyBytes("", true)
	require.Error(err)

	_, err = StringToPubKeyBytes(sm2publicKey, true)
	require.NoError(err)
}

/*
TODO (dustinxie): revise this unit test: don't use address
func TestCompatibility(t *testing.T) {
	require := require.New(t)

	sk, err := crypto.GenerateKey()
	require.NoError(err)
	ethAddr := crypto.PubkeyToAddress(sk.PublicKey)
	nsk := &secp256k1PrvKey{PrivateKey: sk}
	addr, err := address.FromBytes(nsk.PublicKey().Hash())
	require.NoError(err)
	require.Equal(ethAddr.Bytes(), addr.Bytes())
}
*/
