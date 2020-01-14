// Copyright (c) 2019 IoTeX
// This is an alpha (internal) release and is not suitable for production. This source code is provided 'as is' and no
// warranties are given as to title or non-infringement, merchantability or fitness for purpose and, to the extent
// permitted by law, all liability for your use of the code is disclaimed. This source code is governed by Apache
// License 2.0 that can be found in the LICENSE file.

package crypto

import (
	"encoding/hex"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/iotexproject/go-pkgs/hash"
)

func TestSm2(t *testing.T) {
	require := require.New(t)

	sk, err := newSm2PrvKey()
	require.NoError(err)
	defer sk.Zero()
	require.Equal(secp256prvKeyLength, len(sk.Bytes()))
	pk := sk.PublicKey()
	require.Equal(secp256pubKeyLength, len(pk.Bytes()))
	nsk, err := newSm2PrvKeyFromBytes(sk.Bytes())
	require.NoError(err)
	require.Equal(sk, nsk)
	npk, err := newSm2PubKeyFromBytes(pk.Bytes())
	require.NoError(err)
	require.Equal(pk, npk)

	h := hash.Hash256b([]byte("test secp256k1 signature så∫jaç∂fla´´3jl©˙kl3∆˚83jl≈¥fjs2"))
	sig, err := sk.Sign(h[:])
	require.NoError(err)
	require.True(sig[secp256pubKeyLength-1] == 0 || sig[secp256pubKeyLength-1] == 1)
	require.True(pk.Verify(h[:], sig))
	for i := 0; i < len(sig)-1; i++ {
		fsig := make([]byte, len(sig))
		copy(fsig, sig)
		fsig[i]--
		require.False(pk.Verify(h[:], fsig))
	}

	sig[secp256pubKeyLength-1] += 27
	require.True(pk.Verify(h[:], sig))

	sig[secp256pubKeyLength-1] = 2
	require.False(pk.Verify(h[:], sig))

	h = hash.Hash256b([]byte("1"))
	sig, err = sk.Sign(h[:])
	require.NoError(err)
	require.True(sig[secp256pubKeyLength-1] == 0 || sig[secp256pubKeyLength-1] == 1)
	require.True(pk.Verify(h[:], sig))

	h = hash.Hash256b([]byte("2"))
	sig, err = sk.Sign(h[:])
	require.NoError(err)
	require.True(sig[secp256pubKeyLength-1] == 0 || sig[secp256pubKeyLength-1] == 1)
	require.True(pk.Verify(h[:], sig))

	b, err := hex.DecodeString("c648180dae87b91eb80499f72f7e1ea5feed12e449bbfecca86bb8070680a47d")
	require.NoError(err)
	sig, err = sk.Sign(b[:])
	require.NoError(err)
	require.True(sig[secp256pubKeyLength-1] == 0 || sig[secp256pubKeyLength-1] == 1)
	require.True(pk.Verify(b[:], sig))
}
