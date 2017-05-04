package secp256k1

import (
	"crypto/rand"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"io"
	"testing"
)

const (
	TestCompactSig   string = `fe5fe404f3d8c21e1204a08c38ff3912d43c5a22541d2f1cdc4977cbcad240015a3b6e9040f62cacf016df4fef9412091592e4908e5e3a7bd2a42a4d1be01951`
)

func testingRand32() [32]byte {
	key := [32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return key
}
func testingRand(n int) []byte {
	key := make([]byte, n)
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
		panic(err)
	}
	return key
}

func Test_ContextCreate1(t *testing.T) {

	params := uint(ContextSign | ContextVerify)
	ctx, err := ContextCreate(params)

	assert.NoError(t, err)
	assert.NotNil(t, ctx)
	assert.IsType(t, Context{}, *ctx)

	clone, err := ContextClone(ctx)
	assert.NoError(t, err)
	assert.NotNil(t, ctx)
	assert.IsType(t, Context{}, *ctx)

	ContextDestroy(clone)

	res := ContextRandomize(ctx, testingRand32())
	assert.Equal(t, 1, res)
}

func Test_EcdsaSignatureParseCompact(t *testing.T) {
	ctx, err := ContextCreate(uint(ContextSign | ContextVerify))
	if err != nil {
		panic(err)
	}

	sigByte, err := hex.DecodeString(TestCompactSig)

	s, sig, err := EcdsaSignatureParseCompact(ctx, sigByte)
	if err != nil {
		panic(err)
	}

	assert.IsType(t, EcdsaSignature{}, *sig)
	assert.Equal(t, 1, s)
	assert.NoError(t, err)

	s, out, err := EcdsaSignatureSerializeCompact(ctx, sig)
	assert.Equal(t, 1, s)
	assert.NoError(t, err)
	assert.Equal(t, TestCompactSig, hex.EncodeToString(out))

}
