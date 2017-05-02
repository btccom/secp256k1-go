package secp256k1

import (
	"testing"
	"crypto/rand"
	"io"
	"github.com/stretchr/testify/assert"
)

func testingRand32() [32]byte {
	key := [32]byte{}
	_, err := io.ReadFull(rand.Reader, key[:])
	if err != nil {
	panic(err)
	}
	return key
}

func Test_ContextCreate(t *testing.T) {

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
