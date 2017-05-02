package secp256k1

// #include "c-secp256k1/include/secp256k1.h"
// #cgo LDFLAGS: ${SRCDIR}/c-secp256k1/.libs/libsecp256k1.a -lgmp
import "C"

import(
"unsafe"
)

const (
	Secp256k1ContextVerify = C.SECP256K1_CONTEXT_VERIFY
	Secp256k1ContextSign = C.SECP256K1_CONTEXT_SIGN
)

type Context struct {
	ctx *C.secp256k1_context
}

/** Create a secp256k1 context object.
 *
 *  Returns: a newly created context object.
 *  In:      flags: which parts of the context to initialize.
 */
func ContextCreate(flags uint) (*Context, error) {

	context := &Context{}
	context.ctx = C.secp256k1_context_create(C.uint(flags))

	return context, nil
}

func ContextClone(ctx *Context) (*Context, error) {

	other := &Context{}
	other.ctx = C.secp256k1_context_clone(ctx.ctx)

	return other, nil
}

func ContextDestroy(ctx *Context) {
	C.secp256k1_context_destroy(ctx.ctx)
}

/** Updates the context randomization.
 *  Returns: 1: randomization successfully updated
 *           0: error
 *  Args:    ctx:       pointer to a context object (cannot be NULL)
 *  In:      seed32:    pointer to a 32-byte random seed (NULL resets to initial state)
 */
func ContextRandomize(ctx *Context, seed32 [32]byte) int {
	return int(C.secp256k1_context_randomize(ctx.ctx, cBuf(seed32[:])))
}

func cBuf(goSlice []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&goSlice[0]))
}
