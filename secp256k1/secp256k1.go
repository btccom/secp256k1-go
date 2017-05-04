package secp256k1

// #include <stdlib.h>
// #include "c-secp256k1/include/secp256k1.h"
// #include "c-secp256k1/include/secp256k1_ecdh.h"
// #include "c-secp256k1/include/secp256k1_recovery.h"
/*
// for secp256k1_pubkey** https://groups.google.com/forum/#!topic/golang-nuts/pQueMFdY0mk
static secp256k1_pubkey** makePubkeyArray(int size) {
        return calloc(sizeof(secp256k1_pubkey*), size);
}
static void setArrayPubkey(secp256k1_pubkey **a, secp256k1_pubkey *pubkey, int n) {
        a[n] = pubkey;
}
static void freePubkeyArray(secp256k1_pubkey **a) {
        free(a);
}
*/
// #cgo LDFLAGS: ${SRCDIR}/c-secp256k1/.libs/libsecp256k1.a -lgmp
import "C"

import (
	"github.com/pkg/errors"
	"unsafe"
)

const (
	/** Flags to pass to secp256k1_context_create. */
	ContextVerify = uint(C.SECP256K1_CONTEXT_VERIFY)
	ContextSign   = uint(C.SECP256K1_CONTEXT_SIGN)

	/** Flag to pass to secp256k1_ec_pubkey_serialize and secp256k1_ec_privkey_export. */
	EcCompressed   = uint(C.SECP256K1_EC_COMPRESSED)
	EcUncompressed = uint(C.SECP256K1_EC_UNCOMPRESSED)

	LenCompressed   int = 33
	LenUncompressed int = 65

	ErrorEcdh             string = "Unable to do ECDH"
	ErrorPublicKeyCreate  string = "Unable to produce public key"
	ErrorPublicKeyCombine string = "Unable to combine public keys"

	ErrorTweakSize      string = "Tweak must be exactly 32 bytes"
	ErrorMsg32Size      string = "Message hash must be exactly 32 bytes"
	ErrorPrivateKeySize string = "Private key must be exactly 32 bytes"

	ErrorTweakingPublicKey  string = "Unable to tweak this public key"
	ErrorTweakingPrivateKey string = "Unable to tweak this private key"

	ErrorProducingSignature            string = "Unable to produce signature"
	ErrorProducingRecoverableSignature string = "Unable to produce recoverable signature"

	ErrorCompactSigSize      string = "Compact signature must be exactly 64 bytes"
	ErrorCompactSigParse     string = "Unable to parse this compact signature"
	ErrorCompactSigSerialize string = "Unable to serialize this compact signature"

	ErrorDerSigParse     string = "Unable to parse this DER signature"
	ErrorDerSigSerialize string = "Unable to serialize this DER signature"

	ErrorRecoverableSigParse     string = "Unable to parse this recoverable signature"
	ErrorRecoverableSigSerialize string = "Unable to serialize this recoverable signature"
	ErrorRecoveryFailed          string = "Failed to recover public key"

	ErrorPublicKeyParse     string = "Unable to parse this public key"
	ErrorPublicKeySerialize string = "Unable to serialize this public key"

	ErrorNegatePrivateKey string = "Unable to negate private key"
	ErrorNegatePublicKey  string = "Unable to negate public key"
)

type Context struct {
	ctx *C.secp256k1_context
}

type PublicKey struct {
	pk *C.secp256k1_pubkey
}

type EcdsaSignature struct {
	sig *C.secp256k1_ecdsa_signature
}
type EcdsaRecoverableSignature struct {
	sig *C.secp256k1_ecdsa_recoverable_signature
}

func newContext() *Context {
	return &Context{
		ctx: &C.secp256k1_context{},
	}
}
func newPublicKey() *PublicKey {
	return &PublicKey{
		pk: &C.secp256k1_pubkey{},
	}
}
func newEcdsaSignature() *EcdsaSignature {
	return &EcdsaSignature{
		sig: &C.secp256k1_ecdsa_signature{},
	}
}
func newEcdsaRecoverableSignature() *EcdsaRecoverableSignature {
	return &EcdsaRecoverableSignature{
		sig: &C.secp256k1_ecdsa_recoverable_signature{},
	}
}

/** Create a secp256k1 context object.
 *
 *  Returns: a newly created context object.
 *  In:      flags: which parts of the context to initialize.
 */
func ContextCreate(flags uint) (*Context, error) {

	context := newContext()
	context.ctx = C.secp256k1_context_create(C.uint(flags))

	return context, nil
}

/** Copies a secp256k1 context object.
 *
 *  Returns: a newly created context object.
 *  Args:    ctx: an existing context to copy (cannot be NULL)
 */
func ContextClone(ctx *Context) (*Context, error) {

	other := newContext()
	other.ctx = C.secp256k1_context_clone(ctx.ctx)

	return other, nil
}

/** Destroy a secp256k1 context object.
 *
 *  The context pointer may not be used afterwards.
 *  Args:   ctx: an existing context to destroy (cannot be NULL)
 */
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

/** Parse a variable-length public key into the pubkey object.
 *
 *  Returns: 1 if the public key was fully valid.
 *           0 if the public key could not be parsed or is invalid.
 *  Args: ctx:      a secp256k1 context object.
 *  Out:  pubkey:   pointer to a pubkey object. If 1 is returned, it is set to a
 *                  parsed version of input. If not, its value is undefined.
 *  In:   input:    pointer to a serialized public key
 *        inputlen: length of the array pointed to by input
 *
 *  This function supports parsing compressed (33 bytes, header byte 0x02 or
 *  0x03), uncompressed (65 bytes, header byte 0x04), or hybrid (65 bytes, header
 *  byte 0x06 or 0x07) format public keys.
 */
func EcPubkeyParse(ctx *Context, publicKey []byte) (int, *PublicKey, error) {
	l := len(publicKey)
	if l != LenCompressed && l != LenUncompressed {
		return 0, nil, errors.New(ErrorPublicKeyParse)
	}

	pk := newPublicKey()
	result := int(C.secp256k1_ec_pubkey_parse(ctx.ctx, pk.pk, cBuf(publicKey), C.size_t(l)))
	if result != 1 {
		return result, nil, errors.New(ErrorPublicKeyParse)
	}
	return result, pk, nil
}

/** Serialize a pubkey object into a serialized byte sequence.
 *
 *  Returns: 1 always.
 *  Args:   ctx:        a secp256k1 context object.
 *  Out:    output:     a pointer to a 65-byte (if compressed==0) or 33-byte (if
 *                      compressed==1) byte array to place the serialized key
 *                      in.
 *  In/Out: outputlen:  a pointer to an integer which is initially set to the
 *                      size of output, and is overwritten with the written
 *                      size.
 *  In:     pubkey:     a pointer to a secp256k1_pubkey containing an
 *                      initialized public key.
 *          flags:      SECP256K1_EC_COMPRESSED if serialization should be in
 *                      compressed format, otherwise SECP256K1_EC_UNCOMPRESSED.
 */
func EcPubkeySerialize(ctx *Context, publicKey *PublicKey, flags uint) (int, []byte, error) {
	var size int
	if flags == EcCompressed {
		size = 33
	} else {
		size = 65
	}

	output := make([]C.uchar, size)
	outputLen := C.size_t(size)

	result := int(C.secp256k1_ec_pubkey_serialize(ctx.ctx, &output[0], &outputLen, publicKey.pk, C.uint(flags)))
	if result != 1 {
		return result, []byte(``), errors.New(ErrorPublicKeySerialize)
	}
	return result, goBytes(output, C.int(outputLen)), nil
}

/** Parse an ECDSA signature in compact (64 bytes) format.
 *
 *  Returns: 1 when the signature could be parsed, 0 otherwise.
 *  Args: ctx:      a secp256k1 context object
 *  Out:  sig:      a pointer to a signature object
 *  In:   input64:  a pointer to the 64-byte array to parse
 *
 *  The signature must consist of a 32-byte big endian R value, followed by a
 *  32-byte big endian S value. If R or S fall outside of [0..order-1], the
 *  encoding is invalid. R and S with value 0 are allowed in the encoding.
 *
 *  After the call, sig will always be initialized. If parsing failed or R or
 *  S are zero, the resulting sig value is guaranteed to fail validation for any
 *  message and public key.
 */
func EcdsaSignatureParseCompact(ctx *Context, signature []byte) (int, *EcdsaSignature, error) {
	if len(signature) != 64 {
		return 0, nil, errors.New(ErrorCompactSigSize)
	}

	sig := newEcdsaSignature()

	result := int(C.secp256k1_ecdsa_signature_parse_compact(ctx.ctx, sig.sig,
		(*C.uchar)(unsafe.Pointer(&signature[0])),
	))
	if result != 1 {
		return result, nil, errors.New(ErrorCompactSigParse)
	}
	return result, sig, nil
}

/** Serialize an ECDSA signature in compact (64 byte) format.
 *
 *  Returns: 1
 *  Args:   ctx:       a secp256k1 context object
 *  Out:    output64:  a pointer to a 64-byte array to store the compact serialization
 *  In:     sig:       a pointer to an initialized signature object
 *
 *  See secp256k1_ecdsa_signature_parse_compact for details about the encoding.
 */
func EcdsaSignatureSerializeCompact(ctx *Context, sig *EcdsaSignature) (int, []byte, error) {
	output := make([]C.uchar, 64)
	outputLen := C.size_t(64)

	result := int(C.secp256k1_ecdsa_signature_serialize_compact(ctx.ctx, &output[0], sig.sig))
	if result != 1 {
		return result, []byte(``), errors.New(ErrorCompactSigParse)
	}
	return result, goBytes(output, C.int(outputLen)), nil
}

/** Parse a DER ECDSA signature.
 *
 *  Returns: 1 when the signature could be parsed, 0 otherwise.
 *  Args: ctx:      a secp256k1 context object
 *  Out:  sig:      a pointer to a signature object
 *  In:   input:    a pointer to the signature to be parsed
 *        inputlen: the length of the array pointed to be input
 *
 *  This function will accept any valid DER encoded signature, even if the
 *  encoded numbers are out of range.
 *
 *  After the call, sig will always be initialized. If parsing failed or the
 *  encoded numbers are out of range, signature validation with it is
 *  guaranteed to fail for every message and public key.
 */
func EcdsaSignatureParseDer(ctx *Context, signature []byte) (int, *EcdsaSignature, error) {
	sig := newEcdsaSignature()

	result := int(C.secp256k1_ecdsa_signature_parse_der(ctx.ctx, sig.sig,
		(*C.uchar)(unsafe.Pointer(&signature[0])),
		(C.size_t)(len(signature))))

	if result != 1 {
		return result, nil, errors.New(ErrorDerSigParse)
	}
	return result, sig, nil
}

/** Serialize an ECDSA signature in DER format.
 *
 *  Returns: 1 if enough space was available to serialize, 0 otherwise
 *  Args:   ctx:       a secp256k1 context object
 *  Out:    output:    a pointer to an array to store the DER serialization
 *  In/Out: outputlen: a pointer to a length integer. Initially, this integer
 *                     should be set to the length of output. After the call
 *                     it will be set to the length of the serialization (even
 *                     if 0 was returned).
 *  In:     sig:       a pointer to an initialized signature object
 */
func EcdsaSignatureSerializeDer(ctx *Context, sig *EcdsaSignature) (int, []byte, error) {
	serializedSig := make([]C.uchar, 72)
	outputLen := C.size_t(len(serializedSig))

	result := int(C.secp256k1_ecdsa_signature_serialize_der(ctx.ctx, &serializedSig[0], &outputLen, sig.sig))
	if result != 1 {
		return result, []byte(``), errors.New(ErrorDerSigSerialize)
	}
	return result, goBytes(serializedSig, C.int(outputLen)), nil
}

/** Verify an ECDSA signature.
 *
 *  Returns: 1: correct signature
 *           0: incorrect or unparseable signature
 *  Args:    ctx:       a secp256k1 context object, initialized for verification.
 *  In:      sig:       the signature being verified (cannot be NULL)
 *           msg32:     the 32-byte message hash being verified (cannot be NULL)
 *           pubkey:    pointer to an initialized public key to verify with (cannot be NULL)
 *
 * To avoid accepting malleable signatures, only ECDSA signatures in lower-S
 * form are accepted.
 *
 * If you need to accept ECDSA signatures from sources that do not obey this
 * rule, apply secp256k1_ecdsa_signature_normalize to the signature prior to
 * validation, but be aware that doing so results in malleable signatures.
 *
 * For details, see the comments for that function.
 */
func EcdsaVerify(ctx *Context, sig *EcdsaSignature, msg32 []byte, pubkey *PublicKey) int {
	return int(C.secp256k1_ecdsa_verify(ctx.ctx, sig.sig, cBuf(msg32[:]), pubkey.pk))
}

/** Create an ECDSA signature.
 *
 *  Returns: 1: signature created
 *           0: the nonce generation function failed, or the private key was invalid.
 *  Args:    ctx:    pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:     sig:    pointer to an array where the signature will be placed (cannot be NULL)
 *  In:      msg32:  the 32-byte message hash being signed (cannot be NULL)
 *           seckey: pointer to a 32-byte secret key (cannot be NULL)
 *           noncefp:pointer to a nonce generation function. If NULL, secp256k1_nonce_function_default is used
 *           ndata:  pointer to arbitrary data used by the nonce generation function (can be NULL)
 *
 * The created signature is always in lower-S form. See
 * secp256k1_ecdsa_signature_normalize for more details.
 */
func EcdsaSign(ctx *Context, msg32 []byte, seckey []byte) (int, *EcdsaSignature, error) {
	if len(msg32) != 32 {
		return 0, nil, errors.New(ErrorMsg32Size)
	}
	if len(seckey) != 32 {
		return 0, nil, errors.New(ErrorPrivateKeySize)
	}

	signature := newEcdsaSignature()
	result := int(C.secp256k1_ecdsa_sign(ctx.ctx, signature.sig,
		cBuf(msg32[:]), cBuf(seckey[:]), nil, nil))

	if result != 1 {
		return result, nil, errors.New(ErrorProducingSignature)
	}

	return result, signature, nil
}

/** Verify an ECDSA secret key.
 *
 *  Returns: 1: secret key is valid
 *           0: secret key is invalid
 *  Args:    ctx: pointer to a context object (cannot be NULL)
 *  In:      seckey: pointer to a 32-byte secret key (cannot be NULL)
 */
func EcSeckeyVerify(ctx *Context, seckey []byte) int {
	return int(C.secp256k1_ec_seckey_verify(ctx.ctx, cBuf(seckey[:])))
}

/** Compute the public key for a secret key.
 *
 *  Returns: 1: secret was valid, public key stores
 *           0: secret was invalid, try again
 *  Args:   ctx:        pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:    pubkey:     pointer to the created public key (cannot be NULL)
 *  In:     seckey:     pointer to a 32-byte private key (cannot be NULL)
 */
func EcPubkeyCreate(ctx *Context, seckey []byte) (int, *PublicKey, error) {
	if len(seckey) != 32 {
		return 0, nil, errors.New(ErrorPrivateKeySize)
	}

	pk := newPublicKey()

	result := int(C.secp256k1_ec_pubkey_create(ctx.ctx, pk.pk, cBuf(seckey[:])))
	if result != 1 {
		return result, nil, errors.New(ErrorPublicKeyCreate)
	}
	return result, pk, nil
}

/** Negates a private key in place.
 *
 *  Returns: 1 always
 *  Args:   ctx:        pointer to a context object
 *  In/Out: pubkey:     pointer to the public key to be negated (cannot be NULL)
 */
func EcPrivkeyNegate(ctx *Context, seckey []byte) (int, error) {
	if len(seckey) != 32 {
		return 0, errors.New(ErrorPrivateKeySize)
	}

	result := int(C.secp256k1_ec_privkey_negate(ctx.ctx, (*C.uchar)(unsafe.Pointer(&seckey[0]))))
	if result != 1 {
		return result, errors.New(ErrorNegatePrivateKey)
	}
	return result, nil
}

/** Negates a public key in place.
 *
 *  Returns: 1 always
 *  Args:   ctx:        pointer to a context object
 *  In/Out: pubkey:     pointer to the public key to be negated (cannot be NULL)
 */
func EcPubkeyNegate(ctx *Context, pubkey *PublicKey) (int, error) {
	result := int(C.secp256k1_ec_pubkey_negate(ctx.ctx, pubkey.pk))
	return result, nil
}

/** Tweak a private key by adding tweak to it.
 * Returns: 0 if the tweak was out of range (chance of around 1 in 2^128 for
 *          uniformly random 32-byte arrays, or if the resulting private key
 *          would be invalid (only when the tweak is the complement of the
 *          private key). 1 otherwise.
 * Args:    ctx:    pointer to a context object (cannot be NULL).
 * In/Out:  seckey: pointer to a 32-byte private key.
 * In:      tweak:  pointer to a 32-byte tweak.
 */
func EcPrivkeyTweakAdd(ctx *Context, seckey []byte, tweak []byte) (int, error) {
	if len(seckey) != 32 {
		return 0, errors.New(ErrorPrivateKeySize)
	}
	if len(tweak) != 32 {
		return 0, errors.New(ErrorTweakSize)
	}

	result := int(C.secp256k1_ec_privkey_tweak_add(ctx.ctx, (*C.uchar)(unsafe.Pointer(&seckey[0])), cBuf(tweak[:])))
	if result != 1 {
		return result, errors.New(ErrorTweakingPrivateKey)
	}
	return result, nil
}

/** Tweak a public key by adding tweak times the generator to it.
 * Returns: 0 if the tweak was out of range (chance of around 1 in 2^128 for
 *          uniformly random 32-byte arrays, or if the resulting public key
 *          would be invalid (only when the tweak is the complement of the
 *          corresponding private key). 1 otherwise.
 * Args:    ctx:    pointer to a context object initialized for validation
 *                  (cannot be NULL).
 * In/Out:  pubkey: pointer to a public key object.
 * In:      tweak:  pointer to a 32-byte tweak.
 */
func EcPrivkeyTweakMul(ctx *Context, seckey []byte, tweak []byte) (int, error) {
	if len(seckey) != 32 {
		return 0, errors.New(ErrorPrivateKeySize)
	}
	if len(tweak) != 32 {
		return 0, errors.New(ErrorTweakSize)
	}

	result := int(C.secp256k1_ec_privkey_tweak_mul(ctx.ctx, (*C.uchar)(unsafe.Pointer(&seckey[0])), cBuf(tweak[:])))
	if result != 1 {
		return result, errors.New(ErrorTweakingPrivateKey)
	}
	return result, nil
}

/** Tweak a private key by multiplying it by a tweak.
 * Returns: 0 if the tweak was out of range (chance of around 1 in 2^128 for
 *          uniformly random 32-byte arrays, or equal to zero. 1 otherwise.
 * Args:   ctx:    pointer to a context object (cannot be NULL).
 * In/Out: seckey: pointer to a 32-byte private key.
 * In:     tweak:  pointer to a 32-byte tweak.
 */
func EcPubkeyTweakAdd(ctx *Context, pk *PublicKey, tweak []byte) (int, error) {
	if len(tweak) != 32 {
		return 0, errors.New(ErrorTweakSize)
	}

	result := int(C.secp256k1_ec_pubkey_tweak_add(ctx.ctx, pk.pk, cBuf(tweak)))
	if result != 1 {
		return result, errors.New(ErrorTweakingPublicKey)
	}
	return result, nil
}

/** Tweak a public key by multiplying it by a tweak value.
 * Returns: 0 if the tweak was out of range (chance of around 1 in 2^128 for
 *          uniformly random 32-byte arrays, or equal to zero. 1 otherwise.
 * Args:    ctx:    pointer to a context object initialized for validation
 *                 (cannot be NULL).
 * In/Out:  pubkey: pointer to a public key obkect.
 * In:      tweak:  pointer to a 32-byte tweak.
 */
func EcPubkeyTweakMul(ctx *Context, pk *PublicKey, tweak []byte) (int, error) {
	if len(tweak) != 32 {
		return 0, errors.New(ErrorTweakSize)
	}

	result := int(C.secp256k1_ec_pubkey_tweak_mul(ctx.ctx, pk.pk, cBuf(tweak)))
	if result != 1 {
		return result, errors.New(ErrorTweakingPublicKey)
	}
	return result, nil
}

/** Add a number of public keys together.
 *  Returns: 1: the sum of the public keys is valid.
 *           0: the sum of the public keys is not valid.
 *  Args:   ctx:        pointer to a context object
 *  Out:    out:        pointer to a public key object for placing the resulting public key
 *                      (cannot be NULL)
 *  In:     ins:        pointer to array of pointers to public keys (cannot be NULL)
 *          n:          the number of public keys to add together (must be at least 1)
 */
func EcPubkeyCombine(ctx *Context, vPk []*PublicKey) (int, *PublicKey, error) {
	l := len(vPk)
	array := C.makePubkeyArray(C.int(l))
	for i := 0; i < l; i++ {
		C.setArrayPubkey(array, vPk[i].pk, C.int(i))
	}

	defer C.freePubkeyArray(array)

	pkOut := newPublicKey()
	result := int(C.secp256k1_ec_pubkey_combine(ctx.ctx, pkOut.pk, array, C.size_t(l)))
	if result != 1 {
		return result, nil, errors.New(ErrorPublicKeyCombine)
	}

	return result, pkOut, nil
}

/** Compute an EC Diffie-Hellman secret in constant time
 *  Returns: 1: exponentiation was successful
 *           0: scalar was invalid (zero or overflow)
 *  Args:    ctx:        pointer to a context object (cannot be NULL)
 *  Out:     result:     a 32-byte array which will be populated by an ECDH
 *                       secret computed from the point and scalar
 *  In:      pubkey:     a pointer to a secp256k1_pubkey containing an
 *                       initialized public key
 *           privkey:    a 32-byte scalar with which to multiply the point
 */
func Ecdh(ctx *Context, pubKey *PublicKey, privKey []byte) (int, []byte, error) {
	if len(privKey) != 32 {
		return 0, []byte{}, errors.New(ErrorPrivateKeySize)
	}

	secret := make([]byte, 32)
	result := int(C.secp256k1_ecdh(ctx.ctx, cBuf(secret[:]), pubKey.pk, cBuf(privKey[:])))
	if result != 1 {
		return result, []byte{}, errors.New(ErrorEcdh)
	}
	return result, secret, nil
}

/** Parse a compact ECDSA signature (64 bytes + recovery id).
 *
 *  Returns: 1 when the signature could be parsed, 0 otherwise
 *  Args: ctx:     a secp256k1 context object
 *  Out:  sig:     a pointer to a signature object
 *  In:   input64: a pointer to a 64-byte compact signature
 *        recid:   the recovery id (0, 1, 2 or 3)
 */
func EcdsaRecoverableSignatureParseCompact(ctx *Context, signature []byte, recid int) (int, *EcdsaRecoverableSignature, error) {
	if len(signature) != 64 {
		return 0, nil, errors.New(ErrorCompactSigSize)
	}

	sig := newEcdsaRecoverableSignature()

	result := int(C.secp256k1_ecdsa_recoverable_signature_parse_compact(ctx.ctx, sig.sig,
		(*C.uchar)(unsafe.Pointer(&signature[0])), (C.int(recid))))

	if result != 1 {
		return result, nil, errors.New(ErrorRecoverableSigParse)
	}
	return result, sig, nil
}

/** Serialize an ECDSA signature in compact format (64 bytes + recovery id).
 *
 *  Returns: 1
 *  Args: ctx:      a secp256k1 context object
 *  Out:  output64: a pointer to a 64-byte array of the compact signature (cannot be NULL)
 *        recid:    a pointer to an integer to hold the recovery id (can be NULL).
 *  In:   sig:      a pointer to an initialized signature object (cannot be NULL)
 */
func EcdsaRecoverableSignatureSerializeCompact(ctx *Context, sig *EcdsaRecoverableSignature) (int, []byte, int, error) {
	output := make([]C.uchar, 64)
	outputLen := C.size_t(64)

	r := C.int(0)
	result := int(C.secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx.ctx, &output[0], &r, sig.sig))
	return result, goBytes(output, C.int(outputLen)), int(r), nil
}

/** Convert a recoverable signature into a normal signature.
 *
 *  Returns: 1
 *  Out: sig:    a pointer to a normal signature (cannot be NULL).
 *  In:  sigin:  a pointer to a recoverable signature (cannot be NULL).
 */
func EcdsaRecoverableSignatureConvert(ctx *Context, sig *EcdsaRecoverableSignature) (int, *EcdsaSignature, error) {
	sigOut := newEcdsaSignature()
	result := int(C.secp256k1_ecdsa_recoverable_signature_convert(ctx.ctx, sigOut.sig, sig.sig))
	return result, sigOut, nil
}

/** Create a recoverable ECDSA signature.
 *
 *  Returns: 1: signature created
 *           0: the nonce generation function failed, or the private key was invalid.
 *  Args:    ctx:    pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:     sig:    pointer to an array where the signature will be placed (cannot be NULL)
 *  In:      msg32:  the 32-byte message hash being signed (cannot be NULL)
 *           seckey: pointer to a 32-byte secret key (cannot be NULL)
 *           noncefp:pointer to a nonce generation function. If NULL, secp256k1_nonce_function_default is used
 *           ndata:  pointer to arbitrary data used by the nonce generation function (can be NULL)
 */
func EcdsaSignRecoverable(ctx *Context, msg32 []byte, seckey []byte) (int, *EcdsaRecoverableSignature, error) {
	if len(msg32) != 32 {
		return 0, nil, errors.New(ErrorMsg32Size)
	}
	if len(seckey) != 32 {
		return 0, nil, errors.New(ErrorPrivateKeySize)
	}

	recoverable := newEcdsaRecoverableSignature()
	result := int(C.secp256k1_ecdsa_sign_recoverable(ctx.ctx, recoverable.sig, cBuf(msg32), cBuf(seckey), nil, nil))
	if result != 1 {
		return result, nil, errors.New(ErrorProducingRecoverableSignature)
	}
	return result, recoverable, nil

}

/** Recover an ECDSA public key from a signature.
 *
 *  Returns: 1: public key successfully recovered (which guarantees a correct signature).
 *           0: otherwise.
 *  Args:    ctx:        pointer to a context object, initialized for verification (cannot be NULL)
 *  Out:     pubkey:     pointer to the recovered public key (cannot be NULL)
 *  In:      sig:        pointer to initialized signature that supports pubkey recovery (cannot be NULL)
 *           msg32:      the 32-byte message hash assumed to be signed (cannot be NULL)
 */
func EcdsaRecover(ctx *Context, sig *EcdsaRecoverableSignature, msg32 []byte) (int, *PublicKey, error) {
	if len(msg32) != 32 {
		return 0, nil, errors.New(ErrorMsg32Size)
	}
	recovered := newPublicKey()
	result := int(C.secp256k1_ecdsa_recover(ctx.ctx, recovered.pk, sig.sig, cBuf(msg32)))
	if result != 1 {
		return result, nil, errors.New(ErrorRecoveryFailed)
	}
	return result, recovered, nil
}

func cBuf(goSlice []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&goSlice[0]))
}

func goBytes(cSlice []C.uchar, size C.int) []byte {
	return C.GoBytes(unsafe.Pointer(&cSlice[0]), size)
}
