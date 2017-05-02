package secp256k1

import "unsafe"
import "C"


func goBool(success C.int) bool {
	return success == 1
}

func cBuf(goSlice []byte) *C.uchar {
	return (*C.uchar)(unsafe.Pointer(&goSlice[0]))
}