// itsrisky provide some sign helper method for web application
package itsrisky

import (
	"hash"
	"unsafe"
)

// common signer to provide normal sign method
type Signer struct {
	SecretKey string
	Hash      hash.Hash
}

// signer to provide sign method with timeout
type SignerWithTimeout struct {
	SecretKey string
	Hash      hash.Hash
}

// serialization to provide a serializer with web-friendly
type Serialization struct {
	SecretKey string
	Hash      hash.Hash
	salt      string
}

//return GoString's buffer slice(enable modify string)
func StringBytes(s string) []byte {
	return *(*[]byte)(unsafe.Pointer(&s))
}

// convert b to string without copy
func BytesString(b []byte) string {
	return *(*string)(unsafe.Pointer(&b))
}
