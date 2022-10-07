package session

import (
	"crypto/rand"
	"encoding/hex"
	"io"
	"sync"
)

// https://github.com/google/uuid

const randPoolSize = 16 * 16

var (
	poolMu  sync.Mutex
	poolPos = randPoolSize     // protected with poolMu
	pool    [randPoolSize]byte // protected with poolMu
)

func newUUID() string {
	var uuid [16]byte
	poolMu.Lock()
	if poolPos == randPoolSize {
		io.ReadFull(rand.Reader, pool[:])
		poolPos = 0
	}
	copy(uuid[:], pool[poolPos:(poolPos+16)])
	poolPos += 16
	poolMu.Unlock()

	uuid[6] = (uuid[6] & 0x0f) | 0x40 // Version 4
	uuid[8] = (uuid[8] & 0x3f) | 0x80 // Variant is 10

	var buf [36]byte
	encodeHex(buf[:], uuid[:])
	return string(buf[:])
}

func encodeHex(dst []byte, uuid []byte) {
	hex.Encode(dst, uuid[:4])
	dst[8] = '-'
	hex.Encode(dst[9:13], uuid[4:6])
	dst[13] = '-'
	hex.Encode(dst[14:18], uuid[6:8])
	dst[18] = '-'
	hex.Encode(dst[19:23], uuid[8:10])
	dst[23] = '-'
	hex.Encode(dst[24:], uuid[10:])
}
