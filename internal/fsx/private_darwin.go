package fsx

import (
	"encoding/binary"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	attrBitMapCount       = 5
	attrCmnextPrivateSize = 0x00000008 // bytes that a delete frees: blocks shared with APFS clones are not counted
	fsoptNoFollow         = 0x00000001
	fsoptAttrCmnExtended  = 0x00000020
)

// PrivateSize asks APFS how many bytes deleting this file would free. ok is false when the volume cannot say.
func PrivateSize(path string) (int64, bool) {
	p, err := unix.BytePtrFromString(path)
	if err != nil {
		return 0, false
	}
	al := unix.Attrlist{Bitmapcount: attrBitMapCount, Forkattr: attrCmnextPrivateSize}
	var buf [32]byte
	_, _, e := unix.Syscall6(unix.SYS_GETATTRLIST, uintptr(unsafe.Pointer(p)), uintptr(unsafe.Pointer(&al)),
		uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), fsoptNoFollow|fsoptAttrCmnExtended, 0)
	if e != 0 {
		return 0, false
	}
	if binary.LittleEndian.Uint32(buf[0:4]) < 12 {
		return 0, false
	}
	return int64(binary.LittleEndian.Uint64(buf[4:12])), true
}
