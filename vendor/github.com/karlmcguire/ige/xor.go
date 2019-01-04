package ige

import (
	"runtime"
	"unsafe"
)

const (
	word      = int(unsafe.Sizeof(uintptr(0)))
	unaligned = runtime.GOARCH == "386" ||
		runtime.GOARCH == "amd64" ||
		runtime.GOARCH == "ppc64" ||
		runtime.GOARCH == "ppc64le" ||
		runtime.GOARCH == "s390x"
)

func safe(dst, a, b []byte) int {
	n := len(a)

	if len(b) < n {
		n = len(b)
	}

	for i := 0; i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}

	return n
}

func fast(dst, a, b []byte) int {
	n := len(a)

	if len(b) < n {
		n = len(b)
	}

	if n == 0 {
		return 0
	}

	_ = dst[n-1]
	w := n / word

	if w > 0 {
		dw := *(*[]uintptr)(unsafe.Pointer(&dst))
		aw := *(*[]uintptr)(unsafe.Pointer(&a))
		bw := *(*[]uintptr)(unsafe.Pointer(&b))

		for i := 0; i < w; i++ {
			dw[i] = aw[i] ^ bw[i]
		}
	}

	for i := (n - n%word); i < n; i++ {
		dst[i] = a[i] ^ b[i]
	}

	return n
}

func xor(dst, a, b []byte) int {
	if unaligned {
		return fast(dst, a, b)
	}
	return safe(dst, a, b)
}
