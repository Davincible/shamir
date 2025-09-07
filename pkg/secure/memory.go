package secure

import (
	"crypto/rand"
	"crypto/subtle"
	"fmt"
	"runtime"
	"sync"
)

type SecureBytes struct {
	data []byte
	mu   sync.RWMutex
}

func NewSecureBytes(size int) *SecureBytes {
	return &SecureBytes{
		data: make([]byte, size),
	}
}

func FromBytes(data []byte) *SecureBytes {
	sb := &SecureBytes{
		data: make([]byte, len(data)),
	}
	copy(sb.data, data)
	return sb
}

func (sb *SecureBytes) Set(data []byte) {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	if len(data) != len(sb.data) {
		Zero(sb.data)
		sb.data = make([]byte, len(data))
	}
	copy(sb.data, data)
}

func (sb *SecureBytes) Get() []byte {
	sb.mu.RLock()
	defer sb.mu.RUnlock()

	result := make([]byte, len(sb.data))
	copy(result, sb.data)
	return result
}

func (sb *SecureBytes) Clear() {
	sb.mu.Lock()
	defer sb.mu.Unlock()

	Zero(sb.data)
	runtime.GC()
}

func (sb *SecureBytes) Len() int {
	sb.mu.RLock()
	defer sb.mu.RUnlock()
	return len(sb.data)
}

func (sb *SecureBytes) Destroy() {
	sb.Clear()
	sb.data = nil
}

func Zero(b []byte) {
	for i := range b {
		b[i] = 0
	}
	runtime.KeepAlive(b)
}

func RandomOverwrite(b []byte) error {
	if _, err := rand.Read(b); err != nil {
		return fmt.Errorf("failed to overwrite with random data: %w", err)
	}
	Zero(b)
	return nil
}

func ConstantTimeCompare(x, y []byte) bool {
	if len(x) != len(y) {
		return false
	}
	return subtle.ConstantTimeCompare(x, y) == 1
}

func ConstantTimeCopy(dst, src []byte) {
	if len(dst) != len(src) {
		panic("secure: dst and src must have same length")
	}
	subtle.ConstantTimeCopy(1, dst, src)
}

type SecureString struct {
	data *SecureBytes
}

func NewSecureString(s string) *SecureString {
	return &SecureString{
		data: FromBytes([]byte(s)),
	}
}

func (ss *SecureString) String() string {
	if ss.data == nil {
		return ""
	}
	return string(ss.data.Get())
}

func (ss *SecureString) Clear() {
	if ss.data != nil {
		ss.data.Clear()
	}
}

func (ss *SecureString) Destroy() {
	if ss.data != nil {
		ss.data.Destroy()
		ss.data = nil
	}
}

type LockedBuffer struct {
	data []byte
	size int
	mu   sync.Mutex
}

func NewLockedBuffer(size int) *LockedBuffer {
	return &LockedBuffer{
		data: make([]byte, size),
		size: size,
	}
}

func (lb *LockedBuffer) Write(data []byte) error {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	if len(data) > lb.size {
		return fmt.Errorf("data exceeds buffer size")
	}

	Zero(lb.data)
	copy(lb.data, data)
	return nil
}

func (lb *LockedBuffer) Read() []byte {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	result := make([]byte, lb.size)
	copy(result, lb.data)
	return result
}

func (lb *LockedBuffer) Clear() {
	lb.mu.Lock()
	defer lb.mu.Unlock()

	Zero(lb.data)
}

func (lb *LockedBuffer) Destroy() {
	lb.Clear()
	lb.data = nil
}

func ClearString(s *string) {
	if s == nil {
		return
	}
	*s = ""
	runtime.GC()
}

func ClearBytes(b *[]byte) {
	if b == nil || *b == nil {
		return
	}
	Zero(*b)
	*b = nil
	runtime.GC()
}

func SecureRandom(size int) ([]byte, error) {
	b := make([]byte, size)
	if _, err := rand.Read(b); err != nil {
		Zero(b)
		return nil, fmt.Errorf("failed to generate secure random bytes: %w", err)
	}
	return b, nil
}
