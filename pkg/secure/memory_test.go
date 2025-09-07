package secure

import (
	"bytes"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestSecureBytes(t *testing.T) {
	size := 32
	sb := NewSecureBytes(size)
	assert.Equal(t, size, sb.Len())

	data := []byte("sensitive test data here")
	sb.Set(data)
	retrieved := sb.Get()
	assert.Equal(t, data, retrieved)

	sb.Clear()
	cleared := sb.Get()
	for _, b := range cleared {
		assert.Equal(t, byte(0), b)
	}

	sb.Destroy()
}

func TestFromBytes(t *testing.T) {
	original := []byte("test data for secure bytes")
	sb := FromBytes(original)

	retrieved := sb.Get()
	assert.Equal(t, original, retrieved)

	original[0] = 0xFF
	retrieved2 := sb.Get()
	assert.NotEqual(t, original, retrieved2)
	assert.Equal(t, retrieved, retrieved2)

	sb.Destroy()
}

func TestSecureBytesResize(t *testing.T) {
	sb := NewSecureBytes(10)

	smallData := []byte("small")
	sb.Set(smallData)
	assert.Equal(t, len(smallData), sb.Len())

	largeData := []byte("much larger data than before")
	sb.Set(largeData)
	assert.Equal(t, len(largeData), sb.Len())

	retrieved := sb.Get()
	assert.Equal(t, largeData, retrieved)

	sb.Destroy()
}

func TestZero(t *testing.T) {
	data := []byte("sensitive data to be zeroed")
	original := make([]byte, len(data))
	copy(original, data)

	Zero(data)

	for _, b := range data {
		assert.Equal(t, byte(0), b)
	}
	assert.NotEqual(t, original, data)
}

func TestRandomOverwrite(t *testing.T) {
	data := []byte("data to be overwritten")
	original := make([]byte, len(data))
	copy(original, data)

	err := RandomOverwrite(data)
	require.NoError(t, err)

	for _, b := range data {
		assert.Equal(t, byte(0), b)
	}
}

func TestConstantTimeCompare(t *testing.T) {
	a := []byte("test data")
	b := []byte("test data")
	c := []byte("different")
	d := []byte("test dat")

	assert.True(t, ConstantTimeCompare(a, b))
	assert.False(t, ConstantTimeCompare(a, c))
	assert.False(t, ConstantTimeCompare(a, d))
	assert.False(t, ConstantTimeCompare(a, []byte{}))
}

func TestSecureString(t *testing.T) {
	original := "sensitive string data"
	ss := NewSecureString(original)

	retrieved := ss.String()
	assert.Equal(t, original, retrieved)

	ss.Clear()
	cleared := ss.String()
	assert.NotEqual(t, original, cleared)

	ss.Destroy()
	destroyed := ss.String()
	assert.Equal(t, "", destroyed)
}

func TestLockedBuffer(t *testing.T) {
	size := 64
	lb := NewLockedBuffer(size)

	data := []byte("test data for locked buffer")
	err := lb.Write(data)
	require.NoError(t, err)

	retrieved := lb.Read()
	assert.Equal(t, data, retrieved[:len(data)])
	assert.Len(t, retrieved, size)

	tooLarge := make([]byte, size+1)
	err = lb.Write(tooLarge)
	assert.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds buffer size")

	lb.Clear()
	cleared := lb.Read()
	for _, b := range cleared {
		assert.Equal(t, byte(0), b)
	}

	lb.Destroy()
}

func TestSecureRandom(t *testing.T) {
	sizes := []int{16, 32, 64, 128}

	for _, size := range sizes {
		t.Run(string(rune(size)), func(t *testing.T) {
			data, err := SecureRandom(size)
			require.NoError(t, err)
			assert.Len(t, data, size)

			data2, err := SecureRandom(size)
			require.NoError(t, err)
			assert.NotEqual(t, data, data2, "Random data should be different")
		})
	}

	_, err := SecureRandom(0)
	assert.NoError(t, err)
}

func TestClearString(t *testing.T) {
	str := "sensitive string"
	ClearString(&str)
	assert.Equal(t, "", str)

	ClearString(nil)
}

func TestClearBytes(t *testing.T) {
	data := []byte("sensitive bytes")
	original := make([]byte, len(data))
	copy(original, data)

	ClearBytes(&data)
	assert.Nil(t, data)

	ClearBytes(nil)

	var nilSlice []byte
	ClearBytes(&nilSlice)
	assert.Nil(t, nilSlice)
}

func TestSecureBytesThreadSafety(t *testing.T) {
	sb := FromBytes([]byte("concurrent test data"))
	defer sb.Destroy()

	done := make(chan bool, 2)

	go func() {
		for i := 0; i < 100; i++ {
			data := sb.Get()
			assert.NotNil(t, data)
		}
		done <- true
	}()

	go func() {
		for i := 0; i < 100; i++ {
			sb.Set([]byte("updated data"))
		}
		done <- true
	}()

	<-done
	<-done
}

func TestConstantTimeCopy(t *testing.T) {
	src := []byte("source data")
	dst := make([]byte, len(src))

	ConstantTimeCopy(dst, src)
	assert.Equal(t, src, dst)

	assert.Panics(t, func() {
		ConstantTimeCopy(make([]byte, 5), src)
	})
}

func BenchmarkSecureBytes(b *testing.B) {
	sb := NewSecureBytes(32)
	data := []byte("benchmark test data here")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		sb.Set(data)
		_ = sb.Get()
	}
}

func BenchmarkZero(b *testing.B) {
	data := make([]byte, 1024)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		Zero(data)
	}
}

func BenchmarkConstantTimeCompare(b *testing.B) {
	a := bytes.Repeat([]byte{0x42}, 32)
	b1 := bytes.Repeat([]byte{0x42}, 32)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ConstantTimeCompare(a, b1)
	}
}
