package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
)

const size = 16

func genCounter(nonce []byte) [size]byte {
	var counter [size]byte
	copy(counter[:], nonce)
	counter[size-1] = 1
	return counter
}

func incrementCounter(counter [size]byte) [size]byte {
	// nonce は 12バイトな想定
	// counter全体は16バイト
	// 残り4バイトのカウントを増やす
	c := counter[size-4:]
	binary.BigEndian.PutUint32(c, binary.BigEndian.Uint32(c)+1)
	copy(counter[size-4:], c)
	return counter
}

func xors(l, r []byte) []byte {
	ll := make([]byte, len(l))
	copy(ll, l)
	for i, rv := range r {
		ll[i] ^= rv
	}
	return ll
}

func enc(plaintext, key, nonce []byte) ([]byte, error) {
	return encWitchCounter(plaintext, key, nonce, genCounter(nonce))
}

func encWitchCounter(plaintext, key, nonce []byte, c [16]byte) ([]byte, error) {
	blockNum, r := len(plaintext)/size, len(plaintext)%size
	if r != 0 {
		blockNum++
	}
	// plaintext は `size` の倍数であるとは限らないため、
	// plaintext より大きい倍数になるものを暗号化対象にする
	ct := make([]byte, blockNum*size)
	copy(ct, plaintext)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	for i := 0; i < blockNum; i++ {
		start, end := size*i, size*(i+1)
		pt := ct[start:end]

		var mask [size]byte
		block.Encrypt(mask[:], c[:])
		copy(ct[start:end], xors(pt, mask[:]))

		c = incrementCounter(c)
	}
	// 事前にもともとの `plaintext`より大きいサイズになっている可能性があるので、削る
	// 暗号化前後でバイト列の長さは変わらない
	return ct[:len(plaintext)], nil
}

// 00100001
// x^7 + x^2 + x + 1
var max128 uint128 = uint128{
	lhs: 0xe100000000000000,
	rhs: 0x0000000000000000,
}

func add(lhs, rhs uint128) uint128 {
	return lhs.xor(rhs)
}

func mul(lhs, rhs uint128) uint128 {
	var sum uint128
	for b := 127; b >= 0; b-- {
		if lhs.rightShift(uint(b)).and(uint128{0, 1}) == (uint128{0, 1}) {
			// lhs >> b & 1 == 1
			sum = add(sum, rhs)
		}
		rhs = rightShift(rhs)
	}
	return sum
}

func rightShift(u uint128) uint128 {
	if u.and(uint128{0, 1}) == (uint128{0, 1}) {
		u = u.rightShift(1)
		return add(u, max128)
	} else {
		return u.rightShift(1)
	}
}

func split(in []byte) <-chan uint128 {
	ch := make(chan uint128)
	go func() {
		defer close(ch)
		for i := 0; i < len(in); i += 16 {
			var out [16]byte
			copy(out[:], in[i:])
			ch <- newUint128(out[:])
		}
	}()
	return ch
}

func newUint128(in []byte) uint128 {
	// TODO check length
	l := binary.BigEndian.Uint64(in[:8])
	r := binary.BigEndian.Uint64(in[8:])
	return uint128{l, r}
}

func ghash(cipherText, additionalData, hk []byte) [16]byte {
	h := newUint128(hk)
	var x uint128
	for v := range split(additionalData) {
		x = mul(add(x, v), h)
	}
	for v := range split(cipherText) {
		x = mul(add(x, v), h)
	}

	x = mul(add(x, uint128{
		uint64(len(additionalData) * 8),
		uint64(len(cipherText) * 8),
	}), h)

	var hashed [16]byte
	binary.BigEndian.PutUint64(hashed[:8], x.lhs)
	binary.BigEndian.PutUint64(hashed[8:], x.rhs)
	return hashed
}

func seal(plaintext, key, nonce, additionalData []byte) ([]byte, error) {
	counter := incrementCounter(genCounter(nonce))
	ct, err := encWitchCounter(plaintext, key, nonce, counter)
	if err != nil {
		return nil, err
	}

	block, _ := aes.NewCipher(key)
	hk := make([]byte, 16)
	block.Encrypt(hk, make([]byte, 16))

	xx := ghash(ct, additionalData, hk)

	encryptedCounter := make([]byte, 16)
	c := genCounter(nonce)
	block.Encrypt(encryptedCounter, c[:])

	tags := xors(encryptedCounter[:], xx[:])

	ct = append(ct, tags[:]...)
	return ct, nil
}

func main() {
	key, _ := hex.DecodeString("000102030405060708090A0B0C0E0F101112131415161718191A1B1C1E1F2021")
	plaintext := []byte("text")

	nonce := make([]byte, 12)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		fmt.Println(err)
		return
	}
	// var nonce = []byte{
	// 	0x11, 0x12, 0x13, 0x14, 0x15, 0x16,
	// 	0x21, 0x22, 0x23, 0x24, 0x25, 0x26,
	// }
	{
		c := genCounter(nonce)
		c = incrementCounter(c)
		b, err := encWitchCounter(plaintext, key, nonce, c)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("%x\n", b)
	}

	additionalData := []byte{}
	{
		fmt.Printf("====start standard encryption====\n")
		b, err := seal(plaintext, key, nonce, additionalData)
		if err != nil {
			fmt.Println(err)
			return
		}
		fmt.Printf("result\t%x\n", b)
	}
	{
		ss, _ := aes.NewCipher(key)
		aa, _ := cipher.NewGCM(ss)
		fmt.Printf("====start go encryption====\n")
		b := aa.Seal(nil, nonce, plaintext, additionalData)
		fmt.Printf("result\t%x\n", b)

		c := genCounter(nonce)
		c = incrementCounter(c)
		s := cipher.NewCTR(ss, c[:])

		dst := make([]byte, len(plaintext))
		s.XORKeyStream(dst, plaintext)
		fmt.Printf("test\t%x\n", dst)
	}

}
