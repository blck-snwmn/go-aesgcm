package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"io"

	goaesgcm "github.com/blck-snwmn/go-aesgcm"
)

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
	additionalData := []byte{}
	{
		fmt.Printf("====start standard encryption====\n")
		b, err := goaesgcm.Seal(plaintext, key, nonce, additionalData)
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
	}
}
