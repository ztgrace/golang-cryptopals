package cryptopals

import (
	"fmt"
	"strings"
	"encoding/hex"
	"crypto/aes"
)

func pkcs7Padding(bytes []byte, length int) []byte {
	diff := length - len(bytes)
	out := make([]byte, length)
	out = bytes
	str, err := hex.DecodeString(fmt.Sprintf("%02x", diff))
	if err != nil {
		panic("Failed to decode")
	}
	out = append(out, strings.Repeat(string(str), diff)...)
	return out
}

//https://en.wikipedia.org/wiki/Block_cipher_mode_of_operation#Cipher_Block_Chaining_(CBC)
func encryptCBC(key []byte, iv []byte, bytes []byte) []byte {
	cipher, e := aes.NewCipher(key)
	if e != nil {
		panic(e)
	}
	if len(bytes) % cipher.BlockSize() !=0 {
		panic("Ciphertext length isn't a multiple of the block size.")
	}
	ct := make([]byte, len(bytes))
	block := make([]byte, cipher.BlockSize())
	// iterate over block-size bytes
	var xored []byte
	for i := 0; i < len(bytes); i += cipher.BlockSize() {
		if i == 0 {
			xored = xor(bytes[i*cipher.BlockSize():(i+1)*cipher.BlockSize()], iv)
		} else {
			xored = xor(bytes[i*cipher.BlockSize():(i+1)*cipher.BlockSize()], block)
		}
		cipher.Encrypt(block, xored)
		ct = append(ct, block...)
	}

	return ct
}

func decryptCBC(key []byte, iv []byte, ct []byte) []byte {
	cipher, e := aes.NewCipher(key)
	if e != nil {
		panic(e)
	}
	if len(ct) % cipher.BlockSize() !=0 {
		panic("Ciphertext length isn't a multiple of the block size.")
	}
	plain := make([]byte, len(ct))
	block := make([]byte, cipher.BlockSize())
	// iterate over block-size bytes
	var xored []byte
	for i := 0; i < len(ct); i += cipher.BlockSize() {
		cipher.Decrypt(block, ct[i:(i+1)*cipher.BlockSize()])
		if i == 0 {
			xored = xor(ct[i*cipher.BlockSize():(i+1)*cipher.BlockSize()], iv)
		} else {
			xored = xor(ct[i*cipher.BlockSize():(i+1)*cipher.BlockSize()], block)
		}
		plain = append(plain, xored...)
	}

	return plain
}
