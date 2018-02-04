package cryptopals

import (
	b64 "encoding/base64"
	"crypto/aes"
	"encoding/hex"
	"log"
)


func hex_decode(s string) ([]byte, error) {
	raw, err := hex.DecodeString(s)
	return raw, err
}

func hex_encode(b []byte) (string) {
	s := hex.EncodeToString(b)
	return s
}

func hex2base64(s string) (string, error) {
	raw, err := hex_decode(s)
	if err != nil {
	    return "", err
	}
	return b64.StdEncoding.EncodeToString(raw), err
}

func xor(a []byte, b []byte) ([]byte) {
	res := make([]byte, len(a))

	for i := 0; i < len(a); i++ {
	    res[i] = a[i] ^ b[i]
	}


	return res
}

func singleXor(xorkey byte, bytes []byte) ([]byte) {
	res := make([]byte, len(bytes))

	for i := 0; i < len(bytes); i++ {
	    res[i] = xorkey ^ bytes[i]
	}

	return res
}

func scoreEnglish(b []byte)(float32) {
	// score based on printable ascii chars - 0x20-0x7e
	var count int = 0

	for i := 0; i < len(b); i++ {
	    //if b[i] >= 0x20 && b[i] <= 0x7e {
	    if b[i] >= 0x20 && b[i] <= 0x7a {
	        count++
	    }
	}

	score := float32(count) / float32(len(b))
	if score > 80.0 {
	    log.Printf("%s", string(b))
	}
	return score
}

func findSingleXorKey(b []byte)(key byte, res []byte, topScore float32) {
	topScore = 0

	for i := 0; i < 256; i++ {
	    x := singleXor(byte(i), b)
	    score := scoreEnglish(x)
	    if score > topScore {
	        key = byte(i)
	        topScore = score
	        res = x
	    }
	}

	return
}

//https://github.com/golang/go/issues/5597
func decryptECB(key []byte, bytes []byte) []byte {
	cipher, e := aes.NewCipher(key)
	if e != nil {
		panic(e)
	}
	if len(bytes) % cipher.BlockSize() !=0 {
		panic("Ciphertext length isn't a multiple of the block size.")
	}
	decrypted := make([]byte, len(bytes))
	// iterate over block-size bytes
	for i := 0; i < len(bytes); i += cipher.BlockSize() {
		cipher.Decrypt(decrypted[i:i+cipher.BlockSize()], bytes[i:i+cipher.BlockSize()])
	}

	return decrypted
}

func detectECB(size int, bytes []byte) bool {
	if len(bytes) % size != 0 {
		panic("Ciphertext length isn't a multiple of the block size.")
	}

	blocks := make(map[string]int)
	for i := 0; i < len(bytes); i += size {
		block := bytes[i:i+size]
		count := blocks[string(block)]
		if count > 0 {
			return true
		}
		count += 1
		blocks[string(block)] = count
	}

	return false
}
