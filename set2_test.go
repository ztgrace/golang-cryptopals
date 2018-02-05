package cryptopals

import (
	//"bytes"
	"log"
	"testing"
	"strings"
)

func TestChal9(t *testing.T) {
	data := []byte("YELLOW SUBMARINE")
	length := 20
	padded := pkcs7Padding(data, length)
	tpadded := "YELLOW SUBMARINE\x04\x04\x04\x04"
	if string(padded) != tpadded {
		log.Printf("chal9 fail: %s", padded)
		t.Fatal("padded doesn't match expected")
	}


	log.Printf("chal9: %s", padded)
}

func TestChal10(t *testing.T) {
	//pt := []byte("1234567890abcdef")
	key := []byte("YELLOW SUBMARINE")
	/*
	iv := make([]byte, 16)
	res := decryptCBC(key, iv , encryptCBC(key, iv, pt))
	if !bytes.Equal(res, pt) {
		t.Fatal("CBC encrypt/decrypt doesn't match")
	}
	*/

	f := readFile(t, "data/set2/10.txt")
	res := decryptCBC(key, []byte(strings.Repeat("\x00", 16)), base64Decode(t, string(f)))
	log.Printf("chal10: %s\n", res)
}
