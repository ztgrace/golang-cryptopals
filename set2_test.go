package cryptopals

import (
	"log"
	"testing"
)

func TestChal9(t *testing.T) {
	data := []byte("YELLOW SUBMARINE")
	length := 20
	padded := pkcs7Padding(data, length)
	tpadded := "YELLOW SUBMARINE\x04\x04\x04\x04"
	if string(padded) != tpadded {
		log.Printf("chal9 fail: %s", padded)
		log.Printf("chal9 failt: %s", tpadded)
		log.Printf("chal9 fail: %v", len(tpadded))
		t.Fatal("padded doesn't match expected")
	}


	log.Printf("chal9: %s", padded)

}
