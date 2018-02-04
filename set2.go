package cryptopals

import (
	"fmt"
	"strings"
	"encoding/hex"
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
