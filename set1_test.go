package cryptopals

import (
    "log"
    "testing"
)

// http://cryptopals.com/sets/1/challenges/1
func TestChal1(t *testing.T) {
    var enc string = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
    var answer string = "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"

    res, err := hex2base64(enc)
    if err != nil {
        t.Fatal(err)
    }
    if res != answer {
        t.Error("Failed", res)
    }
}

// http://cryptopals.com/sets/1/challenges/2
func TestChal2(t *testing.T) {
    var input string = "1c0111001f010100061a024b53535009181c"
    var key string = "686974207468652062756c6c277320657965"
    var answer string = "746865206b696420646f6e277420706c6179"

    raw_i, _ := hex_decode(input)
    raw_k, _ := hex_decode(key)

    res := xor(raw_i, raw_k)
    res_hex := hex_encode(res)
    log.Printf("%s", res_hex)

    if res_hex != answer {
        t.Error("",)
    }
}

// http://cryptopals.com/sets/1/challenges/3
func TestChal3(t *testing.T) {
    var input string = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736"
    raw_i, _ := hex_decode(input)

    key, res, topScore := findSingleXorKey(raw_i)
    log.Printf("chal3 - key:%v, score: %f, res: %s", int(key), topScore, res)

}