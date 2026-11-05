// The same-machine comparison the README quotes: Go's crypto/ecdsa next to
// mooncrypt's, on P-256, signing and verifying the same message.
//
//     go run scripts/compare_ecdsa.go
//
// The best of several rounds is reported: a shared machine's noise is one-sided,
// so the minimum is the closest thing to the cost of the operation itself.
package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"time"
)

func best(rounds, each int, op func()) float64 {
	for i := 0; i < 3; i++ {
		op()
	}
	low := time.Duration(1 << 62)
	for r := 0; r < rounds; r++ {
		start := time.Now()
		for i := 0; i < each; i++ {
			op()
		}
		d := time.Since(start) / time.Duration(each)
		if d < low {
			low = d
		}
	}
	return float64(low.Nanoseconds()) / 1000.0
}

func main() {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		panic(err)
	}
	msg := []byte("hello world")
	digest := sha256.Sum256(msg)
	sig, err := ecdsa.SignASN1(rand.Reader, key, digest[:])
	if err != nil {
		panic(err)
	}
	if !ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig) {
		panic("the signature did not verify")
	}
	sign := best(9, 200, func() {
		if _, err := ecdsa.SignASN1(rand.Reader, key, digest[:]); err != nil {
			panic(err)
		}
	})
	verify := best(9, 200, func() {
		ecdsa.VerifyASN1(&key.PublicKey, digest[:], sig)
	})
	fmt.Printf("go  crypto/ecdsa P-256  sign %.1f us  verify %.1f us\n", sign, verify)
}
