package main

import (
	"crypto/rand"
	"encoding/base64"
	"log"

	"github.com/gorilla/securecookie"
)

func initSecureCookie(blockKey *string, hashKey *string) securecookie.SecureCookie {
	var sc securecookie.SecureCookie
	if blockKey == nil || hashKey == nil {
		hash, err := getRandBytes(32)
		if err != nil {
			log.Fatal("randomness as we know it has ceased")
		}
		block, err := getRandBytes(32)
		if err != nil {
			log.Fatal("randomness as we know it has ceased")
		}
		sc = *securecookie.New(hash, block)
	} else {
		hash, err := base64.StdEncoding.DecodeString(*hashKey)
		if err != nil {
			log.Fatal("provided hash key is not b64 encoded")
		}
		block, err := base64.StdEncoding.DecodeString(*blockKey)
		if err != nil {
			log.Fatal("provided block key is not b64 encoded")
		}
		sc = *securecookie.New(hash, block)
	}
	sc.MaxAge(604800)
	return sc
}
func getRandBytes(n int) ([]byte, error) {
	dat := make([]byte, n)
	_, err := rand.Read(dat)
	if err != nil {
		return nil, err
	}
	return dat, nil
}
