package main

import (
	"crypto/rand"
	"encoding/base64"
	"log"

	"github.com/gorilla/securecookie"
)

func initSecureCookie(blockKey *string, hashKey *string) (*securecookie.SecureCookie, error) {
	var sc *securecookie.SecureCookie
	if blockKey == nil || hashKey == nil {
		hash, err := getRandBytes(32)
		if err != nil {
			return sc, err
		}
		block, err := getRandBytes(32)
		if err != nil {
			return sc, err
		}
		sc = securecookie.New(hash, block)
	} else {
		hash, err := base64.StdEncoding.DecodeString(*hashKey)
		if err != nil {
			log.Fatal("provided hash key is not b64 encoded")
		}
		block, err := base64.StdEncoding.DecodeString(*blockKey)
		if err != nil {
			log.Fatal("provided block key is not b64 encoded")
		}
		sc = securecookie.New(hash, block)
	}
	sc.MaxAge(604800)
	return sc, nil
}
func getRandBytes(n int) ([]byte, error) {
	dat := make([]byte, n)
	_, err := rand.Read(dat)
	if err != nil {
		return nil, err
	}
	return dat, nil
}
