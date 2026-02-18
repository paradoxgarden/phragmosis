package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"log"
	"net/http"

	"github.com/gorilla/securecookie"
	"golang.org/x/oauth2"
)

type oauthMeta struct {
	CRSFState string
	PKCECode  string
	Redirect  string
}

type token struct {
	Access  string
	Refresh string
	Subject *string
	Iat     string
}

// check token expiration, refresh if close to time
func (*token) Valid() bool {
	// TODO check token expiry
	return true
}

type validationError string

func (e validationError) Error() string {
	return string(e)
}
// make discord token exchange and ensure token recieved is good
func getDiscordToken(ctx context.Context, discord oauth2.Config, code string, PKCE string) (*oauth2.Token, error) {
	token, err := discord.Exchange(ctx, code, oauth2.VerifierOption(PKCE))
	if err != nil {
		return nil, err
	}
	if !token.Valid() {
		return nil, validationError("error validating token")
	}
	return token, nil
}
// read the user's oauth metadata from browser cookies
func getUserMeta(r *http.Request, sc securecookie.SecureCookie) (*oauthMeta, error) {
	cookie, err := r.Cookie("oauthMeta")
	if err != nil {
		return nil, err
	}

	ometa := &oauthMeta{}
	err = sc.Decode("oauthMeta", cookie.Value, ometa)
	if err != nil {
		return nil, err
	}
	//state := r.FormValue("state")
	//if ometa.CRSFState != state {
	//	return nil, &CRSFError{
	//		orig: ometa.CRSFState,
	//		new:  state,
	//	}
	//}
	return ometa, nil

}

type CRSFError struct {
	orig string
	new  string
}

func (e *CRSFError) Error() string {
	return fmt.Sprintf("CSRF validation error: %s vs %s", e.orig, e.new)
}
// initialize securecookie with config provided (or generate) keys
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
// return an array of bytes size n
func getRandBytes(n int) ([]byte, error) {
	dat := make([]byte, n)
	_, err := rand.Read(dat)
	if err != nil {
		return nil, err
	}
	return dat, nil
}
// generate the oauthmetadata struct 
func genOAuthMeta(redirect string) (*oauthMeta, error) {
	stateRand, err := getRandBytes(16)
	if err != nil {
		return nil, err
	}
	crsfState := base64.URLEncoding.EncodeToString(stateRand)
	return &oauthMeta{
		CRSFState: crsfState,
		PKCECode:  oauth2.GenerateVerifier(),
		Redirect:  redirect,
	}, nil
}
