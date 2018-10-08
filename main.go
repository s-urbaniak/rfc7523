package main

import (
	"context"
	"encoding/json"
	"io/ioutil"
	"log"
	"net"
	"net/http"
	"os"
	"strings"
	"time"

	"net/http/httputil"

	"github.com/coreos/go-oidc"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/clientcredentials"
	kingpin "gopkg.in/alecthomas/kingpin.v2"
	jose "gopkg.in/square/go-jose.v2"
	"gopkg.in/square/go-jose.v2/jwt"
)

var (
	jwkPath = kingpin.Flag("jwk-path", "the private JWK used for signing client assertion JWTs").Required().ExistingFile()
)

func main() {
	kingpin.Parse()

	// generate with i.e. `jwk-keygen --use=sig --alg=RS512 --bits=4096 --kid-rand`
	privJWK := mustParseJWK(*jwkPath)
	pubJWKS := jose.JSONWebKeySet{[]jose.JSONWebKey{privJWK.Public()}}

	// the `/jwks` endpoint hosting the JWK public key content

	http.HandleFunc("/jwks", func(w http.ResponseWriter, r *http.Request) {
		{
			rd, _ := httputil.DumpRequest(r, true)
			log.Println("/jwks handler: request", string(rd))
		}
		_ = json.NewEncoder(w).Encode(pubJWKS)
	})

	go func() {
		http.ListenAndServe(":8888", nil)
	}()

	signer, err := jose.NewSigner(
		jose.SigningKey{
			Key:       privJWK,
			Algorithm: jose.RS512,
		},
		&jose.SignerOptions{
			// this will only embed the JWK's key ID "kid"
			// the public key content can be retrieved using the `/jwks` endpoint
			EmbedJWK: false,
		},
	)
	if err != nil {
		log.Fatal(err)
	}

	// oauth

	issuer := "http://localhost:8080/auth/realms/master"

	ctx := context.Background()
	provider, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		log.Fatal(err)
	}

	// no client ID and client secrets needed here,
	// as the client is asserted via a signed jwt.
	cfg := clientcredentials.Config{TokenURL: provider.Endpoint().TokenURL}

	transport := &http.Transport{
		Dial:                (&net.Dialer{Timeout: 10 * time.Second}).Dial,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     30 * time.Second,
	}

	client := &http.Client{
		Timeout: 20 * time.Second,
		Transport: &jwtClientAuthenticator{
			claims: Claims{
				// subject needs to match the client ID,
				// see https://github.com/keycloak/keycloak/blob/b478472b3578b8980d7b5f1642e91e75d1e78d16/services/src/main/java/org/keycloak/authentication/authenticators/client/JWTClientAuthenticator.java#L102-L105
				Subject: "telemeter",

				// audience needs to match realm issuer,
				// see https://github.com/keycloak/keycloak/blob/b478472b3578b8980d7b5f1642e91e75d1e78d16/services/src/main/java/org/keycloak/authentication/authenticators/client/JWTClientAuthenticator.java#L142-L144
				Audience: []string{issuer},
			},

			expiry: 10 * time.Second,
			signer: signer,
			next:   &debugRoundTripper{transport},

			now: time.Now,
		},
	}

	ctx = context.WithValue(ctx, oauth2.HTTPClient, client)

	src := cfg.TokenSource(ctx)
	for {
		t, err := src.Token()
		if err != nil {
			log.Fatal(err)
		}

		s := 10 * time.Second
		log.Println("got token (expires", t.Expiry, ") sleeping", s)
		time.Sleep(s)
	}
}

type debugRoundTripper struct {
	next http.RoundTripper
}

func (rt *debugRoundTripper) RoundTrip(req *http.Request) (res *http.Response, err error) {
	reqd, _ := httputil.DumpRequest(req, true)
	log.Println("request", string(reqd))

	res, err = rt.next.RoundTrip(req)
	if err != nil {
		log.Println(err)
		return
	}

	resd, _ := httputil.DumpResponse(res, true)
	log.Println("response", string(resd))

	return
}

type Claims struct {
	Issuer   string
	Subject  string
	Audience []string
	ID       string
}

type jwtClientAuthenticator struct {
	claims Claims
	signer jose.Signer
	expiry time.Duration
	next   http.RoundTripper

	now func() time.Time
}

func (rt *jwtClientAuthenticator) RoundTrip(req *http.Request) (*http.Response, error) {
	now := rt.now()

	clientAuthClaims := jwt.Claims{
		Issuer:    rt.claims.Issuer,
		Subject:   rt.claims.Subject,
		Audience:  rt.claims.Audience,
		ID:        rt.claims.ID,
		Expiry:    jwt.NewNumericDate(now.Add(rt.expiry)),
		IssuedAt:  jwt.NewNumericDate(now),
		NotBefore: jwt.NewNumericDate(now.Add(-10 * time.Second)),
	}

	clientAuthJWT, err := jwt.Signed(rt.signer).Claims(clientAuthClaims).CompactSerialize()
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Del("Authorization") // replaced with client assertion

	if err := req.ParseForm(); err != nil {
		return nil, err
	}

	req.Form.Set("client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer")
	req.Form.Set("client_assertion", clientAuthJWT)

	newBody := req.Form.Encode()
	req.Body = ioutil.NopCloser(strings.NewReader(newBody))
	req.ContentLength = int64(len(newBody))

	return rt.next.RoundTrip(req)
}

func mustMarshal(src json.Marshaler) []byte {
	bytes, err := src.MarshalJSON()
	if err != nil {
		panic(err)
	}
	return bytes
}

func mustParseJWK(path string) *jose.JSONWebKey {
	var jwk jose.JSONWebKey
	f, err := os.Open(path)
	if err != nil {
		log.Fatal(err)
	}
	defer f.Close()
	if err := json.NewDecoder(f).Decode(&jwk); err != nil {
		log.Fatal(err)
	}
	return &jwk
}
