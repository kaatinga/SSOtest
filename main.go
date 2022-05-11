package main

import (
	"context"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"time"

	"github.com/crewjam/saml/samlsp"
)

func hello(w http.ResponseWriter, r *http.Request) {
	log.Println("hello endpoint hit", r.RemoteAddr, time.Now())
	fmt.Fprintf(w, "Hello, %s!", samlsp.AttributeFromContext(r.Context(), "cn"))
}

func processError(_ http.ResponseWriter, _ *http.Request, err error) {
	log.Println("middleware error", err)
}

func main() {
	keyPair, err := tls.LoadX509KeyPair("myservice.cert", "myservice.key")
	if err != nil {
		log.Fatalln("unable to load certificate", err)
	}
	keyPair.Leaf, err = x509.ParseCertificate(keyPair.Certificate[0])
	if err != nil {
		log.Fatalln("unable to parse certificate", err)
	}

	idpMetadataURL, err := url.Parse("https://samltest.id/saml/idp")
	if err != nil {
		log.Fatalln("unable to parse idp metadata url", err)
	}
	idpMetadata, err := samlsp.FetchMetadata(context.Background(), http.DefaultClient,
		*idpMetadataURL)
	if err != nil {
		log.Fatalln("unable to load idp metadata", err)
	}

	rootURL, err := url.Parse("http://localhost:8000")
	if err != nil {
		log.Fatalln("unable to parse sp url", err)
	}

	log.Println("all the data is prepared to run service")

	var samlSP *samlsp.Middleware
	samlSP, err = samlsp.New(samlsp.Options{
		URL:         *rootURL,
		Key:         keyPair.PrivateKey.(*rsa.PrivateKey),
		Certificate: keyPair.Leaf,
		IDPMetadata: idpMetadata,
	})
	if err != nil {
		log.Fatalln("unable to create samlsp middleware", err)
	}

	samlSP.OnError = processError

	app := http.HandlerFunc(hello)
	http.Handle("/hello", samlSP.RequireAccount(app))
	http.Handle("/saml/", samlSP)

	log.Println("service launched on the port", rootURL.Port())
	err = http.ListenAndServe(":"+rootURL.Port(), nil)
	if err != nil {
		log.Println("http service finished", err)
	}
	log.Println("sso test service finished")
}
