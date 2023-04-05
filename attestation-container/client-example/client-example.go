package main

import (
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"flag"
	"log"
	"net"
	"time"

	pb "microsoft/attestation-container/protobuf"

	"google.golang.org/grpc"
)

var (
	addr = flag.String("addr", "/tmp/attestation-container.sock", "the Unix domain socket address to connect to")
)

const TIMEOUT_IN_SEC = 10

func splitPemChain(pemChain []byte) [][]byte {
	var chain [][]byte
	var certDERBlock *pem.Block
	for {
		certDERBlock, pemChain = pem.Decode(pemChain)
		if certDERBlock == nil {
			break
		}
		if certDERBlock.Type == "CERTIFICATE" {
			chain = append(chain, certDERBlock.Bytes)
		}
	}
	return chain
}

func main() {
	flag.Parse()
	// Set up a connection to the server.
	dialer := func(addr string, t time.Duration) (net.Conn, error) {
		return net.Dial("unix", addr)
	}
	conn, err := grpc.Dial(*addr, grpc.WithInsecure(), grpc.WithDialer(dialer))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewAttestationContainerClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), TIMEOUT_IN_SEC*time.Second)
	defer cancel()
	// public key bytes in UTF-8 (https://go.dev/blog/strings)
	publicKey := []byte("public-key-contents")
	r, err := c.FetchAttestation(ctx, &pb.FetchAttestationRequest{ReportData: publicKey})
	if err != nil {
		log.Fatalf("could not get attestation: %v", err)
	}
	// Verify attestation
	attestation := r.GetAttestation()
	if len(attestation) == 0 {
		log.Fatalf("attestation is empty")
	}
	// log.Printf("Attestation: %v", hex.EncodeToString(attestation))

	// Verify endorsements
	endorsementCertificates := r.GetAttestationEndorsements()
	if len(endorsementCertificates) == 0 {
		log.Fatalf("endorsementCertificates is empty")
	}
	certChain := splitPemChain(endorsementCertificates)
	chainLen := len(certChain)
	if chainLen != 3 {
		// Expecting VCEK, ASK and ARK
		log.Fatalf("endorsementCertificates does not contain 3 certificates, found %d", chainLen)
	}
	// log.Printf("Attestation endorsement certificates: %v", hex.EncodeToString(endorsementCertificates))
	log.Printf("Attestation endorsement certificates: %v", string(endorsementCertificates))

	chipCertificate, err := x509.ParseCertificate(certChain[0])
	if chipCertificate == nil {
		log.Fatalf("failed to parse certificate rootCertificate PEM: " + err.Error())
	}
	sevVersionCertificate, err := x509.ParseCertificate(certChain[1])
	if sevVersionCertificate == nil {
		log.Fatalf("failed to parse certificate rootCertificate PEM: " + err.Error())
	}
	rootCertificate, err := x509.ParseCertificate(certChain[2])
	if rootCertificate == nil {
		log.Fatalf("failed to parse certificate rootCertificate PEM: " + err.Error())
	}

	knownRootOfTrustPublicKey := []byte(`-----BEGIN PUBLIC KEY-----
MIICIjANBgkqhkiG9w0BAQEFAAOCAg8AMIICCgKCAgEA0Ld52RJOdeiJlqK2JdsV
mD7FktuotWwX1fNgW41XY9Xz1HEhSUmhLz9Cu9DHRlvgJSNxbeYYsnJfvyjx1MfU
0V5tkKiU1EesNFta1kTA0szNisdYc9isqk7mXT5+KfGRbfc4V/9zRIcE8jlHN61S
1ju8X93+6dxDUrG2SzxqJ4BhqyYmUDruPXJSX4vUc01P7j98MpqOS95rORdGHeI5
2Naz5m2B+O+vjsC060d37jY9LFeuOP4Meri8qgfi2S5kKqg/aF6aPtuAZQVR7u3K
FYXP59XmJgtcog05gmI0T/OitLhuzVvpZcLph0odh/1IPXqx3+MnjD97A7fXpqGd
/y8KxX7jksTEzAOgbKAeam3lm+3yKIcTYMlsRMXPcjNbIvmsBykD//xSniusuHBk
gnlENEWx1UcbQQrs+gVDkuVPhsnzIRNgYvM48Y+7LGiJYnrmE8xcrexekBxrva2V
9TJQqnN3Q53kt5viQi3+gCfmkwC0F0tirIZbLkXPrPwzZ0M9eNxhIySb2npJfgnq
z55I0u33wh4r0ZNQeTGfw03MBUtyuzGesGkcw+loqMaq1qR4tjGbPYxCvpCq7+Og
pCCoMNit2uLo9M18fHz10lOMT8nWAUvRZFzteXCm+7PHdYPlmQwUw3LvenJ/ILXo
QPHfbkH0CyPfhl1jWhJFZasCAwEAAQ==
-----END PUBLIC KEY-----`)

	block, _ := pem.Decode(knownRootOfTrustPublicKey)
	if block == nil {
		log.Fatal("failed to decode PEM block containing public key")
	}

	knownPub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		log.Fatal(err)
	}

	if !rootCertificate.PublicKey.(*rsa.PublicKey).Equal(knownPub.(*rsa.PublicKey)) {
		log.Fatalf("SEV-SNP: The root of trust public key for this attestation was not the expected one, %x, %x", rootCertificate.PublicKey.(*rsa.PublicKey), knownPub.(*rsa.PublicKey))
	}
	// log.Println(string(rootCertificate.RawSubjectPublicKeyInfo))

	roots := x509.NewCertPool()
	roots.AddCert(rootCertificate)
	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := rootCertificate.Verify(opts); err != nil {
		log.Fatalf("SEV-SNP: The root of trust public key for this attestation was not self signed as expected" + err.Error())
	}

	// It's not in CCF. Check if it's necessary
	if _, err := sevVersionCertificate.Verify(opts); err != nil {
		log.Fatalf("SEV-SNP: The chain of signatures from the root of trust to this attestation is broken" + err.Error())
	}

	opts.Roots.AddCert(sevVersionCertificate)
	if _, err := chipCertificate.Verify(opts); err != nil {
		log.Fatalf("SEV-SNP: The chain of signatures from the root of trust to this attestation is broken" + err.Error())
	}

	if len(r.GetUvmEndorsements()) == 0 {
		log.Fatalf("UVM endorsement is empty")
	}
	// log.Printf("UVM endorsement: %s", r.GetUvmEndorsements())
}
