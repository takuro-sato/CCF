package main

import (
	"context"
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

	// chipCertificate := certChain[0]
	// sevVersionCertificate := certChain[1]
	// rootCertificate := certChain[2]

	// First, create the set of root certificates. For this example we only
	// have one. It's also possible to omit this in order to use the
	// default root set of the current operating system.
	roots := x509.NewCertPool()
	ok := roots.AppendCertsFromPEM(endorsementCertificates)
	if !ok {
		log.Fatalf("failed to parse root certificate 0")
	}

	block, _ := pem.Decode(endorsementCertificates)
	if block == nil {
		log.Fatalf("failed to parse certificate PEM 1")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		log.Fatalf("failed to parse certificate: " + err.Error())
	}

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := cert.Verify(opts); err != nil {
		log.Fatalf("failed to verify certificate: " + err.Error())
	}

	if len(r.GetUvmEndorsements()) == 0 {
		log.Fatalf("UVM endorsement is empty")
	}
	// log.Printf("UVM endorsement: %s", r.GetUvmEndorsements())
}
