package main

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"flag"
	"fmt"
	"log"
	"math/big"
	"net"
	"time"

	"microsoft/attestation-container/client-example/cosesign1"
	didx509resolver "microsoft/attestation-container/client-example/did-x509-resolver"
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

// Attestation report is based on SEV-SNP ABI Spec
// https://www.amd.com/system/files/TechDocs/56860.pdf

const (
	// Table 21
	ATTESTATION_REPORT_SIZE = 1184
	SIGNATURE_SIZE          = 512
)

const (
	// Encoding for Signing Algorithms
	// Table 113
	SIGNATURE_ALGO_ECDSA_P384_SHA384 = 1
)

type ECDSASignatureP384SHA384 struct {
	R *big.Int
	S *big.Int
}

// Attestation report
// Table 21
type SNPAttestationReport struct {
	// version no. of this attestation report. Set to 1 for this specification.
	Version uint32 `json:"version"`
	// The guest SVN
	GuestSvn uint32 `json:"guest_svn"`
	// see table 8 - various settings
	Policy uint64 `json:"policy"`
	// as provided at launch    hex string of a 16-byte integer
	FamilyID string `json:"family_id"`
	// as provided at launch 	hex string of a 16-byte integer
	ImageID string `json:"image_id"`
	// the request VMPL for the attestation report
	VMPL          uint32 `json:"vmpl"`
	SignatureAlgo uint32 `json:"signature_algo"`
	// The install version of the firmware
	PlatformVersion uint64 `json:"platform_version"`
	// information about the platform see table 22
	PlatformInfo uint64 `json:"platform_info"`
	// 31 bits of reserved, must be zero, bottom bit indicates that the digest of the author key is present in AUTHOR_KEY_DIGEST. Set to the value of GCTX.AuthorKeyEn.
	AuthorKeyEn uint32 `json:"author_key_en"`
	// must be zero
	Reserved1 uint32 `json:"reserved1"`
	// Guest provided data.	64-byte
	ReportData string `json:"report_data"`
	// measurement calculated at launch 48-byte
	Measurement string `json:"measurement"`
	// data provided by the hypervisor at launch 32-byte
	HostData string `json:"host_data"`
	// SHA-384 digest of the ID public key that signed the ID block provided in SNP_LAUNCH_FINISH 48-byte
	IDKeyDigest string `json:"id_key_digest"`
	// SHA-384 digest of the Author public key that certified the ID key, if provided in SNP_LAUNCH_FINISH. Zeros if author_key_en is 1 (sounds backwards to me). 48-byte
	AuthorKeyDigest string `json:"author_key_digest"`
	// Report ID of this guest. 32-byte
	ReportID string `json:"report_id"`
	// Report ID of this guest's mmigration agent. 32-byte
	ReportIDMA string `json:"report_id_ma"`
	// Reported TCB version used to derive the VCEK that signed this report
	ReportedTCB uint64 `json:"reported_tcb"`
	// reserved 24-byte
	Reserved2 string `json:"reserved2"`
	// Identifier unique to the chip 64-byte
	ChipID string `json:"chip_id"`
	// The current commited SVN of the firware (version 2 report feature)
	CommittedSvn uint64 `json:"committed_svn"`
	// The current commited version of the firware
	CommittedVersion uint64 `json:"committed_version"`
	// The SVN that this guest was launched or migrated at
	LaunchSvn uint64 `json:"launch_svn"`
	// reserved 168-byte
	Reserved3 string `json:"reserved3"`
	// Signature of this attestation report. See table 23. 512-byte
	Signature string `json:"signature"`
}

// Deserialize SEV-SNP attestation report
// Copied from https://github.com/microsoft/confidential-sidecar-containers/blob/d933d0f/pkg/attest/snp.go
func (r *SNPAttestationReport) DeserializeReport(report []uint8) error {

	if len(report) != ATTESTATION_REPORT_SIZE {
		return fmt.Errorf("invalid snp report size")
	}

	r.Version = binary.LittleEndian.Uint32(report[0:4])
	r.GuestSvn = binary.LittleEndian.Uint32(report[4:8])
	r.Policy = binary.LittleEndian.Uint64(report[8:16])
	r.FamilyID = hex.EncodeToString(report[16:32])
	r.ImageID = hex.EncodeToString(report[32:48])
	r.VMPL = binary.LittleEndian.Uint32(report[48:52])
	r.SignatureAlgo = binary.LittleEndian.Uint32(report[52:56])
	r.PlatformVersion = binary.LittleEndian.Uint64(report[56:64])
	r.PlatformInfo = binary.LittleEndian.Uint64(report[64:72])
	r.AuthorKeyEn = binary.LittleEndian.Uint32(report[72:76])
	r.Reserved1 = binary.LittleEndian.Uint32(report[76:80])
	r.ReportData = hex.EncodeToString(report[80:144])
	r.Measurement = hex.EncodeToString(report[144:192])
	r.HostData = hex.EncodeToString(report[192:224])
	r.IDKeyDigest = hex.EncodeToString(report[224:272])
	r.AuthorKeyDigest = hex.EncodeToString(report[272:320])
	r.ReportID = hex.EncodeToString(report[320:352])
	r.ReportIDMA = hex.EncodeToString(report[352:384])
	r.ReportedTCB = binary.LittleEndian.Uint64(report[384:392])
	r.Reserved2 = hex.EncodeToString(report[392:416])
	r.ChipID = hex.EncodeToString(report[416:480])
	r.CommittedSvn = binary.LittleEndian.Uint64(report[480:488])
	r.CommittedVersion = binary.LittleEndian.Uint64(report[488:496])
	r.LaunchSvn = binary.LittleEndian.Uint64(report[496:504])
	r.Reserved3 = hex.EncodeToString(report[504:672])
	r.Signature = hex.EncodeToString(report[672:1184])

	return nil
}

func reverseBytes(bytes []byte) []byte {
	// Deep copy to avoid side effects on the parameter
	out := append(make([]byte, 0, len(bytes)), bytes...)
	for i := 0; i < len(out)/2; i++ {
		j := len(out) - i - 1
		out[i], out[j] = out[j], out[i]
	}
	return out
}

// Deserialize ECDSA signature with P384 and SHA384
func deserializeSignature(hexSignature string) (ECDSASignatureP384SHA384, error) {
	sigBytes, err := hex.DecodeString(hexSignature)
	if err != nil {
		log.Fatalf("Failed to decode signature: %s", err.Error())
	}
	if len(sigBytes) != SIGNATURE_SIZE {
		log.Fatalf("Signature length should be %d bytes, but it's %d", SIGNATURE_SIZE, len(sigBytes))
	}
	rbytesLittleEndian := sigBytes[0:72]
	sbytesLittleEndian := sigBytes[72 : 72+72]
	// Big endian is requred by `SetBytes()`.
	rbytesBigEndian := reverseBytes(rbytesLittleEndian)
	sbytesBigEndian := reverseBytes(sbytesLittleEndian)
	return ECDSASignatureP384SHA384{
		R: new(big.Int).SetBytes(rbytesBigEndian),
		S: new(big.Int).SetBytes(sbytesBigEndian),
	}, nil
}

// DID stuf
// From https://www.w3.org/TR/did-core
type DIDDocumentVerificationMethod struct {
	Id                  string              `json:"id"`
	Type                string              `json:"type"`
	Controller          string              `json:"controller"`
	JSonWebKeyRSAPublic *JSONWebKeyRSAPublic `json:"publicKeyJwk"`
}

type JSONWebKeyRSAPublic struct {
	E string `json:"e"` // base64url
	N string `json:"N"` // base64url
}

type DIDDocument struct {
	Id                 string                          `json:"id"`
	Context            string                          `json:"@context"`
	Type               string                          `json:"type"`
	VerificationMethod []DIDDocumentVerificationMethod `json:"verificationMethod"`
	AssertionMethod    string                          `json:"assertionMethod"`
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

	// From https://developer.amd.com/sev/
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

	deserializedReport := new(SNPAttestationReport)
	if err := deserializedReport.DeserializeReport(attestation); err != nil {
		log.Fatalf("Failed to deserialize attestation report: %s", err.Error())
	}

	if deserializedReport.SignatureAlgo != SIGNATURE_ALGO_ECDSA_P384_SHA384 {
		log.Fatalf("Unsupported signature algorithm")
	}

	sig, err := deserializeSignature(deserializedReport.Signature)
	if err != nil {
		log.Fatalf("Failed to deserialize signature: %s", err.Error())
	}

	signedContents := attestation[:ATTESTATION_REPORT_SIZE-SIGNATURE_SIZE]
	h := crypto.SHA384.New()
	h.Write(signedContents)
	hashedContents := h.Sum(nil)

	valid := ecdsa.Verify(chipCertificate.PublicKey.(*ecdsa.PublicKey), hashedContents, sig.R, sig.S)
	if valid {
		log.Println("Attestation report's signature is valid")
	} else {
		log.Fatalf("Attestation report's signature is not valid")
	}
	uvmEndorsements := r.GetUvmEndorsements()
	if len(uvmEndorsements) == 0 {
		log.Fatalf("UVM endorsement is empty")
	}

	unpacked, err := cosesign1.UnpackAndValidateCOSE1CertChain(uvmEndorsements)
	if err != nil {
		log.Fatalf("InjectFragment failed COSE validation: %s", err.Error())
	}
	// log.Printf("UVM endorsement: %s", r.GetUvmEndorsements())

	payloadString := string(unpacked.Payload[:])
	issuer := unpacked.Issuer
	feed := unpacked.Feed
	chainPem := unpacked.ChainPem

	log.Printf("unpacked COSE1 cert chain: issuer: %s, feed: %s, cty: %s, chainPem: %s", issuer, feed, unpacked.ContentType, chainPem)

	log.Printf("unpacked COSE1 payload: payload: %s", payloadString)

	if len(issuer) == 0 || len(feed) == 0 { // must both be present
		log.Fatalf("either issuer and feed must both be provided in the COSE_Sign1 protected header")
	}

	// Resolve returns a did doc that we don't need
	// we only care if there was an error or not
	didDocumentStr, err := didx509resolver.Resolve(unpacked.ChainPem, issuer, true)
	if err != nil {
		// log.G(ctx).Printf("Badly formed fragment - did resolver failed to match fragment did:x509 from chain with purported issuer %s, feed %s - err %s", issuer, feed, err.Error())
		log.Fatalf("Badly formed fragment - did resolver failed to match fragment did:x509 from chain with purported issuer %s, feed %s - err %s", issuer, feed, err.Error())
	}

	log.Printf("didDocumentStr: %s", didDocumentStr)
	didDocument := new(DIDDocument)
	err = json.Unmarshal([]byte(didDocumentStr), &didDocument)
	if err != nil {
		log.Fatalf("Badly formed did document: %s", err.Error())
	}
	fmt.Printf("Unmarshalled did doc: %#v\n", didDocument)

	if len(didDocument.VerificationMethod) == 0 {
		log.Fatalf("Could not find verification method for DID document: %s", didDocumentStr)
	}

	var pubKey *JSONWebKeyRSAPublic
	for _, vm := range didDocument.VerificationMethod {
		if vm.Controller == issuer && vm.JSonWebKeyRSAPublic != nil {
			pubKey = vm.JSonWebKeyRSAPublic
			log.Printf("Found public key: %#v\n", *vm.JSonWebKeyRSAPublic)
			break
		}
	}

	if pubKey == nil {
		log.Fatalf("Could not find matching public key for DID %s for %s", issuer, didDocumentStr)
	}

}
