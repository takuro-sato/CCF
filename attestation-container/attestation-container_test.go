package main

import (
	"context"
	"encoding/hex"
	"flag"
	"log"
	"testing"
	"time"

	pb "microsoft/attestation-container/protobuf"

	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials/insecure"
)

var (
	addr = flag.String("addr", "localhost:50051", "the address to connect to")
)

func TestFetchReport(t *testing.T) {
	flag.Parse()
	// Set up a connection to the server.
	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewAttestationContainerClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	// public key bytes in UTF-8 (https://go.dev/blog/strings)
	publicKey := []byte("public-key-contents")
	r, err := c.FetchAttestation(ctx, &pb.FetchAttestationRequest{ReportData: publicKey})
	if err != nil {
		log.Fatalf("could not get attestation: %v", err)
	}
	log.Printf("Attestation: %v", hex.EncodeToString(r.GetAttestation()))
	log.Printf("Collateral: %v", hex.EncodeToString(r.GetCollateral()))
}

func TestInputError(t *testing.T) {
	flag.Parse()
	// Set up a connection to the server.
	conn, err := grpc.Dial(*addr, grpc.WithTransportCredentials(insecure.NewCredentials()))
	if err != nil {
		log.Fatalf("did not connect: %v", err)
	}
	defer conn.Close()
	c := pb.NewAttestationContainerClient(conn)

	// Contact the server and print out its response.
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	publicKey := []byte("too long (longer than 64 bytes in utf-8) ------------------------")
	if _, err := c.FetchAttestation(ctx, &pb.FetchAttestationRequest{ReportData: publicKey}); err == nil {
		log.Fatalf("server should return input error for too large input")
	}
}
