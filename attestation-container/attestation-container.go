package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"log"
	"net"
	"os"

	"microsoft/attestation-container/attest"
	pb "microsoft/attestation-container/protobuf"

	"google.golang.org/grpc"
)

var (
	port = flag.Int("port", 50051, "The server port")
)

type server struct {
	pb.UnimplementedAttestationContainerServer
}

func (s *server) FetchAttestation(ctx context.Context, in *pb.FetchAttestationRequest) (*pb.FetchAttestationReply, error) {
	log.Printf("Received: %v", in.GetPublicKey())

	reportData := [64]byte{}
	for i, x := range []byte(in.GetPublicKey()) {
		reportData[i] = x
	}
	reportBytes, err := attest.FetchAttestationReportByte(reportData)
	if err != nil {
		fmt.Println("Failed to fetch attestation report:", err)
		return nil, fmt.Errorf("failed to fetch attestation report")
	}
	var SNPReport attest.SNPAttestationReport
	if err := SNPReport.DeserializeReport(reportBytes); err != nil {
		fmt.Println("Failed to deserialize attestation report")
		return nil, fmt.Errorf("failed to deserialize attestation report")
	}
	// IMPROVE: Use logging.Debug()
	// fmt.Printf("Deserialized attestation: %#v\n", SNPReport)
	return &pb.FetchAttestationReply{Attestation: "Attestation report: " + fmt.Sprintf("%#v\n", SNPReport)}, nil
}

func main() {
	fmt.Println("Attestation container started.")

	if _, err := os.Stat("/dev/sev"); err == nil {
		fmt.Println("/dev/sev is detected")
	} else if errors.Is(err, os.ErrNotExist) {
		fmt.Println("/dev/sev is not detected")
	} else {
		fmt.Println("Unknown error:", err)
	}

	flag.Parse()
	lis, err := net.Listen("tcp", fmt.Sprintf(":%d", *port))
	if err != nil {
		log.Fatalf("failed to listen: %v", err)
	}
	s := grpc.NewServer()
	pb.RegisterAttestationContainerServer(s, &server{})
	log.Printf("server listening at %v", lis.Addr())
	if err := s.Serve(lis); err != nil {
		log.Fatalf("failed to serve: %v", err)
	}
}
