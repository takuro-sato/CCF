package attest

import (
	"encoding/hex"
	"testing"
)

func assertEqual[T comparable](t *testing.T, description string, expect T, actual T) {
	if expect != actual {
		t.Fatalf("%s: Expected %v, but got %v", description, expect, actual)
	}
}

func TestFetchAndDeserializeReport(t *testing.T) {
	reportData := [64]byte{0, 1, 2, 3, 4, 5}

	reportBytes, err := FetchAttestationReportByte(reportData[:])
	if err != nil {
		t.Fatalf("Fetching report failed: %v", err)
	}
	var SNPReport SNPAttestationReport
	if err := SNPReport.DeserializeReport(reportBytes); err != nil {
		t.Fatalf("Failed to deserialize attestation report: %v", err)
	}
	// fmt.Printf("%v\n", hex.EncodeToString(reportBytes))
	expectedByteString := hex.EncodeToString(reportData[:])
	assertEqual(t, "Check report data", expectedByteString, SNPReport.ReportData)
}
