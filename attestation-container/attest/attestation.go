package attest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	SNP_REPORT_SIZE                 = 1184
	SEV_SNP_GUEST_MSG_REPORT uint64 = 3223868161
	REPORT_DATA_SIZE                = 64
	REPORT_REQ_SIZE                 = 96
	RESPONSE_RESP_SIZE              = 1280
	PAYLOAD_SIZE                    = 40
)

const (
	SNP_MSG_TYPE_INVALID = 0
	SNP_MSG_CPUID_REQ    = 1
	SNP_MSG_CPUID_RSP    = 2
	SNP_MSG_KEY_REQ      = 3
	SNP_MSG_KEY_RSP      = 4
	SNP_MSG_REPORT_REQ   = 5
	SNP_MSG_REPORT_RSP   = 6
	SNP_MSG_EXPORT_REQ   = 7
	SNP_MSG_EXPORT_RSP   = 8
	SNP_MSG_IMPORT_REQ   = 9
	SNP_MSG_IMPORT_RSP   = 10
	SNP_MSG_ABSORB_REQ   = 11
	SNP_MSG_ABSORB_RSP   = 12
	SNP_MSG_VMRK_REQ     = 13
	SNP_MSG_VMRK_RSP     = 14
	SNP_MSG_TYPE_MAX     = 15
)

func createReportReqBytes(reportData [REPORT_DATA_SIZE]byte) [REPORT_REQ_SIZE]byte {
	reportReqBytes := [REPORT_REQ_SIZE]byte{}
	for i := 0; i < REPORT_DATA_SIZE; i++ {
		reportReqBytes[i] = reportData[i]
	}
	return reportReqBytes
}

func createPayloadBytes(reportReqPtr uintptr, responseRespPtr uintptr) ([PAYLOAD_SIZE]byte, error) {
	payload := [PAYLOAD_SIZE]byte{}
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.LittleEndian, uint8(SNP_MSG_REPORT_REQ)); err != nil {
		return payload, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, uint8(SNP_MSG_REPORT_RSP)); err != nil {
		return payload, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, uint8(1)); err != nil {
		return payload, err
	}
	// Padding
	if err := binary.Write(&buf, binary.LittleEndian, uint8(0)); err != nil {
		return payload, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, uint16(REPORT_REQ_SIZE)); err != nil {
		return payload, err
	}
	// Padding
	if err := binary.Write(&buf, binary.LittleEndian, uint16(0)); err != nil {
		return payload, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, uint64(reportReqPtr)); err != nil {
		return payload, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, uint16(RESPONSE_RESP_SIZE)); err != nil {
		return payload, err
	}
	// Padding
	if err := binary.Write(&buf, binary.LittleEndian, uint16(0)); err != nil {
		return payload, err
	}
	// Padding
	if err := binary.Write(&buf, binary.LittleEndian, uint32(0)); err != nil {
		return payload, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, uint64(responseRespPtr)); err != nil {
		return payload, err
	}
	if err := binary.Write(&buf, binary.LittleEndian, uint32(0)); err != nil {
		return payload, err
	}
	// Padding
	if err := binary.Write(&buf, binary.LittleEndian, uint32(0)); err != nil {
		return payload, err
	}
	for i, x := range buf.Bytes() {
		payload[i] = x
	}
	return payload, nil
}

func FetchAttestationReportByte(reportData [64]byte) ([]byte, error) {
	path := "/dev/sev"
	fd, err := unix.Open(path, unix.O_RDWR|unix.O_CLOEXEC, 0)
	if err != nil {
		fmt.Println("Can't open /dev/sev")
		return nil, err
	}

	reportReqBytes := createReportReqBytes(reportData)
	responseRespBytes := [RESPONSE_RESP_SIZE]byte{}
	payload, err := createPayloadBytes(uintptr(unsafe.Pointer(&reportReqBytes[0])), uintptr(unsafe.Pointer(&responseRespBytes[0])))
	if err != nil {
		return nil, err
	}

	_, _, errno := unix.Syscall(
		unix.SYS_IOCTL,
		uintptr(fd),
		uintptr(SEV_SNP_GUEST_MSG_REPORT),
		uintptr(unsafe.Pointer(&payload[0])),
	)

	if errno != 0 {
		fmt.Printf("ioctl failed:%v\n", errno)
		return nil, fmt.Errorf("ioctl failed:%v", errno)
	}

	if status := binary.LittleEndian.Uint32(responseRespBytes[0:4]); status != 0 {
		fmt.Printf("fetching attestation report failed. status: %v\n", status)
		return nil, fmt.Errorf("fetching attestation report failed. status: %v", status)
	}

	return responseRespBytes[32 : 32+SNP_REPORT_SIZE], nil
}
