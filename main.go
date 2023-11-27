// Copyright (c) 2014-2017 The btcsuite developers
// Use of this source code is governed by an ISC
// license that can be found in the LICENSE file.

package main

import (
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/btcsuite/btcd/chaincfg/chainhash"
	"log"
	"strings"

	"github.com/btcsuite/btcd/rpcclient"
)

var (
	pointer int
)

func readBytes(raw []byte, n int) []byte {
	value := raw[pointer : pointer+n]
	pointer += n
	return value
}

func getInitialPosition(raw []byte) (int, error) {
	inscriptionMark := []byte{0x00, 0x63, 0x03, 0x6f, 0x72, 0x64}
	pos := strings.Index(string(raw), string(inscriptionMark))
	if pos == -1 {
		return 0, errors.New("No ordinal inscription found in transaction")
	}
	return pos + len(inscriptionMark), nil
}

func readContentType(raw []byte) (string, error) {
	OP_1 := byte(0x51)

	b := readBytes(raw, 1)[0]
	if b != OP_1 {
		if b != 0x01 || readBytes(raw, 1)[0] != 0x01 {
			return "", errors.New("Invalid byte sequence")
		}
	}

	size := int(readBytes(raw, 1)[0])
	contentType := readBytes(raw, size)
	return string(contentType), nil
}

func readPushdata(raw []byte, opcode byte) ([]byte, error) {
	intOpcode := int(opcode)

	if 0x01 <= intOpcode && intOpcode <= 0x4b {
		return readBytes(raw, intOpcode), nil
	}

	numBytes := 0
	switch intOpcode {
	case 0x4c:
		numBytes = 1
	case 0x4d:
		numBytes = 2
	case 0x4e:
		numBytes = 4
	default:
		return nil, fmt.Errorf("Invalid push opcode %x at position %d", intOpcode, pointer)
	}

	if pointer+numBytes > len(raw) {
		return nil, fmt.Errorf("Invalid data length at position %d", pointer)
	}

	sizeBytes := readBytes(raw, numBytes)
	var size int
	switch numBytes {
	case 1:
		size = int(sizeBytes[0])
	case 2:
		size = int(binary.LittleEndian.Uint16(sizeBytes))
	case 4:
		size = int(binary.LittleEndian.Uint32(sizeBytes))
	}

	if pointer+size > len(raw) {
		return nil, fmt.Errorf("Invalid data length at position %d", pointer)
	}

	return readBytes(raw, size), nil
}

func decode(inputData string) {
	raw, err := hex.DecodeString(inputData)
	if err != nil {
		return
	}

	pointer, _ = getInitialPosition(raw)

	contentType, _ := readContentType(raw)
	fmt.Printf("Content type: %s\n", contentType)
	if readBytes(raw, 1)[0] != byte(0x00) {
		fmt.Println("Error: Invalid byte sequence")
		return
	}

	data := []byte{}

	OP_ENDIF := byte(0x68)
	opcode := readBytes(raw, 1)[0]
	for opcode != OP_ENDIF {
		chunk, _ := readPushdata(raw, opcode)
		data = append(data, chunk...)
		opcode = readBytes(raw, 1)[0]
	}

	fmt.Printf("Total size: %d bytes\n", len(data))
	//writeFile(data, "output")
	fmt.Printf("%s\n", string(data))
	fmt.Println("\nDone")
}

func main() {
	//Connect to local bitcoin core RPC server using HTTP POST mode.
	connCfg := &rpcclient.ConnConfig{
		Host:         "btc.getblock.io/32dc1a58-fecd-4378-baf3-3cafa70d38d2/mainnet/",
		User:         "yourrpcuser",
		Pass:         "yourrpcpass",
		HTTPPostMode: true,  // Bitcoin core only supports HTTP POST mode
		DisableTLS:   false, // Bitcoin core does not provide TLS by default
	}

	// Notice the notification parameter is nil since notifications are
	// not supported in HTTP POST mode.
	client, err := rpcclient.New(connCfg, nil)
	if err != nil {
		log.Fatal(err)
	}
	defer client.Shutdown()

	// Get the current block count.
	blockCount, err := client.GetBlockCount()
	if err != nil {
		log.Fatal(err)
	}

	log.Printf("Block count: %d", blockCount)

	txHash, _ := chainhash.NewHashFromStr("2782fcc4173baddd337b6adaaca11535daa821ab6c234d8eee22257260ea7d07")
	blockHash, _ := chainhash.NewHashFromStr("000000000000000000058a86fb6dedd44bfa3577bcee453b1eb86f3a5728df7e")
	log.Printf("blockHash: %s\n", blockHash.String())

	log.Printf("txHash: %s\n", txHash.String())

	block, err := client.GetBlockVerboseTx(blockHash)
	if err != nil {
		log.Fatalf("GetBlockVerboseTx: %v", err)
	}
	log.Printf("height: %v", block.Height)

	for i, tx := range block.Tx {
		//fmt.Printf("%v: %v\n", i, tx.Txid)
		if tx.Txid != txHash.String() {
			continue
		}
		fmt.Printf("%v: %v\n", i, tx.Txid)

		for _, vin := range tx.Vin {
			log.Printf("Witness: %s\n", vin.Witness)

			for _, witness := range vin.Witness {
				decode(witness)
			}
		}
	}
}
