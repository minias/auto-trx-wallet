package main

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"
	"github.com/tyler-smith/go-bip39"
)

// TronAddressPrefix는 트론 주소의 고정 prefix (0x41)입니다.
const TronAddressPrefix = "41"

/*
니모닉: outside industry squirrel sponsor vocal auto general fix evidence right ranch make food burst choose manual shadow speed type also race there chaos catalog
개인 키: fcdd865c563f23075f4c7456058485ba3e74bdbd85a0eaacf0ba8645e1979bf2
트론 주소: TVJkmS5kR3E3MRRfT5ypnNtE3NP1wmdMAF

니모닉: this latin consider lucky spoil friend senior real poem oxygen giggle fault cruise era cigar deal switch secret crater student defense horse gown purity
개인 키: 358377b83ac3971773d4eb957516c0cd38f6849250b32c098949380ebd121854
트론 주소: TYweJWBiozBkLDe5WnEcFQjYXkzsJEcrYe
*/

func main() {
	// 1. 니모닉 생성
	entropy, err := bip39.NewEntropy(256)
	if err != nil {
		log.Fatalf("니모닉 엔트로피 생성 실패: %v", err)
	}
	mnemonic, err := bip39.NewMnemonic(entropy)
	if err != nil {
		log.Fatalf("니모닉 생성 실패: %v", err)
	}
	fmt.Println("니모닉:", mnemonic)

	// 2. 니모닉을 기반으로 시드 키 생성
	seed := bip39.NewSeed(mnemonic, "")

	// 3. 개인 키 생성 (secp256k1 곡선 사용)
	privateKey, publicKey := btcec.PrivKeyFromBytes(seed[:32])
	privateKeyHex := hex.EncodeToString(privateKey.Serialize())
	fmt.Println("개인 키:", privateKeyHex)

	// 4. 공개 키에서 주소 생성
	publicKeyBytes := publicKey.SerializeUncompressed()[1:] // 첫 바이트(0x04) 제거
	address := GenerateTronAddress(publicKeyBytes)
	fmt.Println("트론 주소:", address)
}

// GenerateTronAddress는 공개 키를 기반으로 트론 주소를 생성합니다.
func GenerateTronAddress(publicKey []byte) string {
	// 1. SHA-256 해싱
	sha256Hash := sha256.Sum256(publicKey)

	// 2. RIPEMD-160 해싱 (btcutil 라이브러리 사용)
	publicKeyHash := btcutil.Hash160(sha256Hash[:])

	// 3. 트론 주소 (0x41 + RIPEMD-160 해시)
	addressBytes := append([]byte{0x41}, publicKeyHash...)

	// 4. Base58Check 인코딩 (체크섬 포함)
	return Base58CheckEncode(addressBytes)
}

// Base58CheckEncode는 Base58 체크섬을 포함한 인코딩을 수행합니다.
func Base58CheckEncode(input []byte) string {
	// SHA-256을 두 번 적용하여 체크섬 생성
	hash := sha256.Sum256(input)
	hash = sha256.Sum256(hash[:])

	// 첫 4바이트를 체크섬으로 사용
	checksum := hash[:4]
	fullAddress := append(input, checksum...)

	// Base58로 인코딩
	return base58.Encode(fullAddress)
}
