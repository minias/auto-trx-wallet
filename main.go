package main

import (
	"crypto/sha256"
	"encoding/hex"
	"log"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil"
	"github.com/btcsuite/btcutil/base58"

	// "github.com/ethereum/go-ethereum/accounts/abi"
	// "github.com/ethereum/go-ethereum/common"
	"github.com/tyler-smith/go-bip32"
	"github.com/tyler-smith/go-bip39"
)

// TRC20 USDT 스마트 컨트랙트 주소 (Tron 메인넷 기준)
const TRC20_USDT_CONTRACT = "0xa614f803b6fd780986a42c78ec9c7f77e6ded13c"

// Tron BIP-44 코인 ID
const TronCoinID = 195
const purpose = 44
const masterPass = "12345"

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
	log.Printf("니모닉: %s\n", mnemonic)

	// 2. 니모닉을 기반으로 시드 키 생성
	seed := bip39.NewSeed(mnemonic, masterPass)

	// 3. BIP-32 마스터 키 생성
	masterKey, err := bip32.NewMasterKey(seed)
	if err != nil {
		log.Fatalf("마스터 키 생성 실패: %v", err)
	}
	log.Printf("마스터 키: %s\n\n", masterKey)

	CreateUserWallet(masterKey, 0, 0) // 1번째 사이트 1번째유저
	CreateUserWallet(masterKey, 0, 1) // 1번째 사이트 2번째유저
	CreateUserWallet(masterKey, 1, 0) // 2번째 사이트 1번째유저
	CreateUserWallet(masterKey, 1, 1) // 2번째 사이트 2번째유저

	// 7. TRC20 USDT 전송 트랜잭션 생성 (예제)
	// toAddress := "TXXXXXXX..."    // 수신자 주소 (Base58)
	// amount := big.NewInt(1000000) // USDT 전송량 (소수점 6자리, 1 USDT = 1,000,000)
	// rawTx, err := createTRC20TransferTx(address, toAddress, amount)
	// if err != nil {
	// 	log.Fatalf("TRC20 전송 트랜잭션 생성 실패: %v", err)
	// }
	// log.Println("TRC20 USDT 전송 Raw Tx:", rawTx)
}

// User HD wallet create
func CreateUserWallet(masterKey *bip32.Key, siteNo, userNo uint32) {
	// 4. 첫 번째 주소 생성 (m/44'/195'/0'/0/n ->0)
	accountKey, err := deriveKey(masterKey, purpose, TronCoinID, 0, siteNo, userNo)
	if err != nil {
		log.Fatalf("HD 지갑 키 파생 실패: %v", err)
	}
	log.Printf("[%d] 사이트 키: %s", siteNo, accountKey)

	// 5. 개인 키 및 공개 키 생성
	privateKey, publicKey := btcec.PrivKeyFromBytes(accountKey.Key)
	privateKeyHex := hex.EncodeToString(privateKey.Serialize())
	log.Printf("[%d/%d] 개인 키: %s\n", siteNo, userNo, privateKeyHex)

	// 6. 트론 주소 생성
	publicKeyBytes := publicKey.SerializeUncompressed()[1:] // 첫 바이트(0x04) 제거
	address := generateTronAddress(publicKeyBytes)
	log.Printf("[%d/%d] 주소:%s\n\n", siteNo, userNo, address)
}

// deriveKey는 BIP-44 HD 지갑 키를 파생합니다.
func deriveKey(masterKey *bip32.Key, purpose, coinType, account, change, index uint32) (*bip32.Key, error) {
	purposeKey, err := masterKey.NewChildKey(bip32.FirstHardenedChild + purpose)
	if err != nil {
		return nil, err
	}
	coinTypeKey, err := purposeKey.NewChildKey(bip32.FirstHardenedChild + coinType)
	if err != nil {
		return nil, err
	}
	accountKey, err := coinTypeKey.NewChildKey(bip32.FirstHardenedChild + account)
	if err != nil {
		return nil, err
	}
	changeKey, err := accountKey.NewChildKey(change)
	if err != nil {
		return nil, err
	}
	indexKey, err := changeKey.NewChildKey(index)
	if err != nil {
		return nil, err
	}
	return indexKey, nil
}

// generateTronAddress는 공개 키를 기반으로 트론 주소를 생성합니다.
func generateTronAddress(publicKey []byte) string {
	sha256Hash := sha256.Sum256(publicKey)
	publicKeyHash := btcutil.Hash160(sha256Hash[:])
	addressBytes := append([]byte{0x41}, publicKeyHash...)
	return base58EncodeWithChecksum(addressBytes)
}

// base58EncodeWithChecksum는 Base58 체크섬을 포함한 인코딩을 수행합니다.
func base58EncodeWithChecksum(input []byte) string {
	hash := sha256.Sum256(input)
	hash = sha256.Sum256(hash[:])
	checksum := hash[:4]
	fullAddress := append(input, checksum...)
	return base58.Encode(fullAddress)
}

// createTRC20TransferTx는 TRC20 USDT 전송을 위한 트랜잭션을 생성합니다.
// func createTRC20TransferTx(from, to string, amount *big.Int) (string, error) {
// 	// 1. TRC20 "transfer(address,uint256)" 함수 ABI 생성
// 	transferABI, err := abi.JSON(strings.NewReader(`[{"constant":false,"inputs":[{"name":"_to","type":"address"},{"name":"_value","type":"uint256"}],"name":"transfer","outputs":[{"name":"","type":"bool"}],"payable":false,"stateMutability":"nonpayable","type":"function"}]`))
// 	if err != nil {
// 		return "", err
// 	}

// 	// 2. Base58 주소를 Hex(16진수) 주소로 변환
// 	toHex := base58ToHex(to)

// 	// 3. 데이터 필드 생성 (ABI 인코딩)
// 	data, err := transferABI.Pack("transfer", common.HexToAddress(toHex), amount)
// 	if err != nil {
// 		return "", err
// 	}

// 	// 4. Raw 트랜잭션 생성 (Tron 네트워크에 맞게 변형 필요)
// 	rawTx := log.Sprintf("0x%s", hex.EncodeToString(data))

// 	return rawTx, nil
// }

// base58ToHex는 Tron의 Base58 주소를 Hex 주소로 변환합니다.
// func base58ToHex(address string) string {
// 	addressBytes := base58.Decode(address)
// 	hexAddress := hex.EncodeToString(addressBytes[:len(addressBytes)-4]) // 마지막 4바이트(체크섬) 제거
// 	return "0x" + hexAddress
// }
