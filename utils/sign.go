package utils

import (
	"crypto/ecdsa"
	"fmt"
	"io/ioutil"
	"os"
	"time"

	"github.com/axieinfinity/bridge-core/metrics"
	kms "github.com/axieinfinity/ronin-kms-client"
	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/log"
)

type SignMethodConfig struct {
	PlainPrivateKey string          `json:"plainPrivateKey,omitempty"`
	KmsConfig       *kms.KmsConfig  `json:"kmsConfig,omitempty"`
	KeystoreConfig  *KeystoreConfig `json:"keystoreConfig,omitempty"`
}

type KeystoreConfig struct {
	KeystorePath string `json:"KeystorePath"`
	Password     string `json:"password"`
}

func NewSignMethod(config *SignMethodConfig) (ISign, error) {
	if config.PlainPrivateKey != "" {
		return NewPrivateKeySign(config.PlainPrivateKey)
	} else if config.KmsConfig != nil {
		return NewKmsSign(config.KmsConfig)
	} else if config.KeystoreConfig != nil {
		return NewKmsSign(config.KmsConfig)
	}

	log.Warn("No sign methods provided")
	return nil, nil
}

type ISign interface {
	// sign function receives raw message, not hash of message
	Sign(message []byte, dataType string) ([]byte, error)
	GetAddress() common.Address
}

type PrivateKeySign struct {
	privateKey *ecdsa.PrivateKey
}

func NewPrivateKeySign(plainPrivateKey string) (*PrivateKeySign, error) {
	privateKey, err := crypto.HexToECDSA(plainPrivateKey)
	if err != nil {
		log.Error("[NewPrivateKeySign] error while getting plain private key", "err", err)
		return nil, err
	}

	return &PrivateKeySign{
		privateKey: privateKey,
	}, nil
}

type PrivateKeyConfig struct {
	PrivateKey string `json:"privateKey"`
}

func (privateKeySign *PrivateKeySign) Sign(message []byte, dataType string) ([]byte, error) {
	return crypto.Sign(crypto.Keccak256(message), privateKeySign.privateKey)
}

func (privateKeySign *PrivateKeySign) GetAddress() common.Address {
	return crypto.PubkeyToAddress(privateKeySign.privateKey.PublicKey)
}

type KmsSign struct {
	*kms.KmsSign
}

func NewKmsSign(kmsConfig *kms.KmsConfig) (*KmsSign, error) {
	kms, err := kms.NewKmsSign(kmsConfig)
	if err != nil {
		return nil, err
	}
	return &KmsSign{
		KmsSign: kms,
	}, nil
}

func (kmsSign *KmsSign) Sign(message []byte, dataType string) ([]byte, error) {
	start := time.Now().UnixMilli()

	signature, err := kmsSign.KmsSign.Sign(message, dataType)
	if err != nil {
		if err == kms.ErrAccessDenied {
			metrics.Pusher.IncrCounter(metrics.KmsInternalFailure, 1)
		} else {
			metrics.Pusher.IncrCounter(metrics.KmsNetworkFailure, 1)
		}
		return signature, err
	}
	metrics.Pusher.ObserveHistogram(metrics.KmsSignLatency, int(start-time.Now().UnixMilli()))
	metrics.Pusher.SetGauge(metrics.KmsLastSuccess, int(time.Now().Unix()))
	metrics.Pusher.IncrCounter(metrics.KmsSuccessSign, 1)
	return signature, err
}

func (kmsSign *KmsSign) GetAddress() common.Address {
	return kmsSign.KmsSign.Address
}

type KeystoreSign struct {
	ks      *keystore.KeyStore
	account accounts.Account
}

func NewKeystoreSign(KeystoreConfig *KeystoreConfig) (*KeystoreSign, error) {

	ks := keystore.NewKeyStore("./tmp", keystore.StandardScryptN, keystore.StandardScryptP)
	jsonBytes, err := ioutil.ReadFile(KeystoreConfig.KeystorePath)
	if err != nil {
		fmt.Print("*******1")
		log.Error("[Keystore] Failed to read keystore file", "error", err)
	}

	account, err := ks.Import(jsonBytes, KeystoreConfig.Password, KeystoreConfig.Password)
	if err != nil {
		fmt.Print("*******2")
		log.Error("[Keystore] Failed to import password", "error", err)
	}

	// fmt.Println(account.Address.Hex()) // 0x20F8D42FB0F667F2E53930fed426f225752453b3

	if err := os.Remove(KeystoreConfig.KeystorePath); err != nil {
		fmt.Print("*******3")
		log.Error("[Keystore] Failed to remove keystore file", "error", err)
	}

	return &KeystoreSign{
		ks:      ks,
		account: account,
	}, nil
}

// Sign function receives raw message, not hash of message
func (KeystoreSign *KeystoreSign) Sign(message []byte, dataType string) ([]byte, error) {
	return KeystoreSign.ks.SignHash(KeystoreSign.account, message)
}
