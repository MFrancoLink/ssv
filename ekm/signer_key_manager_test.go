package ekm

import (
	"crypto/hmac"
	"crypto/sha256"
	"fmt"
	"math"
	"math/rand"
	"os"
	"runtime/pprof"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/cloudflare/circl/sign/dilithium"

	"crypto/aes"
	"crypto/cipher"

	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	cryptorand "crypto/rand"
	"crypto/rsa"

	"github.com/attestantio/go-eth2-client/spec/altair"
	"github.com/attestantio/go-eth2-client/spec/bellatrix"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	specqbft "github.com/bloxapp/ssv-spec/qbft"
	spectypes "github.com/bloxapp/ssv-spec/types"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/jamiealquiza/tachymeter"
	"github.com/minio/blake2b-simd"
	"github.com/prysmaticlabs/go-bitfield"
	"github.com/sourcegraph/conc/pool"
	"github.com/stretchr/testify/require"
	"golang.org/x/exp/slices"

	"github.com/bloxapp/ssv/logging"
	"github.com/bloxapp/ssv/networkconfig"
	"github.com/bloxapp/ssv/protocol/v2/types"
	"github.com/bloxapp/ssv/utils/threshold"

	"github.com/algorand/falcon"
	"github.com/monnand/dhkx"
)

const (
	sk1Str = "3548db63ab5701878daf25fa877638dc7809778815b9d9ecd5369da33ca9e64f"
	pk1Str = "a8cb269bd7741740cfe90de2f8db6ea35a9da443385155da0fa2f621ba80e5ac14b5c8f65d23fd9ccc170cc85f29e27d"
	sk2Str = "66dd37ae71b35c81022cdde98370e881cff896b689fa9136917f45afce43fd3b"
	pk2Str = "8796fafa576051372030a75c41caafea149e4368aebaca21c9f90d9974b3973d5cee7d7874e4ec9ec59fb2c8945b3e01"
)

func testKeyManager(t *testing.T) spectypes.KeyManager {
	threshold.Init()

	logger := logging.TestLogger(t)

	db, err := getBaseStorage(logger)
	require.NoError(t, err)

	km, err := NewETHKeyManagerSigner(logger, db, networkconfig.TestNetwork, true)
	require.NoError(t, err)

	sk1 := &bls.SecretKey{}
	require.NoError(t, sk1.SetHexString(sk1Str))

	sk2 := &bls.SecretKey{}
	require.NoError(t, sk2.SetHexString(sk2Str))

	require.NoError(t, km.AddShare(sk1))
	require.NoError(t, km.AddShare(sk2))

	return km
}

func benchKeyManager(b *testing.B) spectypes.KeyManager {
	threshold.Init()

	logger := logging.BenchLogger(b)

	db, err := getBaseStorage(logger)
	require.NoError(b, err)

	km, err := NewETHKeyManagerSigner(logger, db, networkconfig.TestNetwork, true)
	require.NoError(b, err)

	sk1 := &bls.SecretKey{}
	require.NoError(b, sk1.SetHexString(sk1Str))

	sk2 := &bls.SecretKey{}
	require.NoError(b, sk2.SetHexString(sk2Str))

	require.NoError(b, km.AddShare(sk1))
	require.NoError(b, km.AddShare(sk2))

	return km
}

func TestSlashing(t *testing.T) {
	km := testKeyManager(t)

	sk1 := &bls.SecretKey{}
	require.NoError(t, sk1.SetHexString(sk1Str))
	require.NoError(t, km.AddShare(sk1))

	currentSlot := km.(*ethKeyManagerSigner).storage.Network().EstimatedCurrentSlot()
	currentEpoch := km.(*ethKeyManagerSigner).storage.Network().EstimatedEpochAtSlot(currentSlot)

	highestTarget := currentEpoch + minimalAttSlashingProtectionEpochDistance + 1
	highestSource := highestTarget - 1
	highestProposal := currentSlot + minimalBlockSlashingProtectionSlotDistance + 1

	attestationData := &phase0.AttestationData{
		Slot:            30,
		Index:           1,
		BeaconBlockRoot: [32]byte{1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 1, 2, 3, 4, 5, 6, 1, 2},
		Source: &phase0.Checkpoint{
			Epoch: highestSource,
			Root:  [32]byte{},
		},
		Target: &phase0.Checkpoint{
			Epoch: highestTarget,
			Root:  [32]byte{},
		},
	}

	var beaconBlock = &bellatrix.BeaconBlock{
		Slot:          highestProposal,
		ProposerIndex: 0,
		ParentRoot: phase0.Root{
			0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
			0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
		},
		StateRoot: phase0.Root{
			0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29, 0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f,
			0x30, 0x31, 0x32, 0x33, 0x34, 0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x3f,
		},
		Body: &bellatrix.BeaconBlockBody{
			RANDAOReveal: phase0.BLSSignature{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
			ETH1Data: &phase0.ETH1Data{
				DepositRoot: phase0.Root{
					0x40, 0x41, 0x42, 0x43, 0x44, 0x45, 0x46, 0x47, 0x48, 0x49, 0x4a, 0x4b, 0x4c, 0x4d, 0x4e, 0x4f,
					0x50, 0x51, 0x52, 0x53, 0x54, 0x55, 0x56, 0x57, 0x58, 0x59, 0x5a, 0x5b, 0x5c, 0x5d, 0x5e, 0x5f,
				},
				DepositCount: 0,
				BlockHash: []byte{
					0x60, 0x61, 0x62, 0x63, 0x64, 0x65, 0x66, 0x67, 0x68, 0x69, 0x6a, 0x6b, 0x6c, 0x6d, 0x6e, 0x6f,
					0x70, 0x71, 0x72, 0x73, 0x74, 0x75, 0x76, 0x77, 0x78, 0x79, 0x7a, 0x7b, 0x7c, 0x7d, 0x7e, 0x7f,
				},
			},
			Graffiti: [32]byte{
				0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
				0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
			},
			ProposerSlashings: []*phase0.ProposerSlashing{},
			AttesterSlashings: []*phase0.AttesterSlashing{},
			Attestations:      []*phase0.Attestation{},
			Deposits:          []*phase0.Deposit{},
			VoluntaryExits:    []*phase0.SignedVoluntaryExit{},
			SyncAggregate: &altair.SyncAggregate{
				SyncCommitteeBits: bitfield.Bitvector512{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				},
				SyncCommitteeSignature: phase0.BLSSignature{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				},
			},
			ExecutionPayload: &bellatrix.ExecutionPayload{
				ParentHash: phase0.Hash32{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				},
				FeeRecipient: bellatrix.ExecutionAddress{},
				StateRoot: [32]byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				},
				ReceiptsRoot: [32]byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				},
				LogsBloom: [256]byte{},
				PrevRandao: [32]byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				},
				BlockNumber: 0,
				GasLimit:    0,
				GasUsed:     0,
				Timestamp:   0,
				ExtraData:   nil,
				BaseFeePerGas: [32]byte{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				},
				BlockHash: phase0.Hash32{
					0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
					0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
				},
				Transactions: []bellatrix.Transaction{},
			},
		},
	}

	t.Run("sign once", func(t *testing.T) {
		_, sig, err := km.(*ethKeyManagerSigner).SignBeaconObject(attestationData, phase0.Domain{}, sk1.GetPublicKey().Serialize(), spectypes.DomainAttester)
		require.NoError(t, err)
		require.NotNil(t, sig)
		require.NotEqual(t, [32]byte{}, sig)
	})
	t.Run("slashable sign, fail", func(t *testing.T) {
		_, sig, err := km.(*ethKeyManagerSigner).SignBeaconObject(attestationData, phase0.Domain{}, sk1.GetPublicKey().Serialize(), spectypes.DomainAttester)
		require.EqualError(t, err, "slashable attestation (HighestAttestationVote), not signing")
		require.Equal(t, [32]byte{}, sig)
	})

	t.Run("sign once", func(t *testing.T) {
		_, sig, err := km.(*ethKeyManagerSigner).SignBeaconObject(beaconBlock, phase0.Domain{}, sk1.GetPublicKey().Serialize(), spectypes.DomainProposer)
		require.NoError(t, err)
		require.NotNil(t, sig)
		require.NotEqual(t, [32]byte{}, sig)
	})
	t.Run("slashable sign, fail", func(t *testing.T) {
		_, sig, err := km.(*ethKeyManagerSigner).SignBeaconObject(beaconBlock, phase0.Domain{}, sk1.GetPublicKey().Serialize(), spectypes.DomainProposer)
		require.EqualError(t, err, "slashable proposal (HighestProposalVote), not signing")
		require.Equal(t, [32]byte{}, sig)
	})
}

func BenchmarkSecp256k1SignatureVerification(b *testing.B) {
	// Generate a random secp256k1 private key
	privKey, _ := ecdsa.GenerateKey(btcec.S256(), cryptorand.Reader)

	// Create a message to sign
	message := []byte("Hello, world!")
	hashed := sha256.Sum256(message)

	// Sign the message
	r, s, _ := ecdsa.Sign(cryptorand.Reader, privKey, hashed[:])

	// Create a secp256k1 public key from the private key
	publicKey := &privKey.PublicKey

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Verify the signature
		valid := ecdsa.Verify(publicKey, hashed[:], r, s)
		if !valid {
			b.Fatal("Signature verification failed")
		}
	}
}

func BenchmarkSecp256k1SignatureSign(b *testing.B) {
	// Generate a random secp256k1 private key
	privKey, _ := ecdsa.GenerateKey(btcec.S256(), cryptorand.Reader)

	// Create a message to sign
	message := []byte("Hello, world!")
	hashed := sha256.Sum256(message)

	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		// Verify the signature
		_, _, err := ecdsa.Sign(cryptorand.Reader, privKey, hashed[:])
		if err != nil {
			b.Fatal("Signature verification failed")
		}
	}
}

func BenchmarkFalconVerification(b *testing.B) {

	data := []byte("Hello, world!")
	hashed := sha256.Sum256(data)

	pk, sk, err := falcon.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	signature, err := sk.SignCompressed(hashed[:])
	if err != nil {
		panic(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Checks whether a signature is correct
		if pk.Verify(signature, hashed[:]) != nil {
			panic("incorrect signature")
		}
	}
}

func BenchmarkFalconSign(b *testing.B) {

	data := []byte("Hello, world!")
	hashed := sha256.Sum256(data)

	_, sk, err := falcon.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := sk.SignCompressed(hashed[:])
		if err != nil {
			panic(err)
		}
	}
}

func BenchmarkDilithiumVerification(b *testing.B) {

	data := []byte("Hello, world!")
	hashed := sha256.Sum256(data)

	mode := dilithium.ModeByName("Dilithium3")
	if mode == nil {
		panic("Mode3 not supported")
	}

	// Generates a keypair.
	pk, sk, err := mode.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	signature := mode.Sign(sk, hashed[:])

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// Checks whether a signature is correct
		if !mode.Verify(pk, hashed[:], signature) {
			panic("incorrect signature")
		}
	}
}

func BenchmarkDilithiumSign(b *testing.B) {

	data := []byte("Hello, world!")
	hashed := sha256.Sum256(data)

	mode := dilithium.ModeByName("Dilithium3")
	if mode == nil {
		panic("Mode3 not supported")
	}

	// Generates a keypair.
	_, sk, err := mode.GenerateKey(nil)
	if err != nil {
		panic(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		mode.Sign(sk, hashed[:])
	}
}

func TestRSA(b *testing.T) {
	privKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}

	data := []byte("Hello, world!")
	hashed := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(cryptorand.Reader, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		b.Fatal(err)
	}

	err = rsa.VerifyPKCS1v15(&privKey.PublicKey, crypto.SHA256, hashed[:], signature)
	if err != nil {
		b.Fatal(err)
	}

}

func BenchmarkRSASignatureVerification(b *testing.B) {
	privKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}

	data := []byte("Hello, world!")
	hashed := sha256.Sum256(data)
	signature, err := rsa.SignPKCS1v15(cryptorand.Reader, privKey, crypto.SHA256, hashed[:])
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := rsa.VerifyPKCS1v15(&privKey.PublicKey, crypto.SHA256, hashed[:], signature)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkRSASignatureSign(b *testing.B) {
	privKey, err := rsa.GenerateKey(cryptorand.Reader, 2048)
	if err != nil {
		b.Fatal(err)
	}

	data := []byte("Hello, world!")
	hashed := sha256.Sum256(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := rsa.SignPKCS1v15(cryptorand.Reader, privKey, crypto.SHA256, hashed[:])
		if err != nil {
			b.Fatal(err)
		}
	}
}
func BenchmarkRSASignPSS(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(cryptorand.Reader, 2048)

	data := []byte("Hello, world!")
	hashed := sha256.Sum256(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, err := rsa.SignPSS(cryptorand.Reader, privateKey, crypto.SHA256, hashed[:], nil)
		if err != nil {
			b.Fatal("signing failed:", err)
		}
	}
}

func BenchmarkRSAVerifyPSS(b *testing.B) {
	privateKey, _ := rsa.GenerateKey(cryptorand.Reader, 2048)

	data := []byte("Hello, world!")
	hashed := sha256.Sum256(data)

	signature, _ := rsa.SignPSS(cryptorand.Reader, privateKey, crypto.SHA256, hashed[:], nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err := rsa.VerifyPSS(&privateKey.PublicKey, crypto.SHA256, hashed[:], signature, nil)
		if err != nil {
			b.Fatal("verification failed:", err)
		}
	}
}

func BenchmarkECDSASignatureVerification(b *testing.B) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	data := []byte("Hello, world!")
	hashed := sha256.Sum256(data)
	r, s, err := ecdsa.Sign(cryptorand.Reader, privKey, hashed[:])
	if err != nil {
		b.Fatal(err)
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid := ecdsa.Verify(&privKey.PublicKey, hashed[:], r, s)
		if !valid {
			b.Fatal("Signature verification failed")
		}
	}
}

func BenchmarkECDSASignatureSign(b *testing.B) {
	privKey, err := ecdsa.GenerateKey(elliptic.P256(), cryptorand.Reader)
	if err != nil {
		b.Fatal(err)
	}

	data := []byte("Hello, world!")
	hashed := sha256.Sum256(data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _, err := ecdsa.Sign(cryptorand.Reader, privKey, hashed[:])
		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEdDSASignatureVerification(b *testing.B) {
	_, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}

	data := []byte("Hello, world!")
	signature := ed25519.Sign(privKey, data)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		valid := ed25519.Verify(privKey.Public().(ed25519.PublicKey), data, signature)
		if !valid {
			b.Fatal("Signature verification failed")
		}
	}
}

func BenchmarkEdDSASignatureSign(b *testing.B) {
	_, privKey, err := ed25519.GenerateKey(nil)
	if err != nil {
		b.Fatal(err)
	}

	data := []byte("Hello, world!")

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		ed25519.Sign(privKey, data)
	}
}

func BenchmarkInvalidBLSVerification(b *testing.B) {
	// Initialize BLS library
	if err := bls.Init(bls.BLS12_381); err != nil {
		b.Fatal(err)
	}

	// Generate a BLS key pair
	secretKey := new(bls.SecretKey)
	secretKey.SetByCSPRNG()
	publicKey := secretKey.GetPublicKey()

	secretKey2 := new(bls.SecretKey)
	secretKey2.SetByCSPRNG()
	// publicKey2 := secretKey2.GetPublicKey()

	// Create a message to sign
	message := []byte("Hello, world!")

	// Sign the message
	signature := secretKey2.Sign(string(message))

	// Reset the timer
	b.ResetTimer()

	// Perform signature verification in the benchmark
	for i := 0; i < b.N; i++ {
		if signature.Verify(publicKey, string(message)) {
			b.Fatal("Signature verification failed")
		}
	}
}

func BenchmarkBLSVerification(b *testing.B) {
	// Initialize BLS library
	if err := bls.Init(bls.BLS12_381); err != nil {
		b.Fatal(err)
	}

	// Generate a BLS key pair
	secretKey := new(bls.SecretKey)
	secretKey.SetByCSPRNG()
	publicKey := secretKey.GetPublicKey()

	// Create a message to sign
	message := []byte("Hello, world!")

	// Sign the message
	signature := secretKey.Sign(string(message))

	// Reset the timer
	b.ResetTimer()

	// Perform signature verification in the benchmark
	for i := 0; i < b.N; i++ {
		if !signature.Verify(publicKey, string(message)) {
			b.Fatal("Signature verification failed")
		}
	}
}

func BenchmarkBLSSignature(b *testing.B) {
	// Initialize BLS library
	if err := bls.Init(bls.BLS12_381); err != nil {
		b.Fatal(err)
	}

	// Generate a BLS key pair
	secretKey := new(bls.SecretKey)
	secretKey.SetByCSPRNG()

	// Create a message to sign
	message := []byte("Hello, world!")

	// Reset the timer
	b.ResetTimer()

	// Perform signature verification in the benchmark
	for i := 0; i < b.N; i++ {
		// Sign the message
		secretKey.Sign(string(message))
	}
}

func BenchmarkBLSSign(b *testing.B) {
	km := benchKeyManager(b)

	pk := &bls.PublicKey{}
	require.NoError(b, pk.Deserialize(_byteArray(pk1Str)))

	msg := specqbft.Message{
		MsgType:    specqbft.CommitMsgType,
		Height:     specqbft.Height(3),
		Round:      specqbft.Round(2),
		Identifier: []byte("identifier1"),
		Root:       [32]byte{1, 2, 3},
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		// sign
		_, err := km.SignRoot(&msg, spectypes.QBFTSignatureType, pk.Serialize())
		require.NoError(b, err)
	}
}

func BenchmarkBLSVerify(b *testing.B) {
	km := benchKeyManager(b)

	pk := &bls.PublicKey{}
	require.NoError(b, pk.Deserialize(_byteArray(pk1Str)))

	msg := specqbft.Message{
		MsgType:    specqbft.CommitMsgType,
		Height:     specqbft.Height(3),
		Round:      specqbft.Round(2),
		Identifier: []byte("identifier1"),
		Root:       [32]byte{1, 2, 3},
	}

	// sign
	sig, err := km.SignRoot(&msg, spectypes.QBFTSignatureType, pk.Serialize())
	require.NoError(b, err)

	// verify
	signed := &specqbft.SignedMessage{
		Signature: sig,
		Signers:   []spectypes.OperatorID{1},
		Message:   msg,
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		err = types.SingleVerifyByOperators(signed.GetSignature(), signed, networkconfig.TestNetwork.Domain, spectypes.QBFTSignatureType, []*spectypes.Operator{{OperatorID: spectypes.OperatorID(1), PubKey: pk.Serialize()}})
		require.NoError(b, err)
	}
}

func BenchmarkBLSSharedKey(b *testing.B) {

	pk := &bls.PublicKey{}
	require.NoError(b, pk.Deserialize(_byteArray(pk1Str)))

	sk := &bls.SecretKey{}
	require.NoError(b, sk.Deserialize(_byteArray(sk2Str)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		bls.DHKeyExchange(sk, pk)
	}
}

func BenchmarkBLSSharedKeyCompare(b *testing.B) {

	pk1 := &bls.PublicKey{}
	require.NoError(b, pk1.Deserialize(_byteArray(pk1Str)))

	sk2 := &bls.SecretKey{}
	require.NoError(b, sk2.Deserialize(_byteArray(sk2Str)))

	pk2 := &bls.PublicKey{}
	require.NoError(b, pk2.Deserialize(_byteArray(pk2Str)))

	sk1 := &bls.SecretKey{}
	require.NoError(b, sk1.Deserialize(_byteArray(sk1Str)))

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		symmetric_key1 := bls.DHKeyExchange(sk1, pk2)
		symmetric_key2 := bls.DHKeyExchange(sk2, pk1)
		require.True(b, symmetric_key2.GetHexString() == symmetric_key1.GetHexString())
	}
}

func BenchmarkRandomSymmetricKey(b *testing.B) {

	b.ResetTimer()
	for i := 0; i < b.N; i++ {

		_, err := generateSymmetricKey(64)
		require.NoError(b, err)
	}
}

func BenchmarkDHPrivKey(b *testing.B) {

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		g, err := dhkx.GetGroup(14)
		require.NoError(b, err)

		_, err = g.GeneratePrivateKey(nil)
		require.NoError(b, err)
	}
}

func BenchmarkDHPubKey(b *testing.B) {

	g, err := dhkx.GetGroup(14)
	require.NoError(b, err)

	priv, err := g.GeneratePrivateKey(nil)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {

		// Get the public key from the private key.
		priv.Bytes()
	}
}

func BenchmarkDHPubKeyRecover(b *testing.B) {

	g, err := dhkx.GetGroup(14)
	require.NoError(b, err)

	priv, err := g.GeneratePrivateKey(nil)
	require.NoError(b, err)

	// Get the public key from the private key.
	pubKey := priv.Bytes()

	b.ResetTimer()
	for i := 0; i < b.N; i++ {

		// Recover Bob's public key
		dhkx.NewPublicKey(pubKey)
	}
}

func BenchmarkDHComputeSymmetricKey(b *testing.B) {

	g, err := dhkx.GetGroup(14)
	require.NoError(b, err)

	priv, err := g.GeneratePrivateKey(nil)
	require.NoError(b, err)

	bobPrivKey, err := g.GeneratePrivateKey(nil)
	// fmt.Println("Private key: ", priv)
	require.NoError(b, err)

	bobPublicKey := bobPrivKey.Bytes()
	// fmt.Println("Publick key: ", bobPublicKey)

	// Recover Bob's public key
	bobPubKey := dhkx.NewPublicKey(bobPublicKey)

	b.ResetTimer()
	for i := 0; i < 1; i++ {

		// Compute the key
		k, err := g.ComputeKey(bobPubKey, priv)
		require.NoError(b, err)
		// fmt.Println("Symmetric Key: ", k)

		// Get the key in the form of []byte
		k.Bytes()
		// fmt.Println("Symmetric Key bytes: ", k)
	}
}

func generateSymmetricKey(keySize int) ([]byte, error) {
	key := make([]byte, keySize)
	_, err := rand.Read(key)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func BenchmarkHMACCreate(b *testing.B) {

	msg := specqbft.Message{
		MsgType:    specqbft.CommitMsgType,
		Height:     specqbft.Height(3),
		Round:      specqbft.Round(2),
		Identifier: []byte("identifier1"),
		Root:       [32]byte{1, 2, 3},
	}

	dataRoot, err := msg.GetRoot()
	require.NoError(b, err)

	domain := spectypes.ComputeSignatureDomain(networkconfig.TestNetwork.Domain, spectypes.QBFTSignatureType)

	// signing_root := sha256.Sum256(append(dataRoot[:], domain...))

	key, err := generateSymmetricKey(64)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {

		mac := hmac.New(sha256.New, key)
		mac.Write(append(dataRoot[:], domain...))
		mac.Sum(nil)
	}
}

func BenchmarkBlake2Create(b *testing.B) {

	msg := specqbft.Message{
		MsgType:    specqbft.CommitMsgType,
		Height:     specqbft.Height(3),
		Round:      specqbft.Round(2),
		Identifier: []byte("identifier1"),
		Root:       [32]byte{1, 2, 3},
	}

	dataRoot, err := msg.GetRoot()
	require.NoError(b, err)

	domain := spectypes.ComputeSignatureDomain(networkconfig.TestNetwork.Domain, spectypes.QBFTSignatureType)

	// signing_root := sha256.Sum256(append(dataRoot[:], domain...))

	key, err := generateSymmetricKey(64)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {

		mac, err := blake2b.New(&blake2b.Config{Key: key})
		require.NoError(b, err)

		mac.Write(append(dataRoot[:], domain...))
		mac.Sum(nil)
	}
}

func BenchmarkAESGCMCreate(b *testing.B) {

	msg := specqbft.Message{
		MsgType:    specqbft.CommitMsgType,
		Height:     specqbft.Height(3),
		Round:      specqbft.Round(2),
		Identifier: []byte("identifier1"),
		Root:       [32]byte{1, 2, 3},
	}

	dataRoot, err := msg.GetRoot()
	require.NoError(b, err)

	domain := spectypes.ComputeSignatureDomain(networkconfig.TestNetwork.Domain, spectypes.QBFTSignatureType)

	// signing_root := sha256.Sum256(append(dataRoot[:], domain...))

	key, err := generateSymmetricKey(32)
	require.NoError(b, err)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {

		block, err := aes.NewCipher(key)
		if err != nil {
			fmt.Println(err)
			return
		}

		nonce := make([]byte, 12) // 96-bit nonce
		if _, err := rand.Read(nonce); err != nil {
			fmt.Println(err)
			return
		}

		aead, err := cipher.NewGCM(block)
		if err != nil {
			fmt.Println(err)
			return
		}
		aead.Seal(nil, nonce, append(dataRoot[:], domain...), nil)
	}
}

func BenchmarkAESGCMVerify(b *testing.B) {

	msg := specqbft.Message{
		MsgType:    specqbft.CommitMsgType,
		Height:     specqbft.Height(3),
		Round:      specqbft.Round(2),
		Identifier: []byte("identifier1"),
		Root:       [32]byte{1, 2, 3},
	}

	dataRoot, err := msg.GetRoot()
	require.NoError(b, err)

	domain := spectypes.ComputeSignatureDomain(networkconfig.TestNetwork.Domain, spectypes.QBFTSignatureType)

	// signing_root := sha256.Sum256(append(dataRoot[:], domain...))

	key, err := generateSymmetricKey(32)
	require.NoError(b, err)

	block, err := aes.NewCipher(key)
	if err != nil {
		fmt.Println(err)
		return
	}

	nonce := make([]byte, 12) // 96-bit nonce
	if _, err := rand.Read(nonce); err != nil {
		fmt.Println(err)
		return
	}

	aead, err := cipher.NewGCM(block)
	if err != nil {
		fmt.Println(err)
		return
	}

	ciphertext := aead.Seal(nil, nonce, append(dataRoot[:], domain...), nil)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {

		block, err := aes.NewCipher(key)
		if err != nil {
			fmt.Println(err)
			return
		}

		aead, err := cipher.NewGCM(block)
		if err != nil {
			fmt.Println(err)
			return
		}

		_, err = aead.Open(nil, nonce, ciphertext, nil)
		require.NoError(b, err)
	}
}

func TestSignRoot(t *testing.T) {
	require.NoError(t, bls.Init(bls.BLS12_381))

	km := testKeyManager(t)

	t.Run("pk 1", func(t *testing.T) {
		pk := &bls.PublicKey{}
		require.NoError(t, pk.Deserialize(_byteArray(pk1Str)))

		msg := specqbft.Message{
			MsgType:    specqbft.CommitMsgType,
			Height:     specqbft.Height(3),
			Round:      specqbft.Round(2),
			Identifier: []byte("identifier1"),
			Root:       [32]byte{1, 2, 3},
		}

		// sign
		sig, err := km.SignRoot(&msg, spectypes.QBFTSignatureType, pk.Serialize())
		require.NoError(t, err)

		// verify
		signed := &specqbft.SignedMessage{
			Signature: sig,
			Signers:   []spectypes.OperatorID{1},
			Message:   msg,
		}

		start := time.Now()
		err = types.VerifyByOperators(signed.GetSignature(), signed, networkconfig.TestNetwork.Domain, spectypes.QBFTSignatureType, []*spectypes.Operator{{OperatorID: spectypes.OperatorID(1), PubKey: pk.Serialize()}})
		// res, err := signed.VerifySig(pk)
		require.NoError(t, err)
		// require.True(t, res)
		fmt.Println(time.Since(start))
	})

	t.Run("pk 2", func(t *testing.T) {
		pk := &bls.PublicKey{}
		require.NoError(t, pk.Deserialize(_byteArray(pk2Str)))

		msg := specqbft.Message{
			MsgType:    specqbft.CommitMsgType,
			Height:     specqbft.Height(1),
			Round:      specqbft.Round(3),
			Identifier: []byte("identifier2"),
			Root:       [32]byte{4, 5, 6},
		}

		// sign
		sig, err := km.SignRoot(&msg, spectypes.QBFTSignatureType, pk.Serialize())
		require.NoError(t, err)

		// verify
		signed := &specqbft.SignedMessage{
			Signature: sig,
			Signers:   []spectypes.OperatorID{1},
			Message:   msg,
		}

		start := time.Now()
		for i := 0; i < 100; i++ {
			err = types.VerifyByOperators(signed.GetSignature(), signed, networkconfig.TestNetwork.Domain, spectypes.QBFTSignatureType, []*spectypes.Operator{{OperatorID: spectypes.OperatorID(1), PubKey: pk.Serialize()}})
			// res, err := signed.VerifySig(pk)
			require.NoError(t, err)
			// require.True(t, res)
		}
		fmt.Println(time.Since(start))
	})

	t.Run("multiple signers", func(t *testing.T) {
		// t.Skip()

		pk1 := &bls.PublicKey{}
		require.NoError(t, pk1.Deserialize(_byteArray(pk1Str)))
		pk2 := &bls.PublicKey{}
		require.NoError(t, pk2.Deserialize(_byteArray(pk2Str)))

		go func() {
			msg := specqbft.Message{
				MsgType:    specqbft.CommitMsgType,
				Height:     specqbft.Height(1),
				Round:      specqbft.Round(3),
				Identifier: []byte("identifier2"),
				Root:       [32]byte{4, 5, 6},
			}

			// sign
			sig1, err := km.SignRoot(&msg, spectypes.QBFTSignatureType, pk1.Serialize())
			require.NoError(t, err)
			sign1 := &bls.Sign{}
			err = sign1.Deserialize(sig1)
			require.NoError(t, err)

			sig2, err := km.SignRoot(&msg, spectypes.QBFTSignatureType, pk2.Serialize())
			require.NoError(t, err)
			sign2 := &bls.Sign{}
			err = sign2.Deserialize(sig2)
			require.NoError(t, err)

			sign := sign1
			sign.Add(sign2)

			// verify
			signed := &specqbft.SignedMessage{
				Signature: sign.Serialize(),
				Signers:   []spectypes.OperatorID{1, 2},
				Message:   msg,
			}

			err = types.VerifyByOperators(signed.GetSignature(), signed, networkconfig.TestNetwork.Domain, spectypes.QBFTSignatureType,
				[]*spectypes.Operator{
					{OperatorID: spectypes.OperatorID(1), PubKey: pk1.Serialize()},
					{OperatorID: spectypes.OperatorID(2), PubKey: pk2.Serialize()},
				})
			// res, err := signed.VerifySig(pk)
			require.NoError(t, err)
			// require.True(t, res)
		}()

		msg := specqbft.Message{
			MsgType:    specqbft.CommitMsgType,
			Height:     specqbft.Height(1),
			Round:      specqbft.Round(3),
			Identifier: []byte("identifier2"),
			Root:       [32]byte{4, 5, 6},
		}

		// sign
		sig1, err := km.SignRoot(&msg, spectypes.QBFTSignatureType, pk1.Serialize())
		require.NoError(t, err)
		sign1 := &bls.Sign{}
		err = sign1.Deserialize(sig1)
		require.NoError(t, err)

		sig2, err := km.SignRoot(&msg, spectypes.QBFTSignatureType, pk2.Serialize())
		require.NoError(t, err)
		sign2 := &bls.Sign{}
		err = sign2.Deserialize(sig2)
		require.NoError(t, err)

		sign := *sign1
		sign.Add(sign2)

		// verify
		signed := &specqbft.SignedMessage{
			Signature: sign.Serialize(),
			Signers:   []spectypes.OperatorID{1, 2},
			Message:   msg,
		}

		start := time.Now()
		for i := 0; i < 10; i++ {
			err = types.VerifyByOperators(signed.GetSignature(), signed, networkconfig.TestNetwork.Domain, spectypes.QBFTSignatureType,
				[]*spectypes.Operator{
					{OperatorID: spectypes.OperatorID(1), PubKey: pk1.Serialize()},
					{OperatorID: spectypes.OperatorID(2), PubKey: pk2.Serialize()},
				})
			require.NoError(t, err)
		}
		fmt.Println(time.Since(start))
	})

	t.Run("multiple signers 2", func(t *testing.T) {
		// t.Skip()

		batch_lst := []int{100}
		N_lst := []int{2200, 2400, 2600, 2800, 3000}
		timeout_lst := []float64{5}
		num_cpu_lst := []int{4}
		sleep_lst := []bool{false}
		total_duration := 1000
		use_normal_dist := true

		print_sleep_lst := false

		adjust := []bool{true}

		attack_percentage := []int{0}

		f2, _ := os.Create("./output.txt")
		defer f2.Close()

		reps := 5
		rep_i := 1
		for _, attack_p := range attack_percentage {
			for _, adj := range adjust {
				f2.WriteString(fmt.Sprintf("#Adjust:%v\n", adj))
				rep_i = 1
				for rep_i <= reps {
					rep_i += 1
					for _, Batch := range batch_lst {
						for _, NumMessages := range N_lst {
							for _, timeout_v := range timeout_lst {
								for _, num_cpu := range num_cpu_lst {
									for _, sleep_v := range sleep_lst {
										pk1 := &bls.PublicKey{}
										require.NoError(t, pk1.Deserialize(_byteArray(pk1Str)))
										pk2 := &bls.PublicKey{}
										require.NoError(t, pk2.Deserialize(_byteArray(pk2Str)))

										var N = NumMessages
										var msgs = make([]*specqbft.SignedMessage, N)
										do_sleep := sleep_v
										num_cpus := num_cpu // runtime.NumCPU()
										batch := int(math.Min(float64(Batch), float64(NumMessages)))
										batch = int(math.Ceil(float64(NumMessages)*0.01207 + 1.379)) //int(math.Min(float64(Batch), float64(NumMessages)))
										// fmt.Println(NumMessages, "->", batch)
										timeout_time := timeout_v
										types.Verifier = types.NewBatchVerifier(num_cpus, batch, time.Millisecond*time.Duration(timeout_time))
										types.Verifier.Adjust = adj
										go types.Verifier.Start()

										p := pool.New()
										for i := 0; i < N; i++ {
											i := i
											p.Go(func() {
												msg := specqbft.Message{
													MsgType:    specqbft.CommitMsgType,
													Height:     specqbft.Height(rand.Uint64()),
													Round:      specqbft.Round(3),
													Identifier: []byte("identifier2"),
													Root:       [32]byte{4, 5, 6},
												}

												// sign
												sig1, err := km.SignRoot(&msg, spectypes.QBFTSignatureType, pk1.Serialize())
												require.NoError(t, err)
												sign1 := &bls.Sign{}
												err = sign1.Deserialize(sig1)
												require.NoError(t, err)

												sig2, err := km.SignRoot(&msg, spectypes.QBFTSignatureType, pk2.Serialize())
												require.NoError(t, err)
												sign2 := &bls.Sign{}
												err = sign2.Deserialize(sig2)
												require.NoError(t, err)

												sign := *sign1
												if attack_p == 0 || i%attack_p != 0 {
													sign.Add(sign2)
												}

												// verify
												msgs[i] = &specqbft.SignedMessage{
													Signature: sign.Serialize(),
													Signers:   []spectypes.OperatorID{1, 2},
													Message:   msg,
												}
											})
										}
										p.Wait()

										// var total time.Duration
										// for j := 0; j < 10; j++ {
										// 	start := time.Now()
										// 	p = pool.New()
										// 	for i := range msgs {
										// 		signed := msgs[i]
										// 		p.Go(func() {
										// 			err := types.VerifyByOperators(signed.GetSignature(), signed, networkconfig.TestNetwork.Domain, spectypes.QBFTSignatureType,
										// 				[]*spectypes.Operator{
										// 					{OperatorID: spectypes.OperatorID(1), PubKey: pk1.Serialize()},
										// 					{OperatorID: spectypes.OperatorID(2), PubKey: pk2.Serialize()},
										// 				})
										// 			require.NoError(t, err)
										// 		})
										// 	}
										// 	p.Wait()
										// 	fmt.Println(time.Since(start))
										// 	total += time.Since(start)
										// }
										// fmt.Println("avg", total/10)

										f, err := os.Create("./cpu.pprof")
										require.NoError(t, err)
										defer f.Close()
										pprof.StartCPUProfile(f)
										defer pprof.StopCPUProfile()

										var wg sync.WaitGroup
										duration := time.Millisecond * time.Duration(total_duration)
										var total time.Duration
										start := time.Now()
										tm := tachymeter.New(&tachymeter.Config{Size: N, HBins: 10})
										sleep_list := make([]int64, N)

										for i := 0; i < N; i++ {
											i := i
											wg.Add(1)
											go func() {
												defer wg.Done()
												// Sleep random value between 0 and 12 seconds
												start2 := time.Now()
												sleep := time.Duration(0)
												if do_sleep {
													if !use_normal_dist {
														sleep = time.Duration(rand.Intn(int(duration)))
													} else {
														sleep = time.Duration(rand.NormFloat64()*50*float64(time.Millisecond) + float64(duration)/4)
													}
													if sleep > duration {
														sleep = duration
													}
													if sleep < 0 {
														sleep = 0
													}
													time.Sleep(sleep)
													sleep_list[i] = sleep.Milliseconds()
												}

												signed := msgs[i]
												types.VerifyByOperators(signed.GetSignature(), signed, networkconfig.TestNetwork.Domain, spectypes.QBFTSignatureType,
													[]*spectypes.Operator{
														{OperatorID: spectypes.OperatorID(1), PubKey: pk1.Serialize()},
														{OperatorID: spectypes.OperatorID(2), PubKey: pk2.Serialize()},
													})
												require.NoError(t, err)
												dur := time.Since(start2) - sleep
												total += dur
												tm.AddTime(dur)
											}()
										}
										wg.Wait()

										total_time := time.Since(start)
										avg_latency := total / time.Duration(N)

										// fmt.Println("Total Run Time:", total_time)
										// fmt.Println("Average Latency:", avg_latency)
										// b, _ := json.MarshalIndent(types.Verifier.Stats(), "", "  ")
										// fmt.Println("Stats:", string(b))
										// fmt.Println(tm.Calc())
										// fmt.Println(tm.Calc().Histogram)

										metrics := tm.Calc()
										cumulative := metrics.Time.Cumulative.Milliseconds()
										hmean := metrics.Time.HMean.Milliseconds()
										avg := metrics.Time.Avg.Milliseconds()
										p50 := metrics.Time.P50.Milliseconds()
										p75 := metrics.Time.P75.Milliseconds()
										p95 := metrics.Time.P95.Milliseconds()
										p99 := metrics.Time.P99.Milliseconds()
										p999 := metrics.Time.P999.Milliseconds()
										Long5 := metrics.Time.Long5p.Milliseconds()
										Short5 := metrics.Time.Short5p.Milliseconds()
										MaxM := metrics.Time.Max.Milliseconds()
										MinM := metrics.Time.Min.Milliseconds()
										RangM := metrics.Time.Range.Milliseconds()
										StdDevM := metrics.Time.StdDev.Milliseconds()
										RateSec := metrics.Rate.Second
										HistogramM := metrics.Histogram
										HitogramBinSize := metrics.HistogramBinSize
										Samples := metrics.Samples
										Count := metrics.Count

										total_requests := types.Verifier.Stats().TotalRequests
										dup_requests := types.Verifier.Stats().DuplicateRequests
										total_batches := types.Verifier.Stats().TotalBatches
										avg_batch_size := types.Verifier.Stats().AverageBatchSize
										pending_req := types.Verifier.Stats().PendingRequests
										pending_batches := types.Verifier.Stats().PendingBatches
										busy_workers := types.Verifier.Stats().BusyWorkers
										failed_batches := types.Verifier.Stats().FailedBatches
										failed_requests := types.Verifier.Stats().FailedRequests
										recent_batches := types.Verifier.Stats().RecentBatchSizes
										timeouts_triggered := types.Verifier.Stats().TimeoutsTriggered

										slices.Sort[int64](sleep_list)

										ans := fmt.Sprintf("Set(batch=%v,N=%v,timeout=%v,num_cpus=%v,sleep=%v,attack_p=%v, v = ", batch, N, timeout_time, num_cpus, do_sleep, attack_p)
										ans = ans + fmt.Sprintf("{\"total time\": %v,\"avg latency\": %v,\"cumulative\": %v,\"hmean\": %v,\"avg\": %v,\"p50\": %v,\"p75\": %v,\"p95\": %v,\"p99\": %v,\"p999\": %v,\"Long5\": %v,\"Short5\": %v,\"MaxM\": %v,\"MinM\": %v,\"RangM\": %v,\"StdDevM\": %v,\"RateSec\": %v,\"HistogramM\": %v,\"HistogramBinSize\": %v,\"Samples\": %v,\"Count\": %v,", total_time, avg_latency, cumulative, hmean, avg, p50, p75, p95, p99, p999, Long5, Short5, MaxM, MinM, RangM, StdDevM, RateSec, HistogramM, HitogramBinSize, Samples, Count)
										ans = ans + fmt.Sprintf("\"total requests\": %v,\"duplicated requests\": %v,\"total batches\": %v,\"avg batch size\": %v,\"pending requests\": %v,\"pending batches\": %v,\"busy workers\": %v,\"failed batches\": %v,\"failed requests\": %v,", total_requests, dup_requests, total_batches, avg_batch_size, pending_req, pending_batches, busy_workers, failed_batches, failed_requests)
										ans = ans + "\"recent batches\": " + strings.Replace(fmt.Sprintf("%v,", recent_batches), " ", ",", -1)

										sum_recent := 0
										for _, v := range recent_batches {
											sum_recent += int(v)
										}
										ans = ans + "\"recent batches avg\": " + fmt.Sprintf("%v,", (sum_recent)/len(recent_batches))
										ans = ans + "\"timeouts triggered\": " + fmt.Sprintf("%v,", (timeouts_triggered))

										if print_sleep_lst {
											ans = ans + "\"sleep list\": " + strings.Replace(fmt.Sprintf("%v,", sleep_list), " ", ",", -1)
										}
										ans = ans + "})\n"
										ans = strings.Replace(ans, "true", "True", -1)
										ans = strings.Replace(ans, "false", "False", -1)
										ans = strings.Replace(ans, "ms,", ",", -1)
										ans = strings.Replace(ans, "HistogramM\":", "HistogramM\":\"\"\"", -1)
										ans = strings.Replace(ans, ",\"HistogramBinSize\"", "\"\"\",\"HistogramBinSize\"", -1)
										ans = strings.Replace(ans, "µs,", "*pow(10,-3),", -1)
										ans = strings.Replace(ans, "s,", "*pow(10,3),", -1)
										ans = strings.Replace(ans, "NaN", "1", -1)
										f2.WriteString(ans)
										f2.Sync()
									}
								}
							}
						}
					}
				}
			}
		}
	})
}
