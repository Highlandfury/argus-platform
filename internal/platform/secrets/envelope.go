package secrets

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"strconv"
	"strings"
)

// Envelope wire format v1 (the data_enc column). The first byte is the format
// version, so future formats can evolve without ambiguity; every other header
// field is length- or algorithm-tagged.
//
//	offset  size  field
//	0       1     format version (1)
//	1       1     KEK wrap algorithm id (1 = AES-256-GCM)
//	2       1     DEK data algorithm id (1 = AES-256-GCM)
//	3       1     reserved (must be 0)
//	4       2     key version, uint16 big-endian (>= 1)
//	6       2     reserved (must be 0)
//	8       2     wrapped DEK length, uint16 big-endian (60 for v1)
//	10      n     wrapped DEK: 12-byte nonce || AES-256-GCM ciphertext+tag
//	10+n    12    data nonce
//	22+n    m     data ciphertext: AES-256-GCM ciphertext+tag over plaintext
//
// n = 60 for a 32-byte DEK (12 nonce + 32 key + 16 tag); m >= 16. Header size
// is 10 bytes. Both GCM layers use the canonical encryption context as AAD,
// domain-separated (see canonicalAAD), so a wrapped DEK or ciphertext cannot
// be moved to another context.
const (
	envelopeFormatV1 byte = 1
	algAES256GCM     byte = 1

	aesKeyLen = 32 // AES-256
	dekLen    = aesKeyLen

	nonceLen = 12
	tagLen   = 16

	headerLen       = 10
	wrappedDEKLenV1 = nonceLen + dekLen + tagLen // 60
)

// AAD domains separate the two GCM uses (KEK wrap vs data encryption).
const (
	aadDomainWrap = "argus-envelope-v1:kek"
	aadDomainData = "argus-envelope-v1:data"
)

func wrapAAD(c Context) []byte { return canonicalAAD(aadDomainWrap, c) }
func dataAAD(c Context) []byte { return canonicalAAD(aadDomainData, c) }

// canonicalAAD renders the encryption context in a stable, unambiguous byte
// form. The exact bytes are part of the stored format: changing them would
// make every existing envelope unreadable.
func canonicalAAD(domain string, c Context) []byte {
	var b strings.Builder
	b.WriteString(domain)
	b.WriteString("\norg_id=")
	b.WriteString(c.OrgID.String())
	b.WriteString("\nsecret_type=")
	b.WriteString(c.SecretType)
	b.WriteString("\nsecret_id=")
	b.WriteString(c.SecretID.String())
	b.WriteString("\nversion=")
	b.WriteString(strconv.Itoa(c.Version))
	return []byte(b.String())
}

// envelopeV1 is the decoded view of one data_enc blob. The byte slices alias
// the input and are never mutated.
type envelopeV1 struct {
	keyVersion int
	wrappedDEK []byte
	dataNonce  []byte
	ciphertext []byte
}

// encodeEnvelopeV1 assembles the v1 wire format. Arguments are validated so a
// malformed backend result cannot be stored.
func encodeEnvelopeV1(keyVersion int, wrappedDEK, dataNonce, ciphertext []byte) ([]byte, error) {
	if keyVersion <= 0 || keyVersion > 0xffff {
		return nil, fmt.Errorf("%w: key version %d out of range", ErrMalformedEnvelope, keyVersion)
	}
	if len(wrappedDEK) != wrappedDEKLenV1 {
		return nil, fmt.Errorf("%w: wrapped dek is %d bytes, want %d", ErrMalformedEnvelope, len(wrappedDEK), wrappedDEKLenV1)
	}
	if len(dataNonce) != nonceLen {
		return nil, fmt.Errorf("%w: data nonce is %d bytes, want %d", ErrMalformedEnvelope, len(dataNonce), nonceLen)
	}
	if len(ciphertext) < tagLen {
		return nil, fmt.Errorf("%w: ciphertext is %d bytes, want >= %d", ErrMalformedEnvelope, len(ciphertext), tagLen)
	}

	buf := make([]byte, headerLen, headerLen+len(wrappedDEK)+len(dataNonce)+len(ciphertext))
	buf[0] = envelopeFormatV1
	buf[1] = algAES256GCM
	buf[2] = algAES256GCM
	// buf[3] reserved = 0
	binary.BigEndian.PutUint16(buf[4:6], uint16(keyVersion))
	// buf[6:8] reserved = 0
	binary.BigEndian.PutUint16(buf[8:10], wrappedDEKLenV1)
	buf = append(buf, wrappedDEK...)
	buf = append(buf, dataNonce...)
	buf = append(buf, ciphertext...)
	return buf, nil
}

// decodeEnvelope parses data_enc, validating every structural field. Unknown
// format versions fail with ErrUnsupportedVersion.
func decodeEnvelope(data []byte) (envelopeV1, error) {
	if len(data) < headerLen {
		return envelopeV1{}, fmt.Errorf("%w: %d bytes is shorter than the %d-byte header", ErrMalformedEnvelope, len(data), headerLen)
	}
	if data[0] != envelopeFormatV1 {
		return envelopeV1{}, fmt.Errorf("%w: got %d, supported: %d", ErrUnsupportedVersion, data[0], envelopeFormatV1)
	}
	if data[1] != algAES256GCM || data[2] != algAES256GCM {
		return envelopeV1{}, fmt.Errorf("%w: unsupported algorithm ids %d/%d", ErrMalformedEnvelope, data[1], data[2])
	}
	if data[3] != 0 || binary.BigEndian.Uint16(data[6:8]) != 0 {
		return envelopeV1{}, fmt.Errorf("%w: reserved header bytes are not zero", ErrMalformedEnvelope)
	}
	keyVersion := int(binary.BigEndian.Uint16(data[4:6]))
	if keyVersion <= 0 {
		return envelopeV1{}, fmt.Errorf("%w: key version must be positive", ErrMalformedEnvelope)
	}
	wrappedLen := int(binary.BigEndian.Uint16(data[8:10]))
	if wrappedLen != wrappedDEKLenV1 {
		return envelopeV1{}, fmt.Errorf("%w: wrapped dek length %d, want %d", ErrMalformedEnvelope, wrappedLen, wrappedDEKLenV1)
	}
	total := headerLen + wrappedLen + nonceLen + tagLen
	if len(data) < total {
		return envelopeV1{}, fmt.Errorf("%w: %d bytes is shorter than the minimum %d", ErrMalformedEnvelope, len(data), total)
	}
	wrapped := data[headerLen : headerLen+wrappedLen]
	nonce := data[headerLen+wrappedLen : headerLen+wrappedLen+nonceLen]
	return envelopeV1{
		keyVersion: keyVersion,
		wrappedDEK: wrapped,
		dataNonce:  nonce,
		ciphertext: data[headerLen+wrappedLen+nonceLen:],
	}, nil
}

// sealGCM encrypts plaintext under key with a fresh random nonce and returns
// the nonce plus ciphertext (including the GCM tag).
func sealGCM(key, aad, plaintext []byte) ([]byte, []byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, nil, err
	}
	nonce := make([]byte, nonceLen)
	if _, err := rand.Read(nonce); err != nil {
		return nil, nil, fmt.Errorf("secrets: generate nonce: %w", err)
	}
	return nonce, gcm.Seal(nil, nonce, plaintext, aad), nil
}

// openGCM reverses sealGCM. All authentication failures collapse to
// ErrAuthentication without echoing any input material.
func openGCM(key, aad, nonce, ciphertext []byte) ([]byte, error) {
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	if len(nonce) != nonceLen || len(ciphertext) < tagLen {
		return nil, fmt.Errorf("%w: bad nonce/ciphertext length", ErrMalformedEnvelope)
	}
	plaintext, err := gcm.Open(nil, nonce, ciphertext, aad)
	if err != nil {
		return nil, ErrAuthentication
	}
	return plaintext, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	if len(key) != aesKeyLen {
		return nil, fmt.Errorf("secrets: AES-256 requires a %d-byte key, got %d", aesKeyLen, len(key))
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, fmt.Errorf("secrets: cipher: %w", err)
	}
	return cipher.NewGCM(block)
}
