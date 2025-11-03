// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT

package srtp

import ( //nolint:gci
	"crypto/subtle"
	"encoding/binary"
	"fmt"

	"github.com/pion/rtp"
	"github.com/spacemonkeygo/openssl"
)

type srtpCipherAesCmHmacSha1 struct {
	protectionProfileWithArgs

	srtpSessionSalt []byte
	srtpSessionAuth *openssl.HMAC
	srtpSessionKey  []byte
	srtpCipher      *openssl.Cipher
	srtpEncrypted   bool

	srtcpSessionSalt []byte
	srtcpSessionAuth *openssl.HMAC
	srtcpSessionKey  []byte
	srtcpCipher      *openssl.Cipher
	srtcpEncrypted   bool

	mki        []byte
	useCryptex bool
}

// aesCmKeyDerivation2 derives a key using AES in ECB mode with OpenSSL.
func aesCmKeyDerivation2(label byte, masterKey, masterSalt []byte, index int, outLen int) ([]byte, error) {
	if index != 0 {
		return nil, fmt.Errorf("non-zero index not supported")
	}
	nMasterKey := len(masterKey)
	nMasterSalt := len(masterSalt)

	var cipherName string
	switch nMasterKey {
	case 16:
		cipherName = "aes-128-ecb"
	case 24:
		cipherName = "aes-192-ecb"
	case 32:
		cipherName = "aes-256-ecb"
	default:
		return nil, fmt.Errorf("unsupported master key length: %d", nMasterKey)
	}

	c, err := openssl.GetCipherByName(cipherName)
	if err != nil {
		return nil, err
	}

	prfIn := make([]byte, nMasterKey)
	copy(prfIn[:nMasterSalt], masterSalt)
	prfIn[7] ^= label

	out := make([]byte, ((outLen+nMasterKey-1)/nMasterKey)*nMasterKey)
	var i uint16
	for n := 0; n < len(out); n += nMasterKey {
		copyPrfIn := make([]byte, nMasterKey)
		copy(copyPrfIn, prfIn)
		binary.BigEndian.PutUint16(copyPrfIn[nMasterKey-2:], i)

		ctx, err := openssl.NewEncryptionCipherCtx(c, nil, masterKey, nil)
		if err != nil {
			return nil, err
		}

		encrypted, err := ctx.EncryptUpdate(copyPrfIn)
		if err != nil {
			return nil, err
		}
		final, err := ctx.EncryptFinal()
		if err != nil {
			return nil, err
		}
		copy(out[n:], append(encrypted, final...))
		i++
	}
	return out[:outLen], nil
}

// aesCtrXOR performs AES-CTR encryption/decryption (XOR with keystream) using OpenSSL.
func aesCtrXOR(key, iv, in, out []byte, c *openssl.Cipher) error {
	ctx, err := openssl.NewEncryptionCipherCtx(c, nil, key, iv)
	if err != nil {
		return err
	}
	encrypted, err := ctx.EncryptUpdate(in)
	if err != nil {
		return err
	}
	final, err := ctx.EncryptFinal()
	if err != nil {
		return err
	}
	copy(out, append(encrypted, final...))
	return nil
}

var hasAnnounced = false

//nolint:cyclop
func newSrtpCipherAesCmHmacSha1(
	profile protectionProfileWithArgs,
	masterKey, masterSalt, mki []byte,
	encryptSRTP, encryptSRTCP, useCryptex bool,
) (*srtpCipherAesCmHmacSha1, error) {

	if !hasAnnounced {
		fmt.Println("INFO: Using OpenSSL based SRTP cipher.")
		hasAnnounced = true
	}

	switch profile.ProtectionProfile {
	case ProtectionProfileNullHmacSha1_80, ProtectionProfileNullHmacSha1_32:
		encryptSRTP = false
		encryptSRTCP = false
	default:
	}

	srtpCipher := &srtpCipherAesCmHmacSha1{
		protectionProfileWithArgs: profile,
		srtpEncrypted:             encryptSRTP,
		srtcpEncrypted:            encryptSRTCP,
		useCryptex:                useCryptex,
	}

	srtpSessionKey, err := aesCmKeyDerivation2(labelSRTPEncryption, masterKey, masterSalt, 0, len(masterKey))
	if err != nil {
		return nil, err
	}
	srtpCipher.srtpSessionKey = srtpSessionKey

	srtcpSessionKey, err := aesCmKeyDerivation2(labelSRTCPEncryption, masterKey, masterSalt, 0, len(masterKey))
	if err != nil {
		return nil, err
	}
	srtpCipher.srtcpSessionKey = srtcpSessionKey

	if srtpCipher.srtpSessionSalt, err = aesCmKeyDerivation2(
		labelSRTPSalt, masterKey, masterSalt, 0, len(masterSalt),
	); err != nil {
		return nil, err
	} else if srtpCipher.srtcpSessionSalt, err = aesCmKeyDerivation2(
		labelSRTCPSalt, masterKey, masterSalt, 0, len(masterSalt),
	); err != nil {
		return nil, err
	}

	authKeyLen, err := profile.AuthKeyLen()
	if err != nil {
		return nil, err
	}

	srtpSessionAuthTag, err := aesCmKeyDerivation2(labelSRTPAuthenticationTag, masterKey, masterSalt, 0, authKeyLen)
	if err != nil {
		return nil, err
	}

	srtcpSessionAuthTag, err := aesCmKeyDerivation2(labelSRTCPAuthenticationTag, masterKey, masterSalt, 0, authKeyLen)
	if err != nil {
		return nil, err
	}

	srtpCipher.srtcpSessionAuth, err = openssl.NewHMAC(srtcpSessionAuthTag, openssl.EVP_SHA1)
	if err != nil {
		return nil, err
	}

	srtpCipher.srtpSessionAuth, err = openssl.NewHMAC(srtpSessionAuthTag, openssl.EVP_SHA1)
	if err != nil {
		return nil, err
	}

	var cipherName string
	switch len(srtpSessionKey) {
	case 16:
		cipherName = "aes-128-ctr"
	case 24:
		cipherName = "aes-192-ctr"
	case 32:
		cipherName = "aes-256-ctr"
	default:
		return nil, fmt.Errorf("unsupported key length: %d", len(srtpSessionKey))
	}

	srtpCipher.srtpCipher, err = openssl.GetCipherByName(cipherName)
	if err != nil {
		return nil, err
	}

	srtpCipher.srtcpCipher, err = openssl.GetCipherByName(cipherName)
	if err != nil {
		return nil, err
	}

	mkiLen := len(mki)
	if mkiLen > 0 {
		srtpCipher.mki = make([]byte, mkiLen)
		copy(srtpCipher.mki, mki)
	}

	return srtpCipher, nil
}

func (s *srtpCipherAesCmHmacSha1) encryptRTP(
	dst []byte,
	header *rtp.Header,
	headerLen int,
	plaintext []byte,
	roc uint32,
	rocInAuthTag bool,
) (ciphertext []byte, err error) {
	// Grow the given buffer to fit the output.
	authTagLen, err := s.AuthTagRTPLen()
	if err != nil {
		return nil, err
	}
	payloadLen := len(plaintext) - headerLen
	dstLen := headerLen + payloadLen + len(s.mki) + authTagLen
	insertEmptyExtHdr := needsEmptyExtensionHeader(s.useCryptex, header)
	if insertEmptyExtHdr {
		dstLen += extensionHeaderSize
	}
	dst = growBufferSize(dst, dstLen)
	sameBuffer := isSameBuffer(dst, plaintext)
	if insertEmptyExtHdr {
		// Insert an empty extension header to plaintext using dst buffer. After this operation dst is used as the
		// plaintext buffer for next operations.
		plaintext = insertEmptyExtensionHeader(dst, plaintext, sameBuffer, header)
		sameBuffer = true
		headerLen += extensionHeaderSize
	}
	err = s.doEncryptRTP(dst, header, headerLen, plaintext, roc, rocInAuthTag, sameBuffer, payloadLen)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

func (s *srtpCipherAesCmHmacSha1) doEncryptRTP(dst []byte, header *rtp.Header, headerLen int, plaintext []byte,
	roc uint32, rocInAuthTag bool, sameBuffer bool, payloadLen int,
) error {
	encrypt := func(dst, plaintext []byte, headerLen int) error {
		counter := generateCounter(header.SequenceNumber, roc, header.SSRC, s.srtpSessionSalt)
		return aesCtrXOR(s.srtpSessionKey, counter[:], plaintext[headerLen:], dst[headerLen:], s.srtpCipher)
	}
	var err error
	switch {
	case s.useCryptex && header.Extension:
		err = encryptCryptexRTP(dst, plaintext, sameBuffer, header, encrypt)
	case s.srtpEncrypted:
		// Copy the header unencrypted.
		if !sameBuffer {
			copy(dst, plaintext[:headerLen])
		}
		// Encrypt the payload
		err = encrypt(dst, plaintext, headerLen)
	case !sameBuffer:
		copy(dst, plaintext)
	default:
	}
	if err != nil {
		return err
	}
	n := headerLen + payloadLen
	// Generate the auth tag.
	authTag, err := s.generateSrtpAuthTag(dst[:n], roc, rocInAuthTag)
	if err != nil {
		return err
	}
	// Append the MKI (if used)
	if len(s.mki) > 0 {
		copy(dst[n:], s.mki)
		n += len(s.mki)
	}
	// Write the auth tag to the dest.
	copy(dst[n:], authTag)
	return nil
}

func (s *srtpCipherAesCmHmacSha1) decryptRTP(
	dst, ciphertext []byte,
	header *rtp.Header,
	headerLen int,
	roc uint32,
	rocInAuthTag bool,
) ([]byte, error) {
	// Split the auth tag and the cipher text into two parts.
	authTagLen, err := s.AuthTagRTPLen()
	if err != nil {
		return nil, err
	}
	// Split the auth tag and the cipher text into two parts.
	actualTag := ciphertext[len(ciphertext)-authTagLen:]
	ciphertext = ciphertext[:len(ciphertext)-len(s.mki)-authTagLen]
	// Generate the auth tag we expect to see from the ciphertext.
	expectedTag, err := s.generateSrtpAuthTag(ciphertext, roc, rocInAuthTag)
	if err != nil {
		return nil, err
	}
	// See if the auth tag actually matches.
	// We use a constant time comparison to prevent timing attacks.
	if subtle.ConstantTimeCompare(actualTag, expectedTag) != 1 {
		return nil, ErrFailedToVerifyAuthTag
	}
	sameBuffer := isSameBuffer(dst, ciphertext)
	err = s.doDecryptRTP(dst, ciphertext, header, headerLen, roc, sameBuffer)
	if err != nil {
		return nil, err
	}
	return dst, nil
}

func (s *srtpCipherAesCmHmacSha1) doDecryptRTP(dst, ciphertext []byte, header *rtp.Header, headerLen int, roc uint32,
	sameBuffer bool,
) error {
	decrypt := func(dst, ciphertext []byte, headerLen int) error {
		counter := generateCounter(header.SequenceNumber, roc, header.SSRC, s.srtpSessionSalt)
		return aesCtrXOR(s.srtpSessionKey, counter[:], ciphertext[headerLen:], dst[headerLen:], s.srtpCipher)
	}
	switch {
	case isCryptexPacket(header):
		err := decryptCryptexRTP(dst, ciphertext, sameBuffer, header, headerLen, decrypt)
		if err != nil {
			return err
		}
	case s.srtpEncrypted:
		// Write the plaintext header to the destination buffer.
		if !sameBuffer {
			copy(dst, ciphertext[:headerLen])
		}
		// Decrypt the ciphertext for the payload.
		err := decrypt(dst, ciphertext, headerLen)
		if err != nil {
			return err
		}
	case !sameBuffer:
		copy(dst, ciphertext)
	default:
	}
	return nil
}

func (s *srtpCipherAesCmHmacSha1) encryptRTCP(dst, decrypted []byte, srtcpIndex uint32, ssrc uint32) ([]byte, error) {
	authTagLen, err := s.AuthTagRTCPLen()
	if err != nil {
		return nil, err
	}
	mkiLen := len(s.mki)
	decryptedLen := len(decrypted)
	encryptedLen := decryptedLen + authTagLen + mkiLen + srtcpIndexSize
	dst = growBufferSize(dst, encryptedLen)
	sameBuffer := isSameBuffer(dst, decrypted)
	if !sameBuffer {
		copy(dst, decrypted[:srtcpHeaderSize]) // Copy the first 8 bytes (RTCP header)
	}
	// Encrypt everything after header
	if s.srtcpEncrypted {
		counter := generateCounter(uint16(srtcpIndex&0xffff), srtcpIndex>>16, ssrc, s.srtcpSessionSalt) //nolint:gosec // G115
		if err = aesCtrXOR(s.srtcpSessionKey, counter[:], decrypted[srtcpHeaderSize:], dst[srtcpHeaderSize:], s.srtcpCipher); err != nil {
			return nil, err
		}
		// Add SRTCP Index and set Encryption bit
		binary.BigEndian.PutUint32(dst[decryptedLen:], srtcpIndex)
		dst[decryptedLen] |= srtcpEncryptionFlag
	} else {
		// Copy the decrypted payload as is
		if !sameBuffer {
			copy(dst[srtcpHeaderSize:], decrypted[srtcpHeaderSize:])
		}
		// Add SRTCP Index with Encryption bit cleared
		binary.BigEndian.PutUint32(dst[decryptedLen:], srtcpIndex)
	}
	n := decryptedLen + srtcpIndexSize
	// Generate the authentication tag
	authTag, err := s.generateSrtcpAuthTag(dst[:n])
	if err != nil {
		return nil, err
	}
	// Include the MKI if provided
	if len(s.mki) > 0 {
		copy(dst[n:], s.mki)
		n += mkiLen
	}
	// Append the auth tag at the end of the buffer
	copy(dst[n:], authTag)
	return dst, nil
}

func (s *srtpCipherAesCmHmacSha1) decryptRTCP(dst, encrypted []byte, index, ssrc uint32) ([]byte, error) {
	authTagLen, err := s.AuthTagRTCPLen()
	if err != nil {
		return nil, err
	}
	mkiLen := len(s.mki)
	encryptedLen := len(encrypted)
	decryptedLen := encryptedLen - (authTagLen + mkiLen + srtcpIndexSize)
	if decryptedLen < 8 {
		return nil, errTooShortRTCP
	}
	expectedTag, err := s.generateSrtcpAuthTag(encrypted[:encryptedLen-mkiLen-authTagLen])
	if err != nil {
		return nil, err
	}
	actualTag := encrypted[encryptedLen-authTagLen:]
	if subtle.ConstantTimeCompare(actualTag, expectedTag) != 1 {
		return nil, ErrFailedToVerifyAuthTag
	}
	dst = growBufferSize(dst, decryptedLen)
	sameBuffer := isSameBuffer(dst, encrypted)
	if !sameBuffer {
		copy(dst, encrypted[:srtcpHeaderSize]) // Copy the first 8 bytes (RTCP header)
	}
	isEncrypted := encrypted[decryptedLen]&srtcpEncryptionFlag != 0
	if isEncrypted {
		counter := generateCounter(uint16(index&0xffff), index>>16, ssrc, s.srtcpSessionSalt) //nolint:gosec // G115
		err = aesCtrXOR(s.srtcpSessionKey, counter[:], encrypted[srtcpHeaderSize:decryptedLen], dst[srtcpHeaderSize:], s.srtcpCipher)
	} else if !sameBuffer {
		copy(dst[srtcpHeaderSize:], encrypted[srtcpHeaderSize:])
	}
	return dst, err
}

func (s *srtpCipherAesCmHmacSha1) generateSrtpAuthTag(buf []byte, roc uint32, rocInAuthTag bool) ([]byte, error) {
	s.srtpSessionAuth.Reset()
	if _, err := s.srtpSessionAuth.Write(buf); err != nil {
		return nil, err
	}
	// For SRTP only, we need to hash the rollover counter as well.
	rocRaw := [4]byte{}
	binary.BigEndian.PutUint32(rocRaw[:], roc)
	_, err := s.srtpSessionAuth.Write(rocRaw[:])
	if err != nil {
		return nil, err
	}
	mac, err := s.srtpSessionAuth.Final()
	if err != nil {
		return nil, err
	}
	// Truncate the hash to the size indicated by the profile
	authTagLen, err := s.AuthTagRTPLen()
	if err != nil {
		return nil, err
	}
	var authTag []byte
	if rocInAuthTag {
		authTag = append(authTag, rocRaw[:]...)
	}
	authTag = append(authTag, mac...)
	return authTag[0:authTagLen], nil
}

func (s *srtpCipherAesCmHmacSha1) generateSrtcpAuthTag(buf []byte) ([]byte, error) {
	s.srtcpSessionAuth.Reset()
	if _, err := s.srtcpSessionAuth.Write(buf); err != nil {
		return nil, err
	}
	mac, err := s.srtcpSessionAuth.Final()
	if err != nil {
		return nil, err
	}
	authTagLen, err := s.AuthTagRTCPLen()
	if err != nil {
		return nil, err
	}
	return mac[0:authTagLen], nil
}

func (s *srtpCipherAesCmHmacSha1) getRTCPIndex(in []byte) uint32 {
	authTagLen, _ := s.AuthTagRTCPLen()
	tailOffset := len(in) - (authTagLen + srtcpIndexSize + len(s.mki))
	srtcpIndexBuffer := in[tailOffset : tailOffset+srtcpIndexSize]
	return binary.BigEndian.Uint32(srtcpIndexBuffer) &^ (1 << 31)
}
