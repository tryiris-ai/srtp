//go:build openssl

// SPDX-FileCopyrightText: 2023 The Pion community <https://pion.ly>
// SPDX-License-Identifier: MIT
package srtp

import (
	"encoding/binary"
	"fmt"

	"github.com/pion/rtp"
	"github.com/spacemonkeygo/openssl"
)

var hasAnnouncedAesGcm = false

type srtpCipherAeadAesGcm struct {
	protectionProfileWithArgs
	srtpKey          []byte
	srtcpKey         []byte
	srtpSessionSalt  []byte
	srtcpSessionSalt []byte
	mki              []byte
	srtpEncrypted    bool
	srtcpEncrypted   bool
	useCryptex       bool
}

// aesCmKeyDerivationOpenSSL derives a key using AES-ECB (PRF) with OpenSSL.
// It is identical to the derivation used in the original Go implementation.
func aesCmKeyDerivationOpenSSL(label byte, masterKey, masterSalt []byte, outLen int) ([]byte, error) {
	nKey := len(masterKey)
	nSalt := len(masterSalt)

	// Choose the proper ECB cipher name
	var cipherName string
	switch nKey {
	case 16:
		cipherName = "aes-128-ecb"
	case 24:
		cipherName = "aes-192-ecb"
	case 32:
		cipherName = "aes-256-ecb"
	default:
		return nil, fmt.Errorf("unsupported master key length: %d", nKey)
	}

	ciph, err := openssl.GetCipherByName(cipherName)
	if err != nil {
		return nil, err
	}

	// Build the 16-byte block that will be encrypted repeatedly
	block := make([]byte, nKey)
	copy(block[:nSalt], masterSalt)
	block[7] ^= label // label is XOR-ed into byte 7 (as per RFC 3711)

	out := make([]byte, ((outLen+nKey-1)/nKey)*nKey)
	var i uint16
	for pos := 0; pos < len(out); pos += nKey {
		// copy block, inject counter i into the last two bytes
		input := make([]byte, nKey)
		copy(input, block)
		binary.BigEndian.PutUint16(input[nKey-2:], i)

		ctx, err := openssl.NewEncryptionCipherCtx(ciph, nil, masterKey, nil)
		if err != nil {
			return nil, err
		}
		enc, err := ctx.EncryptUpdate(input)
		if err != nil {
			return nil, err
		}
		fin, err := ctx.EncryptFinal()
		if err != nil {
			return nil, err
		}
		copy(out[pos:], append(enc, fin...))
		i++
	}
	return out[:outLen], nil
}

func newSrtpCipherAeadAesGcm(
	profile protectionProfileWithArgs,
	masterKey, masterSalt, mki []byte,
	encryptSRTP, encryptSRTCP, useCryptex bool,
) (*srtpCipherAeadAesGcm, error) {
	if !hasAnnouncedAesGcm {
		fmt.Println("INFO: Using OpenSSL based SRTP AES-GCM cipher.")
		hasAnnouncedAesGcm = true
	}

	c := &srtpCipherAeadAesGcm{
		protectionProfileWithArgs: profile,
		srtpEncrypted:             encryptSRTP,
		srtcpEncrypted:            encryptSRTCP,
		useCryptex:                useCryptex,
	}

	// ---- SRTP key ---------------------------------------------------------
	srtpKey, err := aesCmKeyDerivationOpenSSL(labelSRTPEncryption, masterKey, masterSalt, len(masterKey))
	if err != nil {
		return nil, err
	}
	c.srtpKey = srtpKey

	// ---- SRTCP key -------------------------------------------------------
	srtcpKey, err := aesCmKeyDerivationOpenSSL(labelSRTCPEncryption, masterKey, masterSalt, len(masterKey))
	if err != nil {
		return nil, err
	}
	c.srtcpKey = srtcpKey

	// ---- Salts -----------------------------------------------------------
	if c.srtpSessionSalt, err = aesCmKeyDerivationOpenSSL(labelSRTPSalt, masterKey, masterSalt, len(masterSalt)); err != nil {
		return nil, err
	}
	if c.srtcpSessionSalt, err = aesCmKeyDerivationOpenSSL(labelSRTCPSalt, masterKey, masterSalt, len(masterSalt)); err != nil {
		return nil, err
	}

	// ---- MKI -------------------------------------------------------------
	if len(mki) > 0 {
		c.mki = make([]byte, len(mki))
		copy(c.mki, mki)
	}
	return c, nil
}

/* --------------------------------------------------------------------- *
 *  RTP encryption / decryption (AES-GCM)
 * --------------------------------------------------------------------- */
func (s *srtpCipherAeadAesGcm) encryptRTP(
	dst []byte,
	header *rtp.Header,
	headerLen int,
	plaintext []byte,
	roc uint32,
	rocInAuthTag bool,
) (ciphertext []byte, err error) {

	authTagLen, err := s.AEADAuthTagLen()
	if err != nil {
		return nil, err
	}
	payloadLen := len(plaintext) - headerLen
	authPartLen := headerLen + payloadLen + authTagLen
	dstLen := authPartLen + len(s.mki)
	if rocInAuthTag {
		dstLen += 4
	}
	if needsEmptyExtensionHeader(s.useCryptex, header) {
		dstLen += extensionHeaderSize
	}
	dst = growBufferSize(dst, dstLen)

	sameBuffer := isSameBuffer(dst, plaintext)
	if needsEmptyExtensionHeader(s.useCryptex, header) {
		plaintext = insertEmptyExtensionHeader(dst, plaintext, sameBuffer, header)
		sameBuffer = true
		headerLen += extensionHeaderSize
	}

	if err = s.doEncryptRTP(dst, header, headerLen, plaintext, roc, rocInAuthTag, sameBuffer,
		payloadLen, authPartLen); err != nil {
		return nil, err
	}
	return dst, nil
}

func (s *srtpCipherAeadAesGcm) doEncryptRTP(
	dst []byte, header *rtp.Header, headerLen int, plaintext []byte, roc uint32,
	rocInAuthTag, sameBuffer bool, payloadLen, authPartLen int,
) error {

	iv := s.rtpInitializationVector(header, roc)
	keyBits := len(s.srtpKey) * 8

	encrypt := func(dst, src []byte, hLen int) error {
		aad := src[:hLen]
		payload := src[hLen:]
		ctx, err := openssl.NewGCMEncryptionCipherCtx(keyBits, nil, s.srtpKey, iv[:])
		if err != nil {
			return err
		}
		if err := ctx.ExtraData(aad); err != nil {
			return err
		}
		enc, err := ctx.EncryptUpdate(payload)
		if err != nil {
			return err
		}
		fin, err := ctx.EncryptFinal()
		if err != nil {
			return err
		}
		if len(fin) != 0 {
			return fmt.Errorf("unexpected final data in GCM encryption")
		}
		copy(dst[hLen:], enc)
		tag, err := ctx.GetTag()
		if err != nil {
			return err
		}
		copy(dst[hLen+len(enc):], tag)
		return nil
	}

	switch {
	case s.useCryptex && header.Extension:
		if err := encryptCryptexRTP(dst, plaintext, sameBuffer, header, encrypt); err != nil {
			return err
		}
	case s.srtpEncrypted:
		if !sameBuffer {
			copy(dst[:headerLen], plaintext[:headerLen])
		}
		if err := encrypt(dst, plaintext, headerLen); err != nil {
			return err
		}
	default: // not encrypted -> only auth tag over cleartext
		clearLen := headerLen + payloadLen
		if !sameBuffer {
			copy(dst[:clearLen], plaintext[:clearLen])
		}
		ctx, err := openssl.NewGCMEncryptionCipherCtx(keyBits, nil, s.srtpKey, iv[:])
		if err != nil {
			return err
		}
		aad := dst[:clearLen]
		if err := ctx.ExtraData(aad); err != nil {
			return err
		}
		if _, err := ctx.EncryptUpdate(nil); err != nil {
			return err
		}
		if _, err := ctx.EncryptFinal(); err != nil {
			return err
		}
		tag, err := ctx.GetTag()
		if err != nil {
			return err
		}
		copy(dst[clearLen:], tag)
	}

	// MKI
	if len(s.mki) > 0 {
		copy(dst[authPartLen:], s.mki)
	}
	// optional ROC in tag
	if rocInAuthTag {
		binary.BigEndian.PutUint32(dst[len(dst)-4:], roc)
	}
	return nil
}

func (s *srtpCipherAeadAesGcm) decryptRTP(
	dst, ciphertext []byte,
	header *rtp.Header,
	headerLen int,
	roc uint32,
	rocInAuthTag bool,
) ([]byte, error) {

	authTagLen, err := s.AEADAuthTagLen()
	if err != nil {
		return nil, err
	}
	rocLen := 0
	if rocInAuthTag {
		rocLen = 4
	}
	nDst := len(ciphertext) - authTagLen - len(s.mki) - rocLen
	if nDst < headerLen {
		return nil, ErrFailedToVerifyAuthTag
	}
	dst = growBufferSize(dst, nDst)

	sameBuffer := isSameBuffer(dst, ciphertext)
	nEnd := len(ciphertext) - len(s.mki) - rocLen
	if err = s.doDecryptRTP(dst, ciphertext, header, headerLen, roc, sameBuffer, nEnd, authTagLen); err != nil {
		return nil, err
	}
	return dst, nil
}

func (s *srtpCipherAeadAesGcm) doDecryptRTP(
	dst, ciphertext []byte, header *rtp.Header, headerLen int, roc uint32,
	sameBuffer bool, nEnd, authTagLen int,
) error {

	iv := s.rtpInitializationVector(header, roc)
	keyBits := len(s.srtpKey) * 8

	decrypt := func(dst, src []byte, hLen int) error {
		aad := src[:hLen]
		ctextLen := len(src) - hLen
		payloadLen := ctextLen - authTagLen
		encPayload := src[hLen : hLen+payloadLen]
		tag := src[hLen+payloadLen:]
		ctx, err := openssl.NewGCMDecryptionCipherCtx(keyBits, nil, s.srtpKey, iv[:])
		if err != nil {
			return err
		}
		if err := ctx.ExtraData(aad); err != nil {
			return err
		}
		dec, err := ctx.DecryptUpdate(encPayload)
		if err != nil {
			return err
		}
		if err := ctx.SetTag(tag); err != nil {
			return err
		}
		fin, err := ctx.DecryptFinal()
		if err != nil {
			return err
		}
		if len(fin) != 0 {
			return fmt.Errorf("unexpected final data in GCM decryption")
		}
		copy(dst[hLen:], dec)
		return nil
	}

	switch {
	case isCryptexPacket(header):
		if err := decryptCryptexRTP(dst, ciphertext, sameBuffer, header, headerLen, decrypt); err != nil {
			return fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
	case s.srtpEncrypted:
		if err := decrypt(dst, ciphertext[:nEnd], headerLen); err != nil {
			return fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
		if !sameBuffer {
			copy(dst[:headerLen], ciphertext[:headerLen])
		}
	default: // only auth tag, no payload encryption
		nDataEnd := nEnd - authTagLen
		aad := ciphertext[:nDataEnd]
		tag := ciphertext[nDataEnd:nEnd]
		ctx, err := openssl.NewGCMDecryptionCipherCtx(keyBits, nil, s.srtpKey, iv[:])
		if err != nil {
			return err
		}
		if err := ctx.ExtraData(aad); err != nil {
			return err
		}
		if _, err := ctx.DecryptUpdate(nil); err != nil {
			return err
		}
		if err := ctx.SetTag(tag); err != nil {
			return err
		}
		fin, err := ctx.DecryptFinal()
		if err != nil {
			return fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
		if len(fin) != 0 {
			return fmt.Errorf("%w: unexpected final data in GCM decryption", ErrFailedToVerifyAuthTag)
		}
		if !sameBuffer {
			copy(dst, ciphertext[:nDataEnd])
		}
	}
	return nil
}

/* --------------------------------------------------------------------- *
 *  RTCP encryption / decryption (AES-GCM)
 * --------------------------------------------------------------------- */
func (s *srtpCipherAeadAesGcm) encryptRTCP(dst, decrypted []byte, srtcpIndex uint32, ssrc uint32) ([]byte, error) {
	authTagLen, err := s.AEADAuthTagLen()
	if err != nil {
		return nil, err
	}
	aadPos := len(decrypted) + authTagLen
	dst = growBufferSize(dst, aadPos+srtcpIndexSize+len(s.mki))

	sameBuffer := isSameBuffer(dst, decrypted)
	iv := s.rtcpInitializationVector(srtcpIndex, ssrc)
	keyBits := len(s.srtcpKey) * 8

	if s.srtcpEncrypted {
		aad := s.rtcpAdditionalAuthenticatedData(decrypted, srtcpIndex)
		if !sameBuffer {
			copy(dst[:srtcpHeaderSize], decrypted[:srtcpHeaderSize])
		}
		ctx, err := openssl.NewGCMEncryptionCipherCtx(keyBits, nil, s.srtcpKey, iv[:])
		if err != nil {
			return nil, err
		}
		if err := ctx.ExtraData(aad[:]); err != nil {
			return nil, err
		}
		payload := decrypted[srtcpHeaderSize:]
		enc, err := ctx.EncryptUpdate(payload)
		if err != nil {
			return nil, err
		}
		fin, err := ctx.EncryptFinal()
		if err != nil {
			return nil, err
		}
		if len(fin) != 0 {
			return nil, fmt.Errorf("unexpected final data in GCM encryption")
		}
		copy(dst[srtcpHeaderSize:srtcpHeaderSize+len(enc)], enc)
		tag, err := ctx.GetTag()
		if err != nil {
			return nil, err
		}
		copy(dst[len(decrypted):len(decrypted)+len(tag)], tag)
		// Copy index to the proper place.
		copy(dst[aadPos:aadPos+srtcpIndexSize], aad[8:12])
	} else {
		if !sameBuffer {
			copy(dst, decrypted)
		}
		// Append the SRTCP index to the end of the packet - this will form the AAD.
		binary.BigEndian.PutUint32(dst[len(decrypted):], srtcpIndex)
		aad := dst[:len(decrypted)+srtcpIndexSize]
		ctx, err := openssl.NewGCMEncryptionCipherCtx(keyBits, nil, s.srtcpKey, iv[:])
		if err != nil {
			return nil, err
		}
		if err := ctx.ExtraData(aad); err != nil {
			return nil, err
		}
		if _, err := ctx.EncryptUpdate(nil); err != nil {
			return nil, err
		}
		if _, err := ctx.EncryptFinal(); err != nil {
			return nil, err
		}
		tag, err := ctx.GetTag()
		if err != nil {
			return nil, err
		}
		// Copy index to the proper place.
		copy(dst[aadPos:], dst[len(decrypted):len(decrypted)+srtcpIndexSize])
		// Copy the auth tag after RTCP payload.
		copy(dst[len(decrypted):len(decrypted)+len(tag)], tag)
	}
	copy(dst[aadPos+srtcpIndexSize:], s.mki)
	return dst, nil
}

func (s *srtpCipherAeadAesGcm) decryptRTCP(dst, encrypted []byte, srtcpIndex, ssrc uint32) ([]byte, error) {
	aadPos := len(encrypted) - srtcpIndexSize - len(s.mki)
	authTagLen, err := s.AEADAuthTagLen()
	if err != nil {
		return nil, err
	}
	nDst := aadPos - authTagLen
	if nDst < srtcpHeaderSize {
		return nil, errTooShortRTCP
	}
	dst = growBufferSize(dst, nDst)

	sameBuffer := isSameBuffer(dst, encrypted)
	isEncrypted := encrypted[aadPos]&srtcpEncryptionFlag != 0
	iv := s.rtcpInitializationVector(srtcpIndex, ssrc)
	keyBits := len(s.srtcpKey) * 8

	dataEnd := aadPos - authTagLen
	if isEncrypted {
		aad := s.rtcpAdditionalAuthenticatedData(encrypted, srtcpIndex)
		//payloadLen := dataEnd - srtcpHeaderSize
		encPayload := encrypted[srtcpHeaderSize:dataEnd]
		tag := encrypted[dataEnd:aadPos]
		ctx, err := openssl.NewGCMDecryptionCipherCtx(keyBits, nil, s.srtcpKey, iv[:])
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
		if err := ctx.ExtraData(aad[:]); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
		dec, err := ctx.DecryptUpdate(encPayload)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
		if err := ctx.SetTag(tag); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
		fin, err := ctx.DecryptFinal()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
		if len(fin) != 0 {
			return nil, fmt.Errorf("%w: unexpected final data in GCM decryption", ErrFailedToVerifyAuthTag)
		}
		copy(dst[srtcpHeaderSize:srtcpHeaderSize+len(dec)], dec)
	} else {
		aad := make([]byte, dataEnd+srtcpIndexSize)
		copy(aad, encrypted[:dataEnd])
		copy(aad[dataEnd:], encrypted[aadPos:aadPos+srtcpIndexSize])
		tag := encrypted[dataEnd:aadPos]
		ctx, err := openssl.NewGCMDecryptionCipherCtx(keyBits, nil, s.srtcpKey, iv[:])
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
		if err := ctx.ExtraData(aad); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
		if _, err := ctx.DecryptUpdate(nil); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
		if err := ctx.SetTag(tag); err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
		fin, err := ctx.DecryptFinal()
		if err != nil {
			return nil, fmt.Errorf("%w: %w", ErrFailedToVerifyAuthTag, err)
		}
		if len(fin) != 0 {
			return nil, fmt.Errorf("%w: unexpected final data in GCM decryption", ErrFailedToVerifyAuthTag)
		}
		if !sameBuffer {
			copy(dst[srtcpHeaderSize:], encrypted[srtcpHeaderSize:dataEnd])
		}
	}
	if !sameBuffer {
		copy(dst[:srtcpHeaderSize], encrypted[:srtcpHeaderSize])
	}
	return dst, nil
}

/* --------------------------------------------------------------------- *
 *  IV helpers (unchanged)
 * --------------------------------------------------------------------- */
func (s *srtpCipherAeadAesGcm) rtpInitializationVector(header *rtp.Header, roc uint32) [12]byte {
	var iv [12]byte
	binary.BigEndian.PutUint32(iv[2:], header.SSRC)
	binary.BigEndian.PutUint32(iv[6:], roc)
	binary.BigEndian.PutUint16(iv[10:], header.SequenceNumber)
	for i := range iv {
		iv[i] ^= s.srtpSessionSalt[i]
	}
	return iv
}

func (s *srtpCipherAeadAesGcm) rtcpInitializationVector(srtcpIndex uint32, ssrc uint32) [12]byte {
	var iv [12]byte
	binary.BigEndian.PutUint32(iv[2:], ssrc)
	binary.BigEndian.PutUint32(iv[8:], srtcpIndex)
	for i := range iv {
		iv[i] ^= s.srtcpSessionSalt[i]
	}
	return iv
}

func (s *srtpCipherAeadAesGcm) rtcpAdditionalAuthenticatedData(rtcpPacket []byte, srtcpIndex uint32) [12]byte {
	var aad [12]byte
	copy(aad[:], rtcpPacket[:8])
	binary.BigEndian.PutUint32(aad[8:], srtcpIndex)
	aad[8] |= srtcpEncryptionFlag
	return aad
}

func (s *srtpCipherAeadAesGcm) getRTCPIndex(in []byte) uint32 {
	return binary.BigEndian.Uint32(in[len(in)-len(s.mki)-srtcpIndexSize:]) &^ (srtcpEncryptionFlag << 24)
}
