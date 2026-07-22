use crate::{
    MlsSpecError, SensitiveBytes, Serializable, ToPrefixedLabel,
    crypto::{HpkeCiphertext, HpkeKeyPair, SignContent, SignatureKeyPair},
    defs::{CiphersuiteId, ProtocolVersion, labels::SignatureLabel},
};

pub trait MlsCryptoProvider {
    type Error: From<MlsSpecError>;

    #[inline]
    fn kdf_len(&self, ciphersuite: CiphersuiteId) -> usize {
        self.hash_len(ciphersuite)
    }

    fn hash_len(&self, ciphersuite: CiphersuiteId) -> usize;
    fn key_len(&self, ciphersuite: CiphersuiteId) -> usize;
    fn aead_tag_len(&self, ciphersuite: CiphersuiteId) -> usize;
    fn aead_key_len(&self, ciphersuite: CiphersuiteId) -> usize;
    fn aead_nonce_len(&self, ciphersuite: CiphersuiteId) -> usize;

    fn gen_keypair(
        &self,
        ciphersuite: CiphersuiteId,
        csprng: &mut dyn rand_core::TryCryptoRng<Error = Self::Error>,
    ) -> SignatureKeyPair<'_>;

    fn keypair_from_sk(
        &self,
        ciphersuite: CiphersuiteId,
        sk: SensitiveBytes<'_>,
    ) -> Result<SignatureKeyPair<'_>, Self::Error>;

    // Signatures
    fn sign_raw(
        &self,
        ciphersuite: CiphersuiteId,
        signature_key: &[u8],
        message: &[u8],
    ) -> Result<SensitiveBytes<'_>, Self::Error>;
    fn verify_raw(
        &self,
        ciphersuite: CiphersuiteId,
        verification_key: &[u8],
        payload: &[u8],
        signature: &[u8],
    ) -> bool;
    // HPKE
    fn hpke_seal(
        &self,
        ciphersuite: CiphersuiteId,
        public_key: &[u8],
        info: &[u8],
        aad: &[u8],
        plaintext: &[u8],
        csprng: &mut dyn rand_core::TryCryptoRng<Error = Self::Error>,
    ) -> Result<HpkeCiphertext<'_>, Self::Error>;
    fn hpke_open(
        &self,
        ciphersuite: CiphersuiteId,
        private_key: &[u8],
        encapped_key: &[u8],
        info: &[u8],
        aad: &[u8],
        ciphertext: &[u8],
    ) -> Result<SensitiveBytes<'_>, Self::Error>;
    fn hpke_export_sender(
        &self,
        ciphersuite: CiphersuiteId,
        public_key: &[u8],
        info: &[u8],
        export_info: &[u8],
        csprng: &mut dyn rand_core::TryCryptoRng<Error = Self::Error>,
    ) -> Result<SensitiveBytes<'_>, Self::Error>;
    fn hpke_export_receiver(
        &self,
        ciphersuite: CiphersuiteId,
        private_key: &[u8],
        kem_output: &[u8],
        info: &[u8],
        export_info: &[u8],
    ) -> Result<SensitiveBytes<'_>, Self::Error>;
    fn hpke_gen_keypair(
        &self,
        ciphersuite: CiphersuiteId,
        csprng: &mut dyn rand_core::TryCryptoRng<Error = Self::Error>,
    ) -> Result<HpkeKeyPair<'_>, Self::Error>;
    fn hpke_keypair_from_sk(
        &self,
        ciphersuite: CiphersuiteId,
        sk: &[u8],
    ) -> Result<HpkeKeyPair<'_>, Self::Error>;
    fn hpke_derive_keypair(
        &self,
        ciphersuite: CiphersuiteId,
        external_secret: &[u8],
    ) -> HpkeKeyPair<'_>;
    fn hpke_kem_id(&self, ciphersuite: CiphersuiteId) -> u16;

    // AEAD
    fn aead_encrypt(
        &self,
        ciphersuite: CiphersuiteId,
        key: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
        plaintext: &[u8],
    ) -> Result<SensitiveBytes<'_>, Self::Error>;
    fn aead_decrypt(
        &self,
        ciphersuite: CiphersuiteId,
        key: &[u8],
        nonce: &[u8],
        aad: Option<&[u8]>,
        ciphertext: &[u8],
    ) -> Result<SensitiveBytes<'_>, Self::Error>;

    // Hashes
    fn hash(&self, ciphersuite: CiphersuiteId, data: &[u8]) -> SensitiveBytes<'_>;
    fn hash_multi(&self, ciphersuite: CiphersuiteId, slices: &[&[u8]]) -> SensitiveBytes<'_>;
    // KDF
    fn hkdf_extract(
        &self,
        ciphersuite: CiphersuiteId,
        salt: Option<&[u8]>,
        ikm: &[u8],
    ) -> SensitiveBytes<'_>;
    // Same as hkdf_extract
    #[inline(always)]
    fn hmac(
        &self,
        ciphersuite: CiphersuiteId,
        salt: Option<&[u8]>,
        ikm: &[u8],
    ) -> SensitiveBytes<'_> {
        self.hkdf_extract(ciphersuite, salt, ikm)
    }
    fn hkdf_expand_from_prk(
        &self,
        ciphersuite: CiphersuiteId,
        prk: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<SensitiveBytes<'_>, Self::Error>;
    fn hkdf_expand(
        &self,
        ciphersuite: CiphersuiteId,
        salt: Option<&[u8]>,
        ikm: &[u8],
        info: &[u8],
        len: usize,
    ) -> Result<SensitiveBytes<'_>, Self::Error>;

    // Signing [spec:5.1.2]
    #[inline]
    fn sign(
        &self,
        ciphersuite: CiphersuiteId,
        signature_key: &[u8],
        content: SignContent<'_>,
    ) -> Result<SensitiveBytes<'_>, Self::Error> {
        self.sign_raw(ciphersuite, signature_key, &content.to_tls_bytes()?)
    }

    #[inline]
    fn verify(
        &self,
        ciphersuite: CiphersuiteId,
        verification_key: &[u8],
        content: SignContent<'_>,
        signature: &[u8],
    ) -> bool {
        let Ok(content) = content.to_tls_bytes() else {
            return false;
        };
        self.verify_raw(ciphersuite, verification_key, &content, signature)
    }

    #[inline]
    fn sign_with_label(
        &self,
        ciphersuite: CiphersuiteId,
        protocol_version: ProtocolVersion,
        signature_key: &[u8],
        label: SignatureLabel,
        content: &[u8],
    ) -> Result<SensitiveBytes<'_>, Self::Error> {
        let label = label.to_prefixed_string(protocol_version);
        let sign_content = SignContent {
            label: &label,
            content,
        };
        self.sign(ciphersuite, signature_key, sign_content)
    }

    #[inline]
    fn verify_with_label(
        &self,
        ciphersuite: CiphersuiteId,
        protocol_version: ProtocolVersion,
        key: &[u8],
        label: SignatureLabel,
        content: &[u8],
        signature: &[u8],
    ) -> bool {
        let label = label.to_prefixed_string(protocol_version);
        let sign_content = SignContent {
            label: &label,
            content,
        };
        self.verify(ciphersuite, key, sign_content, signature)
    }
}
