// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

//! Calls the actual pinned legacy zkgroup crypto implementation. No proof or
//! credential equations are reproduced here.
use curve25519_dalek::scalar::Scalar;
use libsignal_core::Aci;
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Map, Value};
use zkgroup::{common::sho::Sho, crypto::*, deserialize, serialize, Timestamp};

// The upstream auth marker types are private, but AttrScalars is public. These
// marker-only adapters select their historical layouts in the real KeyPair code.
struct LegacyAuth;
impl credentials::AttrScalars for LegacyAuth {
    type Storage = [Scalar; 4];
    const NUM_ATTRS: usize = 3;
}
struct LegacyAuthWithPni;
impl credentials::AttrScalars for LegacyAuthWithPni {
    type Storage = [Scalar; 5];
}
fn array<const N: usize>(p: &Value, name: &str) -> Result<[u8; N], String> {
    super::param_bytes(p, name)?
        .try_into()
        .map_err(|_| format!("{name} length"))
}
fn put<T: Serialize>(out: &mut Map<String, Value>, name: &str, value: &T) {
    out.insert(name.into(), json!(hex::encode(serialize(value))));
}
fn read<T: DeserializeOwned + partial_default::PartialDefault>(
    p: &Value,
    name: &str,
) -> Result<T, String> {
    deserialize(&super::param_bytes(p, name)?).map_err(|e| e.to_string())
}
fn timestamp(p: &Value) -> Result<Timestamp, String> {
    Ok(Timestamp::from_epoch_seconds(
        p["timestamp"].as_u64().ok_or("missing timestamp")?,
    ))
}

pub fn generate(p: &Value) -> Result<Value, String> {
    let seed = array::<32>(p, "seed")?;
    let uuid = array(p, "uuid")?;
    let key = array(p, "profile_key")?;
    let serial = array(p, "serial")?;
    let message = super::param_bytes(p, "message")?;
    let expiration = timestamp(p)?;
    let level = p["level"].as_u64().ok_or("missing level")?;
    let mut sho = Sho::new(b"Compat_ZKGroup_Credentials", &seed);
    let mut out = Map::new();
    put(
        &mut out,
        "key_auth",
        &credentials::KeyPair::<LegacyAuth>::generate(&mut sho),
    );
    put(
        &mut out,
        "key_auth_pni",
        &credentials::KeyPair::<LegacyAuthWithPni>::generate(&mut sho),
    );
    put(
        &mut out,
        "key_profile",
        &credentials::KeyPair::<credentials::ProfileKeyCredential>::generate(&mut sho),
    );
    let server =
        credentials::KeyPair::<credentials::ExpiringProfileKeyCredential>::generate(&mut sho);
    put(&mut out, "key_expiring", &server);
    let receipt_server = credentials::KeyPair::<credentials::ReceiptCredential>::generate(&mut sho);
    put(&mut out, "key_receipt", &receipt_server);
    put(
        &mut out,
        "key_pni",
        &credentials::KeyPair::<credentials::PniCredential>::generate(&mut sho),
    );
    put(&mut out, "public_expiring", &server.get_public_key());
    put(&mut out, "public_receipt", &receipt_server.get_public_key());
    let signing = signature::KeyPair::generate(&mut sho);
    put(&mut out, "signing_key", &signing);
    put(&mut out, "signing_public", &signing.get_public_key());
    out.insert(
        "signature".into(),
        json!(hex::encode(signing.sign(&message, &mut sho))),
    );
    let uid = uid_struct::UidStruct::from_service_id(Aci::from_uuid_bytes(uuid).into());
    let profile = profile_key_struct::ProfileKeyStruct::new(key, uuid);
    let commitment = profile_key_commitment::CommitmentWithSecretNonce::new(profile, uuid);
    put(
        &mut out,
        "commitment",
        &commitment.get_profile_key_commitment(),
    );
    let request_key = profile_key_credential_request::KeyPair::generate(&mut sho);
    let request = request_key.encrypt(profile, &mut sho);
    put(&mut out, "request_key", &request_key);
    put(&mut out, "request_public", &request_key.get_public_key());
    put(&mut out, "request_with_nonce", &request);
    put(&mut out, "request", &request.get_ciphertext());
    let request_proof =
        proofs::ProfileKeyCredentialRequestProof::new(request_key, request, commitment, &mut sho);
    put(&mut out, "request_proof", &request_proof);
    let blinded = server.create_blinded_expiring_profile_key_credential(
        uid,
        request_key.get_public_key(),
        request.get_ciphertext(),
        expiration,
        &mut sho,
    );
    put(&mut out, "blinded_with_nonce", &blinded);
    put(
        &mut out,
        "blinded",
        &blinded.get_blinded_expiring_profile_key_credential(),
    );
    let issuance = proofs::ExpiringProfileKeyCredentialIssuanceProof::new(
        server,
        request_key.get_public_key(),
        request.get_ciphertext(),
        blinded,
        uid,
        expiration,
        &mut sho,
    );
    put(&mut out, "issuance_proof", &issuance);
    let credential = request_key.decrypt_blinded_expiring_profile_key_credential(
        blinded.get_blinded_expiring_profile_key_credential(),
    );
    put(&mut out, "credential", &credential);
    let uk = uid_encryption::KeyPair::derive_from(sho.as_mut());
    let pk = profile_key_encryption::KeyPair::derive_from(sho.as_mut());
    put(&mut out, "uid_key", &uk);
    put(&mut out, "profile_enc_key", &pk);
    put(&mut out, "uid_public", &uk.public_key);
    put(&mut out, "profile_enc_public", &pk.public_key);
    let uc = uk.encrypt(&uid);
    let pc = pk.encrypt(&profile);
    put(&mut out, "uid_ciphertext", &uc);
    put(&mut out, "profile_ciphertext", &pc);
    let presentation = proofs::ExpiringProfileKeyCredentialPresentationProof::new(
        uk,
        pk,
        server.get_public_key(),
        credential,
        uc,
        pc,
        uuid,
        key,
        &mut sho,
    );
    put(&mut out, "presentation", &presentation);
    let rk = receipt_credential_request::KeyPair::generate(&mut sho);
    let rc = rk.encrypt(serial, &mut sho);
    put(&mut out, "receipt_request_key", &rk);
    put(&mut out, "receipt_request_public", &rk.get_public_key());
    put(&mut out, "receipt_request_with_nonce", &rc);
    put(&mut out, "receipt_request", &rc.get_ciphertext());
    let rb = receipt_server.create_blinded_receipt_credential(
        rk.get_public_key(),
        rc.get_ciphertext(),
        expiration,
        level,
        &mut sho,
    );
    put(&mut out, "receipt_blinded_with_nonce", &rb);
    put(
        &mut out,
        "receipt_blinded",
        &rb.get_blinded_receipt_credential(),
    );
    let ri = proofs::ReceiptCredentialIssuanceProof::new(
        receipt_server,
        rk.get_public_key(),
        rc.get_ciphertext(),
        rb,
        expiration,
        level,
        &mut sho,
    );
    put(&mut out, "receipt_issuance", &ri);
    let credential = rk.decrypt_blinded_receipt_credential(rb.get_blinded_receipt_credential());
    put(&mut out, "receipt_credential", &credential);
    let rp = proofs::ReceiptCredentialPresentationProof::new(
        receipt_server.get_public_key(),
        credential,
        &mut sho,
    );
    put(&mut out, "receipt_presentation", &rp);
    let receipt = receipt_struct::ReceiptStruct::new(serial, expiration, level);
    put(&mut out, "receipt", &receipt);
    out.insert(
        "receipt_scalar".into(),
        json!(hex::encode(receipt.calc_m1().as_bytes())),
    );
    out.insert(
        "transcript_tail".into(),
        json!(hex::encode(sho.squeeze(32))),
    );
    Ok(Value::Object(out))
}

pub fn verify(p: &Value) -> Result<Value, String> {
    let a = &p["artifacts"];
    let uuid = array(p, "uuid")?;
    let receipt = receipt_struct::ReceiptStruct::new(
        array(p, "serial")?,
        timestamp(p)?,
        p["level"].as_u64().ok_or("missing level")?,
    );
    // Parse errors and failed proof verification both reject, without panicking.
    let signature = (|| -> Result<bool, String> {
        let key: signature::PublicKey = read(a, "signing_public")?;
        Ok(key
            .verify(&super::param_bytes(p, "message")?, array(a, "signature")?)
            .is_ok())
    })()
    .unwrap_or(false);
    let request = (|| -> Result<bool, String> {
        let proof: proofs::ProfileKeyCredentialRequestProof = read(a, "request_proof")?;
        Ok(proof
            .verify(
                read(a, "request_public")?,
                read(a, "request")?,
                read(a, "commitment")?,
            )
            .is_ok())
    })()
    .unwrap_or(false);
    let issuance = (|| -> Result<bool, String> {
        let proof: proofs::ExpiringProfileKeyCredentialIssuanceProof = read(a, "issuance_proof")?;
        Ok(proof
            .verify(
                read(a, "public_expiring")?,
                read(a, "request_public")?,
                uuid,
                read(a, "request")?,
                read(a, "blinded")?,
                timestamp(p)?,
            )
            .is_ok())
    })()
    .unwrap_or(false);
    let presentation = (|| -> Result<bool, String> {
        let proof: proofs::ExpiringProfileKeyCredentialPresentationProof = read(a, "presentation")?;
        Ok(proof
            .verify(
                read(a, "key_expiring")?,
                read(a, "uid_ciphertext")?,
                read(a, "uid_public")?,
                read(a, "profile_ciphertext")?,
                read(a, "profile_enc_public")?,
                timestamp(p)?,
            )
            .is_ok())
    })()
    .unwrap_or(false);
    let receipt_issuance = (|| -> Result<bool, String> {
        let proof: proofs::ReceiptCredentialIssuanceProof = read(a, "receipt_issuance")?;
        Ok(proof
            .verify(
                read(a, "public_receipt")?,
                read(a, "receipt_request_public")?,
                read(a, "receipt_request")?,
                read(a, "receipt_blinded")?,
                receipt,
            )
            .is_ok())
    })()
    .unwrap_or(false);
    let receipt_presentation = (|| -> Result<bool, String> {
        let proof: proofs::ReceiptCredentialPresentationProof = read(a, "receipt_presentation")?;
        Ok(proof.verify(read(a, "key_receipt")?, receipt).is_ok())
    })()
    .unwrap_or(false);
    Ok(
        json!({"signature":signature,"request":request,"issuance":issuance,"presentation":presentation,"receipt_issuance":receipt_issuance,"receipt_presentation":receipt_presentation}),
    )
}

pub fn vectors() -> Value {
    let cases:Vec<Value> = (0u8..24).map(|i| {
        let seed:Vec<u8>=(0u8..32).map(|j| i.wrapping_mul(17).wrapping_add(j)).collect();
        let uuid:Vec<u8>=(0u8..16).map(|j| i.wrapping_mul(13).wrapping_add(j)).collect();
        let key:Vec<u8>=(0u8..32).map(|j| i.wrapping_mul(7).wrapping_add(j)).collect();
        let serial=vec![i;16];
        let timestamp=match i {0=>0,1=>1,2=>u64::MAX,_=>1700000000+(i as u64)*86400};
        let level=match i {0=>0,1=>u64::MAX,_=>i as u64};
        let message=vec![i;i as usize*11];
        let params=json!({"seed":hex::encode(seed),"uuid":hex::encode(uuid),"profile_key":hex::encode(key),"serial":hex::encode(serial),"message":hex::encode(message),"timestamp":timestamp,"level":level});
        let result=generate(&params).expect("valid vector");
        let mut verification_params=params.clone(); verification_params["artifacts"]=result.clone();
        assert!(verify(&verification_params).unwrap().as_object().unwrap().values().all(|v|v==true));
        json!({"params":params,"result":result})
    }).collect();
    json!({"upstream_tag":"v0.102.2","source":"rust/zkgroup/src/crypto; actual upstream credential, request, signature and proof APIs","system":hex::encode(serialize(&credentials::SystemParams::get_hardcoded())),"cases":cases})
}
