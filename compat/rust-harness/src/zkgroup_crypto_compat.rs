// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 8.2 oracle: actual upstream crypto APIs, with GroupSecretParams used
//! for decryption because the raw domain decrypt methods are pub(crate).
use curve25519_dalek::ristretto::{CompressedRistretto, RistrettoPoint};
use libsignal_core::{Aci, Pni, ServiceId};
use serde_json::{json, Value};
use zkgroup::{crypto, groups, serialize, Timestamp};

fn array<const N: usize>(p: &Value, name: &str) -> Result<[u8; N], String> {
    super::param_bytes(p, name)?
        .try_into()
        .map_err(|_| format!("{name} length"))
}

fn group(p: &Value) -> Result<groups::GroupSecretParams, String> {
    Ok(groups::GroupSecretParams::derive_from_master_key(
        groups::GroupMasterKey::new(array(p, "seed")?),
    ))
}

pub fn dispatch(method: &str, p: &Value) -> Result<Value, String> {
    match method {
        "zkgroup.crypto" => {
            let group = group(p)?;
            let uuid = array(p, "uuid")?;
            let key = array(p, "profile_key")?;
            let aci = Aci::from_uuid_bytes(uuid);
            let id: ServiceId = if p["pni"].as_bool().ok_or("missing pni")? {
                Pni::from_uuid_bytes(uuid).into()
            } else {
                aci.into()
            };
            let seconds = p["timestamp"].as_u64().ok_or("missing timestamp")?;
            let timestamp = crypto::timestamp_struct::TimestampStruct::new(
                Timestamp::from_epoch_seconds(seconds),
            );
            let uid = crypto::uid_struct::UidStruct::from_service_id(id);
            let profile = crypto::profile_key_struct::ProfileKeyStruct::new(key, uuid);
            let commitment =
                crypto::profile_key_commitment::CommitmentWithSecretNonce::new(profile, uuid);
            // Fixed bincode field projection only, not a reimplementation of
            // derivation: reserved, master key, group ID, blob key, two pairs.
            let bytes = serialize(&group);
            assert_eq!(bytes.len(), 289);
            let uid_key: &crypto::uid_encryption::KeyPair = group.as_ref();
            let profile_key: crypto::profile_key_encryption::KeyPair =
                zkgroup::deserialize(&bytes[193..289]).map_err(|e| e.to_string())?;
            let uid_ciphertext = serialize(&uid_key.encrypt(&uid));
            let profile_ciphertext = serialize(&profile_key.encrypt(&profile));
            assert_eq!(
                &serialize(&group.encrypt_service_id(id))[1..],
                uid_ciphertext
            );
            assert_eq!(
                &serialize(&group.encrypt_profile_key_bytes(key, aci))[1..],
                profile_ciphertext
            );
            let mapped = RistrettoPoint::map_to_curve(key);
            // Normalize the representative before inverting to make fixture
            // order portable. Go also inverts the canonical representative.
            let mapped = mapped.compress().decompress().unwrap();
            let inverses: Vec<Value> = mapped
                .map_to_curve_inverse()
                .into_iter()
                .take(8)
                .map(|c| Option::<[u8; 32]>::from(c).map_or(Value::Null, |b| json!(hex::encode(b))))
                .collect();
            Ok(json!({
                "uid": hex::encode(serialize(&uid)),
                "profile": hex::encode(serialize(&profile)),
                "uid_key": hex::encode(serialize(uid_key)),
                "profile_key_pair": hex::encode(serialize(&profile_key)),
                "uid_ciphertext": hex::encode(uid_ciphertext),
                "profile_ciphertext": hex::encode(profile_ciphertext),
                "profile_decrypts": group.decrypt_profile_key(group.encrypt_profile_key_bytes(key,aci),aci).is_ok(),
                "commitment": hex::encode(serialize(&commitment.get_profile_key_commitment())),
                "commitment_with_nonce": hex::encode(serialize(&commitment)),
                "timestamp_bytes": hex::encode(serialize(&timestamp)),
                "timestamp_scalar": hex::encode(timestamp.calc_m().as_bytes()),
                "map": hex::encode(mapped.compress().as_bytes()),
                "inverse": inverses,
            }))
        }
        "zkgroup.decrypt_uid" => {
            let raw = super::param_bytes(p, "ciphertext")?;
            let wrapped = [&[0], raw.as_slice()].concat();
            let ciphertext = match zkgroup::deserialize::<groups::UuidCiphertext>(&wrapped) {
                Ok(c) => c,
                Err(_) => return Ok(json!({"verified":false})),
            };
            Ok(match group(p)?.decrypt_service_id(ciphertext) {
                Ok(id) => json!({"verified":true,"plaintext":hex::encode(id.service_id_binary())}),
                Err(_) => json!({"verified":false}),
            })
        }
        "zkgroup.decrypt_profile" => {
            let raw = super::param_bytes(p, "ciphertext")?;
            let wrapped = [&[0], raw.as_slice()].concat();
            let uuid = array(p, "uuid")?;
            let ciphertext = match zkgroup::deserialize::<groups::ProfileKeyCiphertext>(&wrapped) {
                Ok(c) => c,
                Err(_) => return Ok(json!({"verified":false})),
            };
            Ok(
                match group(p)?.decrypt_profile_key(ciphertext, Aci::from_uuid_bytes(uuid)) {
                    Ok(key) => json!({"verified":true,"plaintext":hex::encode(serialize(&key))}),
                    Err(_) => json!({"verified":false}),
                },
            )
        }
        "zkgroup.inverse" => {
            let encoded = array(p, "point")?;
            let point = CompressedRistretto(encoded)
                .decompress()
                .ok_or("invalid point")?;
            let inverses: Vec<Value> = point
                .map_to_curve_inverse()
                .into_iter()
                .take(8)
                .map(|c| Option::<[u8; 32]>::from(c).map_or(Value::Null, |b| json!(hex::encode(b))))
                .collect();
            Ok(json!({"inverse":inverses}))
        }
        _ => Err(format!("unknown zkgroup method: {method}")),
    }
}

pub fn vectors() -> Value {
    let cases: Vec<Value> = (0u8..40).map(|i| {
        let seed: Vec<u8> = (0u8..32).map(|j|i.wrapping_mul(17).wrapping_add(j)).collect();
        let uuid: Vec<u8> = (0u8..16).map(|j|i.wrapping_mul(13).wrapping_add(j)).collect();
        let key: Vec<u8> = match i {
            0..=7 => { let mut k = vec![0;32]; k[0] = (i>>2)&1; k[31] = ((i>>1)&1)<<7 | (i&1)<<6; k },
            8 => vec![255;32],
            _ => (0u8..32).map(|j|i.wrapping_mul(7).wrapping_add(j)).collect(),
        };
        let timestamp = match i { 0 => 0, 1 => 1, 2 => u32::MAX as u64, 3 => u64::MAX, _ => 1700000000 + (i as u64)*86400 };
        let params = json!({"seed":hex::encode(seed),"uuid":hex::encode(uuid),"profile_key":hex::encode(key),"pni":i%2==1,"timestamp":timestamp});
        json!({"params":params,"result":dispatch("zkgroup.crypto",&params).expect("valid vector")})
    }).collect();
    json!({
        "upstream_tag":"v0.102.2",
        "source":"rust/zkgroup crypto and curve25519-dalek 5.0.0 lizard; upstream public APIs",
        "uid_system":hex::encode(serialize(&crypto::uid_encryption::SystemParams::get_hardcoded())),
        "profile_system":hex::encode(serialize(&crypto::profile_key_encryption::SystemParams::get_hardcoded())),
        "commitment_system":hex::encode(serialize(&crypto::profile_key_commitment::SystemParams::get_hardcoded())),
        "cases":cases,
    })
}
