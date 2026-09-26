// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 8.3 oracle: pinned public zkgroup APIs, without algorithm copies.
use libsignal_core::{Aci, Pni};
use serde_json::{json, Value};
use zkgroup::{auth, groups, profiles, serialize, ServerSecretParams, Timestamp};
fn array<const N: usize>(p: &Value, name: &str) -> Result<[u8; N], String> {
    super::param_bytes(p, name)?
        .try_into()
        .map_err(|_| format!("{name} length"))
}
fn time(p: &Value, name: &str) -> Result<Timestamp, String> {
    Ok(Timestamp::from_epoch_seconds(p[name].as_u64().ok_or(name)?))
}
pub fn generate(p: &Value) -> Result<Value, String> {
    let seed = array(p, "seed")?;
    let randomness = array(p, "randomness")?;
    let aci = Aci::from_uuid_bytes(array(p, "aci")?);
    let pni = Pni::from_uuid_bytes(array(p, "pni")?);
    let key = profiles::ProfileKey::create(array(p, "profile_key")?);
    let group = groups::GroupSecretParams::derive_from_master_key(groups::GroupMasterKey::new(
        array(p, "master_key")?,
    ));
    let server = ServerSecretParams::generate(seed);
    let public = server.get_public_params();
    let message = super::param_bytes(p, "message")?;
    let context = public.create_profile_key_credential_request_context(randomness, aci, key);
    let request = context.get_request();
    let commitment = key.get_commitment(aci);
    let response = server
        .issue_expiring_profile_key_credential(
            randomness,
            &request,
            aci,
            commitment,
            time(p, "expiration")?,
        )
        .map_err(|e| e.to_string())?;
    let credential = public
        .receive_expiring_profile_key_credential(&context, &response, time(p, "now")?)
        .map_err(|e| e.to_string())?;
    let presentation =
        public.create_expiring_profile_key_credential_presentation(randomness, group, credential);
    let auth_response = auth::AuthCredentialWithPniZkcResponse::issue_credential(
        aci,
        pni,
        time(p, "redemption")?,
        &server,
        randomness,
    );
    let auth_credential = auth_response
        .clone()
        .receive(aci, pni, time(p, "redemption")?, &public)
        .map_err(|e| e.to_string())?;
    let auth_presentation = auth_credential.present(&public, &group, randomness);
    let padding =
        u32::try_from(p["padding"].as_u64().ok_or("padding")?).map_err(|e| e.to_string())?;
    Ok(json!({
    "server":hex::encode(serialize(&public)),"signature":hex::encode(server.sign(randomness,&message)),
    "group":hex::encode(serialize(&group)),"generated_group":hex::encode(serialize(&groups::GroupSecretParams::generate(randomness))),
    "group_public":hex::encode(serialize(&group.get_public_params())),"group_id":hex::encode(group.get_group_identifier()),
    "aci_ciphertext":hex::encode(serialize(&group.encrypt_service_id(aci.into()))),"pni_ciphertext":hex::encode(serialize(&group.encrypt_service_id(pni.into()))),
    "profile_ciphertext":hex::encode(serialize(&group.encrypt_profile_key(key,aci))),
    "blob":hex::encode(group.encrypt_blob_with_padding(randomness,&message,padding)),
    "commitment":hex::encode(serialize(&commitment)),"version":hex::encode(serialize(&key.get_profile_key_version(aci))),"access_key":hex::encode(key.derive_access_key()),
    "context":hex::encode(serialize(&context)),"request":hex::encode(serialize(&request)),"profile_response":hex::encode(serialize(&response)),"profile_credential":hex::encode(serialize(&credential)),"profile_presentation":hex::encode(serialize(&presentation)),
    "auth_response":hex::encode(serialize(&auth_response)),"auth_credential":hex::encode(serialize(&auth_credential)),"auth_presentation":hex::encode(serialize(&auth_presentation))
    }))
}
pub fn verify(p: &Value) -> Result<Value, String> {
    let server = ServerSecretParams::generate(array(p, "seed")?);
    let public = server.get_public_params();
    let group = groups::GroupSecretParams::derive_from_master_key(groups::GroupMasterKey::new(
        array(p, "master_key")?,
    ));
    let aci = Aci::from_uuid_bytes(array(p, "aci")?);
    let pni = Pni::from_uuid_bytes(array(p, "pni")?);
    let message = super::param_bytes(p, "message")?;
    let expected_profile_key = array::<32>(p, "profile_key")?;
    let a = &p["artifacts"];
    let get = |name| super::param_bytes(a, name);
    let signature = get("signature")?
        .try_into()
        .ok()
        .is_some_and(|b| public.verify_signature(&message, b).is_ok());
    let profile = (|| -> Result<(), String> {
        let raw = get("profile_presentation")?;
        if raw.is_empty() {
            return Err("empty profile presentation".into());
        }
        let presentation =
            profiles::AnyProfileKeyCredentialPresentation::new(&raw).map_err(|e| e.to_string())?;
        server
            .verify_profile_key_credential_presentation(
                group.get_public_params(),
                &presentation,
                time(p, "now")?,
            )
            .map_err(|e| e.to_string())
    })();
    let auth = (|| -> Result<(), String> {
        let raw = get("auth_presentation")?;
        let presentation =
            auth::AnyAuthCredentialPresentation::new(&raw).map_err(|e| e.to_string())?;
        server
            .verify_auth_credential_presentation(
                group.get_public_params(),
                &presentation,
                time(p, "now")?,
            )
            .map_err(|e| e.to_string())
    })();
    let profile_receive = (|| -> Result<(), String> {
        let context =
            zkgroup::deserialize::<profiles::ProfileKeyCredentialRequestContext>(&get("context")?)
                .map_err(|e| e.to_string())?;
        let response = zkgroup::deserialize::<profiles::ExpiringProfileKeyCredentialResponse>(
            &get("profile_response")?,
        )
        .map_err(|e| e.to_string())?;
        public
            .receive_expiring_profile_key_credential(&context, &response, time(p, "now")?)
            .map(|_| ())
            .map_err(|e| e.to_string())
    })();
    let auth_receive = (|| -> Result<(), String> {
        auth::AuthCredentialWithPniResponse::new(&get("auth_response")?)
            .map_err(|e| e.to_string())?
            .receive(&public, aci, pni, time(p, "redemption")?)
            .map(|_| ())
            .map_err(|e| e.to_string())
    })();
    let uid = (|| -> Result<bool, String> {
        let c = zkgroup::deserialize::<groups::UuidCiphertext>(&get("aci_ciphertext")?)
            .map_err(|e| e.to_string())?;
        Ok(group
            .decrypt_service_id(c)
            .map(|id| id == aci)
            .unwrap_or(false))
    })();
    let profile_key = (|| -> Result<bool, String> {
        let c = zkgroup::deserialize::<groups::ProfileKeyCiphertext>(&get("profile_ciphertext")?)
            .map_err(|e| e.to_string())?;
        Ok(group
            .decrypt_profile_key(c, aci)
            .map(|k| k.get_bytes() == expected_profile_key)
            .unwrap_or(false))
    })();
    let blob = group
        .decrypt_blob_with_padding(&get("blob")?)
        .map(|b| b == message)
        .unwrap_or(false);
    Ok(
        json!({"signature":signature,"profile_presentation":profile.is_ok(),"auth_presentation":auth.is_ok(),"profile_receive":profile_receive.is_ok(),"auth_receive":auth_receive.is_ok(),"uid":uid.unwrap_or(false),"profile_key":profile_key.unwrap_or(false),"blob":blob}),
    )
}
pub fn vectors() -> Value {
    let cases:Vec<_>=(0u8..16).map(|i|{
 let bytes=|n:usize,offset:u8|hex::encode((0..n).map(|j|i.wrapping_mul(17).wrapping_add(j as u8).wrapping_add(offset)).collect::<Vec<_>>());
 let day=20000*86400u64;
 let p=json!({"seed":bytes(32,0),"randomness":bytes(32,1),"master_key":bytes(32,2),"aci":bytes(16,3),"pni":bytes(16,4),"profile_key":bytes(32,5),"message":bytes(i as usize*7,6),"padding":i,"now":day,"redemption":day,"expiration":day+(1+(i as u64%7))*86400});
 json!({"params":p,"result":generate(&p).unwrap()})
 }).collect();
    json!({"pin":"v0.102.2","cases":cases})
}
