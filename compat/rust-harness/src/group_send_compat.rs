// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only
//! Phase 8.4 oracle using pinned libsignal APIs.
use libsignal_core::ServiceId;
use serde_json::{json, Value};
use zkgroup::{groups, serialize, ServerSecretParams, Timestamp};
fn array<const N: usize>(p: &Value, name: &str) -> Result<[u8; N], String> {
    super::param_bytes(p, name)?
        .try_into()
        .map_err(|_| format!("{name} length"))
}
fn time(p: &Value, name: &str) -> Result<Timestamp, String> {
    Ok(Timestamp::from_epoch_seconds(p[name].as_u64().ok_or(name)?))
}
fn members(p: &Value) -> Result<Vec<ServiceId>, String> {
    p["members"]
        .as_array()
        .ok_or("members")?
        .iter()
        .map(|id| {
            let b = hex::decode(id.as_str().ok_or("member")?).map_err(|e| e.to_string())?;
            let b = b.try_into().map_err(|_| "member length")?;
            ServiceId::parse_from_service_id_fixed_width_binary(&b).ok_or("member kind".into())
        })
        .collect()
}
pub fn generate(p: &Value) -> Result<Value, String> {
    let members = members(p)?;
    if members.is_empty() {
        return Err("empty batch".into());
    }
    let server = ServerSecretParams::generate(array(p, "seed")?);
    let group = groups::GroupSecretParams::derive_from_master_key(groups::GroupMasterKey::new(
        array(p, "master_key")?,
    ));
    let expiration = time(p, "expiration")?;
    let key = groups::GroupSendDerivedKeyPair::for_expiration(expiration, &server);
    let ciphertexts: Vec<_> = members
        .iter()
        .map(|id| group.encrypt_service_id(*id))
        .collect();
    let response = groups::GroupSendEndorsementsResponse::issue(
        ciphertexts.clone(),
        &key,
        array(p, "randomness")?,
    );
    let received = response
        .clone()
        .receive_with_service_ids(
            members.clone(),
            time(p, "now")?,
            &group,
            &server.get_public_params(),
        )
        .map_err(|e| e.to_string())?;
    let combined =
        groups::GroupSendEndorsement::combine(received.iter().skip(1).map(|e| e.decompressed));
    let all = groups::GroupSendEndorsement::combine(received.iter().map(|e| e.decompressed));
    let token = combined.to_token(&group);
    Ok(
        json!({"server":hex::encode(serialize(&server.get_public_params())),"response":hex::encode(serialize(&response)),
 "ciphertexts":ciphertexts.iter().map(|c|hex::encode(serialize(c))).collect::<Vec<_>>(),
 "endorsements":received.iter().map(|e|hex::encode(serialize(&e.compressed))).collect::<Vec<_>>(),
 "combined":hex::encode(serialize(&combined)),"removed":hex::encode(serialize(&all.remove(&received[0].decompressed))),
 "empty":hex::encode(serialize(&groups::GroupSendEndorsement::combine([]))),
 "token":hex::encode(serialize(&token)),"full_token":hex::encode(serialize(&token.into_full_token(expiration)))}),
    )
}
pub fn verify(p: &Value) -> Result<Value, String> {
    let members = members(p)?;
    let server = ServerSecretParams::generate(array(p, "seed")?);
    let group = groups::GroupSecretParams::derive_from_master_key(groups::GroupMasterKey::new(
        array(p, "master_key")?,
    ));
    let a = &p["artifacts"];
    let response = (|| -> Result<(), String> {
        let response: groups::GroupSendEndorsementsResponse =
            zkgroup::deserialize(&super::param_bytes(a, "response")?).map_err(|e| e.to_string())?;
        if members.is_empty() {
            return Err("empty batch".into());
        }
        response
            .receive_with_service_ids(
                members.clone(),
                time(p, "now")?,
                &group,
                &server.get_public_params(),
            )
            .map(|_| ())
            .map_err(|e| e.to_string())
    })();
    let token = (|| -> Result<(), String> {
        let token: groups::GroupSendFullToken =
            zkgroup::deserialize(&super::param_bytes(a, "full_token")?)
                .map_err(|e| e.to_string())?;
        let key = groups::GroupSendDerivedKeyPair::for_expiration(token.expiration(), &server);
        token
            .verify(members.iter().skip(1).copied(), time(p, "now")?, &key)
            .map_err(|e| e.to_string())
    })();
    Ok(json!({"receive":response.is_ok(),"token":token.is_ok()}))
}
pub fn vectors() -> Value {
    let cases:Vec<_>=(0u8..16).map(|i|{
 let bytes=|n:usize,offset:u8|hex::encode((0..n).map(|j|i.wrapping_mul(17).wrapping_add(j as u8).wrapping_add(offset)).collect::<Vec<_>>());
 let members:Vec<_>=(0..(1+i as usize*2)).map(|j|format!("{:02x}{}",j%2,bytes(16,j as u8))).collect();
 let day=20000*86400u64;
 let p=json!({"seed":bytes(32,0),"randomness":bytes(32,1),"master_key":bytes(32,2),"members":members,"now":day,"expiration":day+(1+(i as u64%7))*86400});
 json!({"params":p,"result":generate(&p).unwrap()})
 }).collect();
    json!({"pin":"v0.102.2","cases":cases})
}
