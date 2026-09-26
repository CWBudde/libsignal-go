// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

//! Oracle for the actual pinned zkcredential crate; no proof equations duplicated.
use curve25519_dalek::RistrettoPoint;
use poksho::{ShoApi, ShoHmacSha256};
use serde::{de::DeserializeOwned, Serialize};
use serde_json::{json, Map, Value};
use zkcredential::{
    attributes::*, credentials::*, endorsements::*, issuance::blind::*, issuance::*,
    presentation::*, sho::ShoExt,
};

struct Bytes(Vec<u8>);
impl PublicAttribute for Bytes {
    fn hash_into(&self, s: &mut dyn ShoApi) {
        s.absorb_and_ratchet(&self.0)
    }
}
struct A;
struct B;
struct Inverse;
macro_rules! domain {
    ($t:ty, $id:literal) => {
        impl Domain for $t {
            type Attribute = [RistrettoPoint; 2];
            const ID: &'static str = $id;
            fn G_a() -> [RistrettoPoint; 2] {
                static STORAGE: std::sync::OnceLock<[RistrettoPoint; 2]> =
                    std::sync::OnceLock::new();
                *derive_default_generator_points::<Self>(&STORAGE)
            }
        }
    };
}
domain!(A, "Compat_ZKCredential_A");
domain!(B, "Compat_ZKCredential_B");
domain!(Inverse, "Compat_ZKCredential_Inverse");
fn put<T: Serialize>(out: &mut Map<String, Value>, name: impl Into<String>, value: &T) {
    out.insert(
        name.into(),
        json!(hex::encode(bincode::serialize(value).unwrap())),
    );
}
fn read<T: DeserializeOwned>(p: &Value, name: &str) -> Result<T, String> {
    use bincode::Options;
    bincode::DefaultOptions::new()
        .with_fixint_encoding()
        .reject_trailing_bytes()
        .deserialize(&super::param_bytes(p, name)?)
        .map_err(|e| e.to_string())
}
struct Params {
    seed: [u8; 32],
    label: Vec<u8>,
    message: Vec<u8>,
    public: Vec<u8>,
    hidden: usize,
    clear: usize,
    revealed: usize,
    unverified: bool,
    same: bool,
}
fn params(p: &Value) -> Result<Params, String> {
    let seed = super::param_bytes(p, "seed")?
        .try_into()
        .map_err(|_| "seed length")?;
    let n = |key| {
        p[key]
            .as_u64()
            .filter(|x| *x <= 6)
            .map(|x| x as usize)
            .ok_or("bad count".to_string())
    };
    let (hidden, clear, revealed) = (n("hidden")?, n("clear")?, n("revealed")?);
    if hidden * 2 + revealed == 0 || hidden * 2 + revealed > 6 || clear > hidden {
        return Err("bad arity".into());
    }
    Ok(Params {
        seed,
        label: super::param_bytes(p, "label")?,
        message: super::param_bytes(p, "message")?,
        public: super::param_bytes(p, "public")?,
        hidden,
        clear,
        revealed,
        unverified: p["unverified"].as_bool().ok_or("unverified")?,
        same: p["same"].as_bool().ok_or("same")?,
    })
}
fn tag(p: &Params) -> ShoHmacSha256 {
    let mut s = ShoHmacSha256::new(b"Compat_ZKCredential_EndorsementTag");
    s.absorb_and_ratchet(&p.public);
    s
}
fn issuance<'a>(p: &'a Params, a: &Value) -> Result<IssuanceProofBuilder<'a>, String> {
    let mut b = IssuanceProofBuilder::with_authenticated_message(&p.label, &p.message)
        .add_public_attribute(&Bytes(p.public.clone()));
    for i in 0..p.clear {
        b = b.add_attribute(&read::<[RistrettoPoint; 2]>(a, &format!("attr{i}"))?)
    }
    Ok(b)
}
fn blinded<'a>(p: &'a Params, a: &Value) -> Result<BlindedIssuanceProofBuilder<'a>, String> {
    let b = issuance(p, a)?;
    let mut ps = Vec::new();
    for i in p.clear..p.hidden {
        ps.extend(read::<BlindedAttribute>(a, &format!("blind{i}"))?.blinded_points)
    }
    for i in 0..p.revealed {
        ps.push(read::<BlindedPoint>(a, &format!("revealed_blind{i}"))?)
    }
    let mut b = b.add_blinded_revealed_attribute(&ps[0]);
    for pt in &ps[1..] {
        b = b.add_blinded_revealed_attribute(pt)
    }
    Ok(b)
}
fn verify_issuance<M: CompatibilityMode>(p: &Params, a: &Value) -> Result<Credential, String> {
    let key = read::<CredentialPublicKey>(a, "public_key")?;
    if p.clear == p.hidden && p.revealed == 0 {
        issuance(p, a)?
            .verify(&key, read(a, "issuance")?)
            .map_err(|e| e.to_string())
    } else {
        blinded(p, a)?
            .verify(&key, &read(a, "blinding_key")?, read(a, "issuance")?)
            .map_err(|e| e.to_string())
    }
}
fn verify_presentation<M: CompatibilityMode>(p: &Params, a: &Value) -> Result<(), String> {
    let ka: PublicKey<A> = read(a, "enc_public0")?;
    let kb: PublicKey<B> = read(a, "enc_public1")?;
    let mut v = PresentationProofVerifier::with_authenticated_message(&p.label, &p.message)
        .add_public_attribute(&Bytes(p.public.clone()));
    for i in 0..p.hidden {
        let ct: [RistrettoPoint; 2] = read(a, &format!("cipher{i}"))?;
        let use_a = p.same || i % 2 == 0;
        v = if p.unverified {
            v.add_attribute_without_verified_key(&ct, if use_a { A::ID } else { B::ID })
        } else if use_a {
            v.add_attribute(&ct, &ka)
        } else {
            v.add_attribute(&ct, &kb)
        };
    }
    for i in 0..p.revealed {
        v = v.add_revealed_attribute(&read::<RistrettoPoint>(a, &format!("revealed{i}"))?)
    }
    v.verify(
        &read::<CredentialKeyPair<M>>(a, "key")?,
        &read(a, "presentation")?,
    )
    .map_err(|e| e.to_string())
}
fn generate_mode<M: CompatibilityMode>(p: &Params) -> Result<Value, String> {
    let mut out = Map::new();
    let mut s = ShoHmacSha256::new(b"Compat_ZKCredential_Flow");
    s.absorb_and_ratchet(&p.seed);
    let k = CredentialKeyPair::<M>::generate(p.seed);
    put(&mut out, "key", &k);
    put(&mut out, "public_key", k.public_key());
    let ka = KeyPair::<A>::derive_from(&mut s);
    let kb = KeyPair::<B>::derive_from(&mut s);
    put(&mut out, "enc_key0", &ka);
    put(&mut out, "enc_key1", &kb);
    put(&mut out, "enc_public0", &ka.public_key);
    put(&mut out, "enc_public1", &kb.public_key);
    put(&mut out, "domain0", &A::G_a());
    put(&mut out, "domain1", &B::G_a());
    let inverse = KeyPair::<Inverse>::inverse_of(&ka);
    put(&mut out, "inverse_key", &inverse);
    let mut attrs = Vec::new();
    for i in 0..p.hidden {
        let a = [s.get_point(), s.get_point()];
        put(&mut out, format!("attr{i}"), &a);
        let ct: Ciphertext<A> = if p.same || i % 2 == 0 {
            ka.encrypt_arbitrary_attribute(&a)
        } else {
            kb.encrypt_arbitrary_attribute(&a)
        };
        put(&mut out, format!("cipher{i}"), &ct);
        attrs.push(a)
    }
    let mut revealed = Vec::new();
    for i in 0..p.revealed {
        let a = s.get_point();
        put(&mut out, format!("revealed{i}"), &a);
        revealed.push(a)
    }
    let bk = BlindingKeyPair::generate(&mut s);
    put(&mut out, "blinding_key", &bk);
    put(&mut out, "blinding_public", bk.public_key());
    for (i, a) in attrs.iter().enumerate().skip(p.clear) {
        let b = bk.encrypt(a, &mut s);
        put(
            &mut out,
            format!("blind{i}"),
            &BlindedAttribute::<WithoutNonce>::from(b),
        );
        put(
            &mut out,
            format!("nonce{i}"),
            &b.blinded_points.map(|x| x.r.0),
        );
    }
    for (i, a) in revealed.iter().enumerate() {
        let b = bk.blind(a, &mut s);
        put(
            &mut out,
            format!("revealed_blind{i}"),
            &BlindedPoint::<WithoutNonce>::from(b),
        );
        put(&mut out, format!("revealed_nonce{i}"), &b.r.0);
    }
    let mut random = [0u8; 32];
    s.squeeze_and_ratchet_into(&mut random);
    let a = Value::Object(out.clone());
    if p.clear == p.hidden && p.revealed == 0 {
        put(&mut out, "issuance", &issuance(p, &a)?.issue(&k, random))
    } else {
        put(
            &mut out,
            "issuance",
            &blinded(p, &a)?.issue(&k, bk.public_key(), random),
        )
    }
    let cred = verify_issuance::<M>(p, &Value::Object(out.clone()))?;
    put(&mut out, "credential", &cred);
    let mut b = PresentationProofBuilder::with_authenticated_message(&p.label, &p.message);
    for (i, a) in attrs.iter().enumerate() {
        b = if p.unverified {
            if p.same || i % 2 == 0 {
                b.add_attribute_without_verified_key(a, &ka)
            } else {
                b.add_attribute_without_verified_key(a, &kb)
            }
        } else if p.same || i % 2 == 0 {
            b.add_attribute(a, &ka)
        } else {
            b.add_attribute(a, &kb)
        };
    }
    for a in &revealed {
        b = b.add_revealed_attribute(a)
    }
    s.squeeze_and_ratchet_into(&mut random);
    put(
        &mut out,
        "presentation",
        &b.present::<M>(k.public_key(), &cred, random),
    );
    verify_presentation::<M>(p, &Value::Object(out.clone()))?;
    let root = ServerRootKeyPair::generate(p.seed);
    let derived = root.derive_key(tag(p));
    put(&mut out, "root", &root);
    put(&mut out, "root_public", root.public_key());
    put(&mut out, "derived", &derived);
    put(
        &mut out,
        "derived_public",
        &root.public_key().derive_key(tag(p)),
    );
    let client = ClientDecryptionKey::for_first_point_of_attribute(&ka);
    put(&mut out, "client", &client);
    let plain: Vec<_> = (0..p.hidden + p.revealed + 1)
        .map(|_| s.get_point())
        .collect();
    let hidden: Vec<_> = plain.iter().map(|x| ka.a1 * x).collect();
    put(&mut out, "endorsement_plain", &plain);
    put(&mut out, "endorsement_hidden", &hidden);
    s.squeeze_and_ratchet_into(&mut random);
    let response = EndorsementResponse::issue(hidden.clone(), &derived, random);
    put(&mut out, "endorsement_response", &response);
    let received = response
        .receive(hidden, &root.public_key().derive_key(tag(p)))
        .map_err(|e| e.to_string())?;
    for (i, e) in received.decompressed.iter().enumerate() {
        put(&mut out, format!("endorsement{i}"), e)
    }
    let combined = Endorsement::combine(received.decompressed.clone());
    put(&mut out, "combined", &combined);
    let removed = combined.remove(&received.decompressed[0]);
    put(&mut out, "removed", &removed);
    let token = combined.to_token(&client);
    out.insert("token".into(), json!(hex::encode(&token)));
    out.insert(
        "removed_token".into(),
        json!(hex::encode(removed.to_token(&client))),
    );
    derived
        .verify(&plain.iter().sum(), &token)
        .map_err(|e| e.to_string())?;
    let tail = s.squeeze_and_ratchet(32);
    out.insert("sho_tail".into(), json!(hex::encode(tail)));
    Ok(Value::Object(out))
}
pub fn generate(p: &Value) -> Result<Value, String> {
    let q = params(p)?;
    if p["legacy"].as_bool().ok_or("legacy")? {
        generate_mode::<LegacyMode>(&q)
    } else {
        generate_mode::<StandardMode>(&q)
    }
}
fn verify_mode<M: CompatibilityMode>(p: &Params, a: &Value) -> Value {
    let endorsement = (|| -> Result<(), String> {
        let r: EndorsementResponse = read(a, "endorsement_response")?;
        let ps: Vec<RistrettoPoint> = read(a, "endorsement_hidden")?;
        if ps.is_empty() {
            return Err("empty".into());
        }
        r.receive(ps, &read(a, "derived_public")?)
            .map_err(|e| e.to_string())?;
        Ok(())
    })();
    let token = (|| -> Result<(), String> {
        let k: ServerDerivedKeyPair = read(a, "derived")?;
        let ps: Vec<RistrettoPoint> = read(a, "endorsement_plain")?;
        k.verify(&ps.iter().sum(), &super::param_bytes(a, "token")?)
            .map_err(|e| e.to_string())
    })();
    json!({"issuance":verify_issuance::<M>(p,a).is_ok(),"presentation":verify_presentation::<M>(p,a).is_ok(),"endorsement":endorsement.is_ok(),"token":token.is_ok()})
}
pub fn verify(p: &Value) -> Result<Value, String> {
    let q = params(p)?;
    Ok(if p["legacy"].as_bool().ok_or("legacy")? {
        verify_mode::<LegacyMode>(&q, &p["artifacts"])
    } else {
        verify_mode::<StandardMode>(&q, &p["artifacts"])
    })
}
pub fn vectors() -> Value {
    let configs = [
        (0, 0, 1),
        (0, 0, 6),
        (1, 1, 0),
        (1, 0, 0),
        (1, 0, 1),
        (1, 1, 4),
        (2, 2, 0),
        (2, 1, 0),
        (2, 0, 2),
        (2, 2, 1),
        (3, 3, 0),
        (3, 1, 0),
        (3, 0, 0),
    ];
    let mut cases = Vec::new();
    for legacy in [false, true] {
        for (idx, (hidden, clear, revealed)) in configs.iter().enumerate() {
            for unverified in [false, true] {
                let seed = [(cases.len() + 1) as u8; 32];
                let p = json!({"seed":hex::encode(seed),"label":hex::encode(b"Compat credential"),"message":hex::encode(if idx%2==0{b"".as_slice()}else{b"proof message".as_slice()}),"public":hex::encode((idx as u64).to_be_bytes()),"hidden":hidden,"clear":clear,"revealed":revealed,"same":idx%3==0,"unverified":unverified,"legacy":legacy});
                cases.push(json!({"params":p,"result":generate(&p).unwrap()}));
            }
        }
    }
    json!({"domain":"zkcredential","upstream_tag":"v0.102.2","cases":cases})
}
