// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

//! Phase 9.1 oracle: the Noise handshakes of rust/attest (client_connection.rs)
//! on snow 0.10.0, the version libsignal v0.102.2 locks.
//!
//! The resolver matches attest/src/snow_resolver.rs: snow's own X25519,
//! SHA-256 and ChaChaPoly (which that file copies from snow's default
//! resolver), and "Kyber1024" backed by libcrux ML-KEM-1024. The one change is
//! randomness: attest draws from OsRng, here every byte comes from a seeded
//! ChaCha20 stream that records what it hands out, so vectors are
//! deterministic and the Go side can replay the same bytes. Draw order per
//! side: initiator e (32), e1 key pair (64); responder e (32), ekem1
//! encapsulation (32).
//!
//! RPC calls are stateless: each call rebuilds its side from the seed and
//! replays the handshake, so a later call with more input reproduces the
//! earlier messages byte for byte.

use std::sync::{Arc, Mutex};

use libcrux_ml_kem::mlkem1024;
use rand::{RngCore as _, SeedableRng};
use rand_chacha::ChaCha20Rng;
use serde_json::{json, Value};
use snow::params::{CipherChoice, DHChoice, HashChoice, KemChoice};
use snow::resolvers::{CryptoResolver, DefaultResolver};
use snow::types::{Cipher, Dh, Hash, Kem, Random};
use snow::{Builder, HandshakeState, TransportState};

const NOISE_PATTERN: &str = "Noise_NK_25519_ChaChaPoly_SHA256";
const NOISE_PATTERN_HFS: &str = "Noise_NKhfs_25519+Kyber1024_ChaChaPoly_SHA256";
// client_connection.rs
const NOISE_TRANSPORT_PER_PACKET_MAX: usize = 65535;
const NOISE_TRANSPORT_PER_PAYLOAD_OVERHEAD: usize = 16;
const NOISE_TRANSPORT_PER_PAYLOAD_MAX: usize =
    NOISE_TRANSPORT_PER_PACKET_MAX - NOISE_TRANSPORT_PER_PAYLOAD_OVERHEAD;

struct Tape {
    rng: ChaCha20Rng,
    drawn: Vec<u8>,
}

type SharedTape = Arc<Mutex<Tape>>;

fn draw(tape: &SharedTape, dest: &mut [u8]) {
    let mut t = tape.lock().expect("tape lock");
    t.rng.fill_bytes(dest);
    t.drawn.extend_from_slice(dest);
}

struct TapeRandom(SharedTape);

impl Random for TapeRandom {
    fn try_fill_bytes(&mut self, dest: &mut [u8]) -> Result<(), snow::Error> {
        draw(&self.0, dest);
        Ok(())
    }
}

// attest/src/snow_resolver.rs's Kyber1024, with the encapsulation randomness
// taken from the tape instead of OsRng.
struct Kyber1024 {
    tape: SharedTape,
    pubkey: mlkem1024::MlKem1024PublicKey,
    privkey: mlkem1024::MlKem1024PrivateKey,
}

impl Kem for Kyber1024 {
    fn name(&self) -> &'static str {
        "Kyber1024"
    }

    fn pub_len(&self) -> usize {
        mlkem1024::MlKem1024PublicKey::len()
    }

    fn ciphertext_len(&self) -> usize {
        mlkem1024::MlKem1024Ciphertext::len()
    }

    fn shared_secret_len(&self) -> usize {
        libcrux_ml_kem::SHARED_SECRET_SIZE
    }

    fn generate(&mut self, rng: &mut dyn Random) {
        let mut randomness = [0u8; 64];
        rng.try_fill_bytes(&mut randomness)
            .expect("can generate random bytes");
        let keypair = mlkem1024::generate_key_pair(randomness);
        (self.privkey, self.pubkey) = keypair.into_parts();
    }

    fn pubkey(&self) -> &[u8] {
        self.pubkey.as_ref()
    }

    fn encapsulate(
        &self,
        pubkey: &[u8],
        shared_secret_out: &mut [u8],
        ciphertext_out: &mut [u8],
    ) -> Result<(usize, usize), snow::Error> {
        let mlkem_pubkey = {
            let key =
                mlkem1024::MlKem1024PublicKey::try_from(pubkey).map_err(|_| snow::Error::Input)?;
            mlkem1024::validate_public_key(&key).then_some(key)
        }
        .ok_or(snow::Error::Input)?;
        let mut randomness = [0u8; 32];
        draw(&self.tape, &mut randomness);
        let (ciphertext, shared_secret) = mlkem1024::encapsulate(&mlkem_pubkey, randomness);
        shared_secret_out.copy_from_slice(shared_secret.as_ref());
        ciphertext_out.copy_from_slice(ciphertext.as_ref());
        Ok((shared_secret.len(), mlkem1024::MlKem1024Ciphertext::len()))
    }

    fn decapsulate(
        &self,
        ciphertext: &[u8],
        shared_secret_out: &mut [u8],
    ) -> Result<usize, snow::Error> {
        let ciphertext =
            mlkem1024::MlKem1024Ciphertext::try_from(ciphertext).map_err(|_| snow::Error::Input)?;
        let shared_secret = mlkem1024::decapsulate(&self.privkey, &ciphertext);
        shared_secret_out.copy_from_slice(shared_secret.as_ref());
        Ok(libcrux_ml_kem::SHARED_SECRET_SIZE)
    }
}

struct Resolver(SharedTape);

impl CryptoResolver for Resolver {
    fn resolve_rng(&self) -> Option<Box<dyn Random>> {
        Some(Box::new(TapeRandom(self.0.clone())))
    }

    fn resolve_dh(&self, choice: &DHChoice) -> Option<Box<dyn Dh>> {
        match choice {
            DHChoice::Curve25519 => DefaultResolver.resolve_dh(choice),
            _ => None,
        }
    }

    fn resolve_hash(&self, choice: &HashChoice) -> Option<Box<dyn Hash>> {
        match choice {
            HashChoice::SHA256 => DefaultResolver.resolve_hash(choice),
            _ => None,
        }
    }

    fn resolve_cipher(&self, choice: &CipherChoice) -> Option<Box<dyn Cipher>> {
        match choice {
            CipherChoice::ChaChaPoly => DefaultResolver.resolve_cipher(choice),
            _ => None,
        }
    }

    fn resolve_kem(&self, choice: &KemChoice) -> Option<Box<dyn Kem>> {
        match choice {
            KemChoice::Kyber1024 => Some(Box::new(Kyber1024 {
                tape: self.0.clone(),
                pubkey: mlkem1024::MlKem1024PublicKey::from(
                    [0u8; mlkem1024::MlKem1024PublicKey::len()],
                ),
                privkey: mlkem1024::MlKem1024PrivateKey::from(
                    [0u8; mlkem1024::MlKem1024PrivateKey::len()],
                ),
            })),
        }
    }
}

fn pattern_name(pattern: &str) -> Result<&'static str, String> {
    match pattern {
        "NK" => Ok(NOISE_PATTERN),
        "NKhfs" => Ok(NOISE_PATTERN_HFS),
        other => Err(format!("unknown noise pattern {other:?}")),
    }
}

/// Builds one side. The initiator gets the responder's static public key, the
/// responder its static private key.
fn build(
    pattern: &str,
    initiator: bool,
    key: &[u8],
    seed: [u8; 32],
) -> Result<(HandshakeState, SharedTape), String> {
    let tape = Arc::new(Mutex::new(Tape {
        rng: ChaCha20Rng::from_seed(seed),
        drawn: Vec::new(),
    }));
    let params = pattern_name(pattern)?
        .parse()
        .map_err(|e| format!("noise params: {e:?}"))?;
    let builder = Builder::with_resolver(params, Box::new(Resolver(tape.clone())));
    let hs = if initiator {
        builder
            .remote_public_key(key)
            .and_then(Builder::build_initiator)
    } else {
        builder
            .local_private_key(key)
            .and_then(Builder::build_responder)
    }
    .map_err(|e| format!("noise build: {e:?}"))?;
    Ok((hs, tape))
}

fn write(hs: &mut HandshakeState, payload: &[u8]) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; NOISE_TRANSPORT_PER_PACKET_MAX];
    let n = hs
        .write_message(payload, &mut buf)
        .map_err(|e| format!("noise write: {e:?}"))?;
    buf.truncate(n);
    Ok(buf)
}

fn read(hs: &mut HandshakeState, message: &[u8]) -> Result<Vec<u8>, String> {
    let mut buf = vec![0u8; message.len()];
    let n = hs
        .read_message(message, &mut buf)
        .map_err(|e| format!("noise read: {e:?}"))?;
    buf.truncate(n);
    Ok(buf)
}

/// client_connection.rs ClientConnection::send.
fn send(t: &mut TransportState, plaintext: &[u8]) -> Result<Vec<u8>, String> {
    let max = plaintext.len()
        + plaintext.len().div_ceil(NOISE_TRANSPORT_PER_PAYLOAD_MAX)
            * NOISE_TRANSPORT_PER_PAYLOAD_OVERHEAD;
    let mut ciphertext = vec![0u8; max];
    let mut total = 0;
    for chunk in plaintext.chunks(NOISE_TRANSPORT_PER_PAYLOAD_MAX) {
        total += t
            .write_message(chunk, &mut ciphertext[total..])
            .map_err(|e| format!("noise send: {e:?}"))?;
    }
    ciphertext.truncate(total);
    Ok(ciphertext)
}

/// client_connection.rs ClientConnection::recv.
fn recv(t: &mut TransportState, ciphertext: &[u8]) -> Result<Vec<u8>, String> {
    let mut plaintext = vec![0u8; ciphertext.len()];
    let mut total = 0;
    for chunk in ciphertext.chunks(NOISE_TRANSPORT_PER_PACKET_MAX) {
        total += t
            .read_message(chunk, &mut plaintext[total..])
            .map_err(|e| format!("noise recv: {e:?}"))?;
    }
    plaintext.truncate(total);
    Ok(plaintext)
}

fn hex_list(p: &Value, name: &str) -> Result<Vec<Vec<u8>>, String> {
    match p.get(name) {
        None | Some(Value::Null) => Ok(Vec::new()),
        Some(Value::Array(items)) => items
            .iter()
            .map(|v| {
                v.as_str()
                    .ok_or_else(|| format!("{name}: not a string"))
                    .and_then(|s| hex::decode(s).map_err(|e| format!("{name}: {e}")))
            })
            .collect(),
        Some(_) => Err(format!("{name}: not an array")),
    }
}

fn opt_bytes(p: &Value, name: &str) -> Result<Option<Vec<u8>>, String> {
    match p.get(name) {
        None | Some(Value::Null) => Ok(None),
        Some(_) => super::param_bytes(p, name).map(Some),
    }
}

fn hexes(items: &[Vec<u8>]) -> Vec<String> {
    items.iter().map(|b| hex::encode(b)).collect()
}

/// Finishes the transport part of an RPC call: decrypts `inbound` and
/// encrypts `outbound` in order.
fn transport(
    hs: HandshakeState,
    p: &Value,
    mut out: serde_json::Map<String, Value>,
) -> Result<Value, String> {
    let hash = hs.get_handshake_hash().to_vec();
    let mut t = hs
        .into_transport_mode()
        .map_err(|e| format!("noise transport: {e:?}"))?;
    let inbound = hex_list(p, "inbound")?
        .iter()
        .map(|ct| recv(&mut t, ct))
        .collect::<Result<Vec<_>, _>>()?;
    let outbound = hex_list(p, "outbound")?
        .iter()
        .map(|pt| send(&mut t, pt))
        .collect::<Result<Vec<_>, _>>()?;
    out.insert("handshake_hash".into(), json!(hex::encode(hash)));
    out.insert("inbound".into(), json!(hexes(&inbound)));
    out.insert("outbound".into(), json!(hexes(&outbound)));
    Ok(Value::Object(out))
}

pub fn dispatch(method: &str, p: &Value) -> Result<Value, String> {
    let pattern = p
        .get("pattern")
        .and_then(Value::as_str)
        .ok_or("missing pattern")?;
    let seed: [u8; 32] = super::param_bytes(p, "seed")?
        .try_into()
        .map_err(|_| "seed must be 32 bytes")?;
    match method {
        // noise.initiator: { pattern, remote_static, seed, payload0,
        //   message1?, payload1 is returned, inbound?, outbound? }
        "noise.initiator" => {
            let (mut hs, _) = build(
                pattern,
                true,
                &super::param_bytes(p, "remote_static")?,
                seed,
            )?;
            let message0 = write(&mut hs, &super::param_bytes(p, "payload0")?)?;
            let mut out = serde_json::Map::new();
            out.insert("message0".into(), json!(hex::encode(&message0)));
            let Some(message1) = opt_bytes(p, "message1")? else {
                return Ok(Value::Object(out));
            };
            let payload1 = read(&mut hs, &message1)?;
            out.insert("payload1".into(), json!(hex::encode(payload1)));
            transport(hs, p, out)
        }
        // noise.responder: { pattern, static_private, seed, message0, payload1,
        //   inbound?, outbound? }
        "noise.responder" => {
            let (mut hs, _) = build(
                pattern,
                false,
                &super::param_bytes(p, "static_private")?,
                seed,
            )?;
            let payload0 = read(&mut hs, &super::param_bytes(p, "message0")?)?;
            let message1 = write(&mut hs, &super::param_bytes(p, "payload1")?)?;
            let mut out = serde_json::Map::new();
            out.insert("payload0".into(), json!(hex::encode(payload0)));
            out.insert("message1".into(), json!(hex::encode(message1)));
            transport(hs, p, out)
        }
        other => Err(format!("unknown method {other:?}")),
    }
}

fn random_bytes(rng: &mut ChaCha20Rng, n: usize) -> Vec<u8> {
    let mut b = vec![0u8; n];
    rng.fill_bytes(&mut b);
    b
}

fn case(
    rng: &mut ChaCha20Rng,
    pattern: &str,
    payloads: [Vec<u8>; 2],
    i2r: &[Vec<u8>],
    r2i: &[Vec<u8>],
) -> Value {
    let static_private = random_bytes(rng, 32);
    let static_public = curve25519_dalek::MontgomeryPoint::mul_base_clamped(
        static_private.clone().try_into().expect("32 bytes"),
    )
    .to_bytes();
    let mut iseed = [0u8; 32];
    let mut rseed = [0u8; 32];
    rng.fill_bytes(&mut iseed);
    rng.fill_bytes(&mut rseed);

    let (mut ini, itape) = build(pattern, true, &static_public, iseed).expect("initiator");
    let (mut res, rtape) = build(pattern, false, &static_private, rseed).expect("responder");
    let message0 = write(&mut ini, &payloads[0]).expect("write 0");
    assert_eq!(read(&mut res, &message0).expect("read 0"), payloads[0]);
    let message1 = write(&mut res, &payloads[1]).expect("write 1");
    assert_eq!(read(&mut ini, &message1).expect("read 1"), payloads[1]);
    let hash = ini.get_handshake_hash().to_vec();
    assert_eq!(hash, res.get_handshake_hash());
    let mut ti = ini.into_transport_mode().expect("transport");
    let mut tr = res.into_transport_mode().expect("transport");

    let exchange = |from: &mut TransportState, to: &mut TransportState, msgs: &[Vec<u8>]| {
        msgs.iter()
            .map(|pt| {
                let ct = send(from, pt).expect("send");
                assert_eq!(&recv(to, &ct).expect("recv"), pt);
                json!({ "plaintext": hex::encode(pt), "ciphertext": hex::encode(ct) })
            })
            .collect::<Vec<_>>()
    };
    let i2r = exchange(&mut ti, &mut tr, i2r);
    let r2i = exchange(&mut tr, &mut ti, r2i);

    let initiator_random = itape.lock().expect("tape").drawn.clone();
    let responder_random = rtape.lock().expect("tape").drawn.clone();
    json!({
        "pattern": pattern,
        "responder_static_private": hex::encode(&static_private),
        "responder_static_public": hex::encode(static_public),
        "initiator_random": hex::encode(initiator_random),
        "responder_random": hex::encode(responder_random),
        "payload0": hex::encode(&payloads[0]),
        "payload1": hex::encode(&payloads[1]),
        "message0": hex::encode(&message0),
        "message1": hex::encode(&message1),
        "handshake_hash": hex::encode(hash),
        "initiator_to_responder": i2r,
        "responder_to_initiator": r2i,
    })
}

pub fn vectors(seed: u64) -> Value {
    let mut rng = ChaCha20Rng::seed_from_u64(seed);
    let mut cases = Vec::new();
    for pattern in ["NK", "NKhfs"] {
        // libsignal's own shape: empty handshake payloads.
        cases.push(case(
            &mut rng,
            pattern,
            [Vec::new(), Vec::new()],
            &[b"request".to_vec()],
            &[b"response".to_vec()],
        ));
        for _ in 0..3 {
            let n0 = 1 + (rng.next_u32() % 200) as usize;
            let p0 = random_bytes(&mut rng, n0);
            let n1 = 1 + (rng.next_u32() % 200) as usize;
            let p1 = random_bytes(&mut rng, n1);
            let mut msgs = || {
                let mut v = vec![Vec::new()];
                for _ in 0..3 {
                    let n = 1 + (rng.next_u32() % 1000) as usize;
                    v.push(random_bytes(&mut rng, n));
                }
                v
            };
            let i2r = msgs();
            let r2i = msgs();
            cases.push(case(&mut rng, pattern, [p0, p1], &i2r, &r2i));
        }
    }
    // One plaintext longer than a Noise message, split into two chunks.
    let long = random_bytes(&mut rng, NOISE_TRANSPORT_PER_PAYLOAD_MAX + 1);
    cases.push(case(
        &mut rng,
        "NK",
        [Vec::new(), Vec::new()],
        &[long.clone()],
        &[long],
    ));
    json!({
        "domain": "noise",
        "seed": format!("{seed:#018x}"),
        "snow": "0.10.0",
        "cases": cases,
    })
}
