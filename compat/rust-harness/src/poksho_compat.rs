// Copyright 2026 libsignal-go contributors.
// SPDX-License-Identifier: AGPL-3.0-only

//! Test-only adapter to the actual v0.102.2 poksho crate. No proof formulas are
//! reproduced here: vectors and live calls use upstream public APIs.
use curve25519_dalek::{
    constants::RISTRETTO_BASEPOINT_POINT as G, ristretto::CompressedRistretto, scalar::Scalar,
};
use poksho::{PointArgs, ScalarArgs, ShoApi, ShoHmacSha256, ShoSha256, Statement};
use serde_json::{json, Value};
use std::collections::HashSet;

fn bytes(p: &Value, key: &str) -> Result<Vec<u8>, String> {
    super::param_bytes(p, key)
}
fn text<'a>(p: &'a Value, key: &str) -> Result<&'a str, String> {
    p.get(key)
        .and_then(Value::as_str)
        .ok_or_else(|| format!("missing {key}"))
}
fn scalar(raw: &[u8]) -> Result<Scalar, String> {
    let a: [u8; 32] = raw.try_into().map_err(|_| "scalar length")?;
    Option::from(Scalar::from_canonical_bytes(a)).ok_or_else(|| "noncanonical scalar".into())
}
fn point(raw: &[u8]) -> Result<curve25519_dalek::ristretto::RistrettoPoint, String> {
    let a: [u8; 32] = raw.try_into().map_err(|_| "point length")?;
    CompressedRistretto(a)
        .decompress()
        .ok_or_else(|| "invalid point".into())
}

fn statement(p: &Value) -> Result<Statement, String> {
    let equations = p["equations"].as_array().ok_or("missing equations")?;
    if equations.is_empty() || equations.len() > 255 {
        return Err("equation count".into());
    }
    let mut st = Statement::new();
    let mut scalars = HashSet::new();
    let mut points = HashSet::from(["G"]);
    for e in equations {
        let lhs = text(e, "lhs")?;
        let terms = e["terms"].as_array().ok_or("missing terms")?;
        if lhs.is_empty() || terms.is_empty() || terms.len() > 255 {
            return Err("invalid equation".into());
        }
        points.insert(lhs);
        let mut pairs = Vec::new();
        for term in terms {
            let s = text(term, "scalar")?;
            let p = text(term, "point")?;
            if s.is_empty() || p.is_empty() {
                return Err("empty name".into());
            }
            scalars.insert(s);
            points.insert(p);
            pairs.push((s, p));
        }
        // Prevent upstream builder/serializer panics for malformed RPC input.
        if scalars.len() > 255 || points.len() > 255 {
            return Err("name count".into());
        }
        st.add(lhs, &pairs);
    }
    Ok(st)
}
fn points(p: &Value) -> Result<PointArgs, String> {
    let mut args = PointArgs::new();
    for (name, value) in p["points"].as_object().ok_or("missing points")? {
        let raw =
            hex::decode(value.as_str().ok_or("point must be hex")?).map_err(|e| e.to_string())?;
        args.add(name.clone(), point(&raw)?);
    }
    Ok(args)
}
fn scalars(p: &Value) -> Result<ScalarArgs, String> {
    let mut args = ScalarArgs::new();
    for (name, value) in p["scalars"].as_object().ok_or("missing scalars")? {
        let raw =
            hex::decode(value.as_str().ok_or("scalar must be hex")?).map_err(|e| e.to_string())?;
        args.add(name.clone(), scalar(&raw)?);
    }
    Ok(args)
}

fn run_sho<S: ShoApi + Clone>(p: &Value) -> Result<Value, String> {
    let mut sho = S::new(&bytes(p, "label")?);
    let mut absorbing = false;
    let mut outputs = Vec::new();
    for op in p["ops"].as_array().ok_or("missing ops")? {
        match text(op, "op")? {
            "absorb" => {
                sho.absorb(&bytes(op, "input")?);
                absorbing = true;
            }
            "ratchet" => {
                sho.ratchet();
                absorbing = false;
            }
            "absorb_and_ratchet" => {
                sho.absorb_and_ratchet(&bytes(op, "input")?);
                absorbing = false;
            }
            "clone" => {
                sho = sho.clone();
            }
            "squeeze" => {
                if absorbing {
                    return Err("squeeze before ratchet".into());
                }
                let n = op["length"].as_u64().ok_or("missing length")?;
                if n > 1048576 {
                    return Err("output too large".into());
                }
                outputs.push(hex::encode(sho.squeeze_and_ratchet(n as usize)));
            }
            _ => return Err("unknown SHO operation".into()),
        }
    }
    Ok(json!({"outputs": outputs}))
}

pub fn dispatch(method: &str, p: &Value) -> Result<Value, String> {
    match method {
        "poksho.sho" => match text(p, "variant")? {
            "hmac" => run_sho::<ShoHmacSha256>(p),
            "sha" => run_sho::<ShoSha256>(p),
            _ => Err("unknown SHO variant".into()),
        },
        "poksho.prove" => {
            let st = statement(p)?;
            let proof = st
                .prove(
                    &scalars(p)?,
                    &points(p)?,
                    &bytes(p, "message")?,
                    &bytes(p, "randomness")?,
                )
                .map_err(|e| format!("{e:?}"))?;
            Ok(json!({"proof": hex::encode(proof)}))
        }
        "poksho.verify" => {
            let st = statement(p)?;
            let verified = st
                .verify_proof(&bytes(p, "proof")?, &points(p)?, &bytes(p, "message")?)
                .is_ok();
            Ok(json!({"verified": verified}))
        }
        "poksho.sign" => {
            let sig = poksho::sign(
                scalar(&bytes(p, "scalar")?)?,
                point(&bytes(p, "point")?)?,
                &bytes(p, "message")?,
                &bytes(p, "randomness")?,
            )
            .map_err(|e| format!("{e:?}"))?;
            Ok(json!({"proof": hex::encode(sig)}))
        }
        "poksho.verify_signature" => {
            let verified = poksho::verify_signature(
                &bytes(p, "proof")?,
                point(&bytes(p, "point")?)?,
                &bytes(p, "message")?,
            )
            .is_ok();
            Ok(json!({"verified": verified}))
        }
        _ => Err("unknown poksho method".into()),
    }
}

fn sequence(n: usize, offset: u8) -> Vec<u8> {
    (0..n).map(|i| (i as u8).wrapping_add(offset)).collect()
}
fn wide(offset: u8) -> Scalar {
    Scalar::from_bytes_mod_order_wide(&sequence(64, offset).try_into().unwrap())
}
fn term(s: &str, p: &str) -> Value {
    json!({"scalar":s,"point":p})
}
fn equation(lhs: &str, terms: Vec<Value>) -> Value {
    json!({"lhs":lhs,"terms":terms})
}
fn record(method: &str, params: Value) -> Value {
    let result = dispatch(method, &params).expect("valid fixed vector");
    json!({"method":method,"params":params,"result":result})
}

pub fn vectors() -> Value {
    let mut cases = Vec::new();
    for variant in ["hmac", "sha"] {
        // Original upstream test_vectors examples and block-boundary schedule.
        for n in [64, 65] {
            cases.push(record("poksho.sho",json!({"variant":variant,"label":hex::encode(b"asd"),"ops":[
                {"op":"absorb_and_ratchet","input":hex::encode(b"asdasd")},{"op":"squeeze","length":n}]})));
        }
        let mut ops = vec![json!({"op":"absorb_and_ratchet","input":hex::encode(b"abc")})];
        for n in [63, 64, 65, 127, 128, 129] {
            ops.push(json!({"op":"absorb_and_ratchet","input":hex::encode(vec![0;n])}));
        }
        for n in [63, 64, 65, 127, 128, 129] {
            ops.push(json!({"op":"squeeze","length":n}));
        }
        ops.push(json!({"op":"absorb_and_ratchet","input":hex::encode(b"def")}));
        ops.push(json!({"op":"squeeze","length":63}));
        cases.push(record(
            "poksho.sho",
            json!({"variant":variant,"label":"","ops":ops}),
        ));
        let mut ops = vec![];
        for n in [0, 1, 31, 32, 33, 63, 64, 65, 127, 128, 129] {
            ops.extend([
                json!({"op":"absorb","input":hex::encode(sequence(n,7))}),
                json!({"op":"clone"}),
                json!({"op":"absorb","input":""}),
                json!({"op":"ratchet"}),
                json!({"op":"ratchet"}),
                json!({"op":"squeeze","length":n}),
                json!({"op":"clone"}),
                json!({"op":"squeeze","length":n}),
            ]);
        }
        cases.push(record(
            "poksho.sho",
            json!({"variant":variant,"label":hex::encode(b"boundaries"),"ops":ops}),
        ));
    }
    for offset in 0..16u8 {
        let a = wide(offset);
        let public = a * G;
        // offset=0 is exactly upstream sign.rs test_signature.
        cases.push(record("poksho.sign",json!({"scalar":hex::encode(a.as_bytes()),"point":hex::encode(public.compress().as_bytes()),
            "message":hex::encode(sequence(if offset==0 {100} else {offset as usize*17},0)),"randomness":hex::encode(sequence(32,offset))})));
        let (a, b, c, d) = (
            wide(10 + offset),
            wide(20 + offset),
            wide(30 + offset),
            wide(40 + offset),
        );
        let (h, i) = (wide(50 + offset) * G, wide(60 + offset) * G);
        // offset=0 is exactly upstream statement.rs test_complex_statement.
        cases.push(record("poksho.prove",json!({
            "equations":[equation("A",vec![term("a","G"),term("b","H"),term("c","I")]), equation("B",vec![term("c","H"),term("d","I")])],
            "scalars":{"a":hex::encode(a.as_bytes()),"b":hex::encode(b.as_bytes()),"c":hex::encode(c.as_bytes()),"d":hex::encode(d.as_bytes())},
            "points":{"A":hex::encode((a*G+b*h+c*i).compress().as_bytes()),"B":hex::encode((c*h+d*i).compress().as_bytes()),"H":hex::encode(h.compress().as_bytes()),"I":hex::encode(i.compress().as_bytes())},
            "message":hex::encode(sequence(offset as usize*19,0)),"randomness":hex::encode(sequence(32,offset))})));
    }
    // Shared witness, repeated term/name and base-point LHS.
    let a = wide(19);
    let h = wide(37) * G;
    for (equations, scalars, points) in [
        (
            json!([
                equation("A", vec![term("a", "G")]),
                equation("B", vec![term("a", "H")])
            ]),
            json!({"a":hex::encode(a.as_bytes())}),
            json!({"A":hex::encode((a*G).compress().as_bytes()),"B":hex::encode((a*h).compress().as_bytes()),"H":hex::encode(h.compress().as_bytes())}),
        ),
        (
            json!([equation("A", vec![term("a", "G"), term("a", "G")])]),
            json!({"a":hex::encode(a.as_bytes())}),
            json!({"A":hex::encode(((a+a)*G).compress().as_bytes())}),
        ),
        (
            json!([equation("G", vec![term("a", "G")])]),
            json!({"a":hex::encode(Scalar::ONE.as_bytes())}),
            json!({}),
        ),
    ] {
        cases.push(record("poksho.prove",json!({"equations":equations,"scalars":scalars,"points":points,"message":"","randomness":hex::encode([0u8;32])})));
    }
    let conversions: Vec<Value> = (0..16u8).map(|offset| {
        let uniform: [u8;64] = sequence(64,offset).try_into().unwrap();
        let s = Scalar::from_bytes_mod_order_wide(&uniform);
        json!({"uniform":hex::encode(uniform),"scalar":hex::encode(s.as_bytes()),"basepoint_multiple":hex::encode((s*G).compress().as_bytes()),
            "uniform_point":hex::encode(curve25519_dalek::ristretto::RistrettoPoint::from_uniform_bytes(&uniform).compress().as_bytes())})
    }).collect();
    json!({"upstream_tag":"v0.102.2","source":"rust/poksho tests and public APIs; fixed byte sequences, no RNG","cases":cases,"conversions":conversions})
}
