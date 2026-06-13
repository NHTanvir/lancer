//! NTLM (NTLMv2) authentication — §23 platform auth.
//!
//! Implements the real Type 1 (Negotiate) and Type 3 (Authenticate) messages
//! with an inline MD4 (for the NT hash) and HMAC-MD5 (for the NTLMv2 proof),
//! replacing the previous placeholder. Negotiate/SPNEGO Kerberos still needs a
//! system GSSAPI/SSPI provider and is out of scope here.

use base64::Engine;
use md5::{Digest, Md5};

const SIGNATURE: &[u8] = b"NTLMSSP\0";
// UNICODE | OEM | REQUEST_TARGET | NTLM | ALWAYS_SIGN | EXTENDED_SESSIONSECURITY | 128 | 56
const NEG_FLAGS: u32 = 0x0008_8207 | 0x0008_0000 | 0xA000_0000;

fn b64(b: &[u8]) -> String {
    base64::engine::general_purpose::STANDARD.encode(b)
}

fn utf16le(s: &str) -> Vec<u8> {
    s.encode_utf16().flat_map(|u| u.to_le_bytes()).collect()
}

/// Type 1 (Negotiate) message — sent on the first challenge.
pub fn type1() -> String {
    let mut m = Vec::with_capacity(40);
    m.extend_from_slice(SIGNATURE);
    m.extend_from_slice(&1u32.to_le_bytes()); // MessageType = 1
    m.extend_from_slice(&NEG_FLAGS.to_le_bytes());
    // Empty Domain + Workstation security buffers (len, maxlen, offset).
    m.extend_from_slice(&[0u8; 8]);
    m.extend_from_slice(&[0u8; 8]);
    b64(&m)
}

// ── MD4 (RFC 1320), needed for the NT hash ──────────────────────────────────

fn md4(input: &[u8]) -> [u8; 16] {
    let mut a: u32 = 0x6745_2301;
    let mut b: u32 = 0xefcd_ab89;
    let mut c: u32 = 0x98ba_dcfe;
    let mut d: u32 = 0x1032_5476;

    let mut msg = input.to_vec();
    let bit_len = (input.len() as u64).wrapping_mul(8);
    msg.push(0x80);
    while msg.len() % 64 != 56 {
        msg.push(0);
    }
    msg.extend_from_slice(&bit_len.to_le_bytes());

    let f = |x: u32, y: u32, z: u32| (x & y) | (!x & z);
    let g = |x: u32, y: u32, z: u32| (x & y) | (x & z) | (y & z);
    let h = |x: u32, y: u32, z: u32| x ^ y ^ z;

    for chunk in msg.chunks(64) {
        let mut x = [0u32; 16];
        for (i, w) in x.iter_mut().enumerate() {
            *w = u32::from_le_bytes([chunk[i * 4], chunk[i * 4 + 1], chunk[i * 4 + 2], chunk[i * 4 + 3]]);
        }
        let (mut aa, mut bb, mut cc, mut dd) = (a, b, c, d);
        // Round 1
        for &k in &[0, 4, 8, 12] {
            aa = aa.wrapping_add(f(bb, cc, dd)).wrapping_add(x[k]).rotate_left(3);
            dd = dd.wrapping_add(f(aa, bb, cc)).wrapping_add(x[k + 1]).rotate_left(7);
            cc = cc.wrapping_add(f(dd, aa, bb)).wrapping_add(x[k + 2]).rotate_left(11);
            bb = bb.wrapping_add(f(cc, dd, aa)).wrapping_add(x[k + 3]).rotate_left(19);
        }
        // Round 2
        for &k in &[0, 1, 2, 3] {
            aa = aa.wrapping_add(g(bb, cc, dd)).wrapping_add(x[k]).wrapping_add(0x5a82_7999).rotate_left(3);
            dd = dd.wrapping_add(g(aa, bb, cc)).wrapping_add(x[k + 4]).wrapping_add(0x5a82_7999).rotate_left(5);
            cc = cc.wrapping_add(g(dd, aa, bb)).wrapping_add(x[k + 8]).wrapping_add(0x5a82_7999).rotate_left(9);
            bb = bb.wrapping_add(g(cc, dd, aa)).wrapping_add(x[k + 12]).wrapping_add(0x5a82_7999).rotate_left(13);
        }
        // Round 3
        for &k in &[0, 2, 1, 3] {
            aa = aa.wrapping_add(h(bb, cc, dd)).wrapping_add(x[k]).wrapping_add(0x6ed9_eba1).rotate_left(3);
            dd = dd.wrapping_add(h(aa, bb, cc)).wrapping_add(x[k + 8]).wrapping_add(0x6ed9_eba1).rotate_left(9);
            cc = cc.wrapping_add(h(dd, aa, bb)).wrapping_add(x[k + 4]).wrapping_add(0x6ed9_eba1).rotate_left(11);
            bb = bb.wrapping_add(h(cc, dd, aa)).wrapping_add(x[k + 12]).wrapping_add(0x6ed9_eba1).rotate_left(15);
        }
        a = a.wrapping_add(aa);
        b = b.wrapping_add(bb);
        c = c.wrapping_add(cc);
        d = d.wrapping_add(dd);
    }
    let mut out = [0u8; 16];
    out[0..4].copy_from_slice(&a.to_le_bytes());
    out[4..8].copy_from_slice(&b.to_le_bytes());
    out[8..12].copy_from_slice(&c.to_le_bytes());
    out[12..16].copy_from_slice(&d.to_le_bytes());
    out
}

fn hmac_md5(key: &[u8], msg: &[u8]) -> [u8; 16] {
    let mut k = [0u8; 64];
    if key.len() > 64 {
        let h = Md5::digest(key);
        k[..16].copy_from_slice(&h);
    } else {
        k[..key.len()].copy_from_slice(key);
    }
    let mut ipad = [0x36u8; 64];
    let mut opad = [0x5cu8; 64];
    for i in 0..64 {
        ipad[i] ^= k[i];
        opad[i] ^= k[i];
    }
    let mut inner = Md5::new();
    inner.update(ipad);
    inner.update(msg);
    let inner = inner.finalize();
    let mut outer = Md5::new();
    outer.update(opad);
    outer.update(inner);
    let r = outer.finalize();
    let mut out = [0u8; 16];
    out.copy_from_slice(&r);
    out
}

/// Type 3 (Authenticate) message answering a Type 2 challenge.
/// `type2_b64` is the base64 token from the server's `WWW-Authenticate: NTLM …`.
pub fn type3(type2_b64: &str, user: &str, password: &str, domain: &str, client_challenge: [u8; 8], timestamp: u64) -> Option<String> {
    let t2 = base64::engine::general_purpose::STANDARD.decode(type2_b64.trim()).ok()?;
    if t2.len() < 32 || &t2[0..8] != SIGNATURE {
        return None;
    }
    let server_challenge = &t2[24..32];
    // Target info security buffer (offset 40, len at 40).
    let target_info = if t2.len() >= 48 {
        let ti_len = u16::from_le_bytes([t2[40], t2[41]]) as usize;
        let ti_off = u32::from_le_bytes([t2[44], t2[45], t2[46], t2[47]]) as usize;
        if ti_off + ti_len <= t2.len() { t2[ti_off..ti_off + ti_len].to_vec() } else { Vec::new() }
    } else {
        Vec::new()
    };

    // NTLMv2 key chain.
    let nt_hash = md4(&utf16le(password));
    let ntlmv2_hash = hmac_md5(&nt_hash, &utf16le(&(user.to_uppercase() + domain)));

    // NTLMv2 blob.
    let mut blob = Vec::new();
    blob.extend_from_slice(&[0x01, 0x01, 0x00, 0x00]); // header
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // reserved
    blob.extend_from_slice(&timestamp.to_le_bytes()); // timestamp
    blob.extend_from_slice(&client_challenge); // client challenge
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // unknown
    blob.extend_from_slice(&target_info); // target info
    blob.extend_from_slice(&[0x00, 0x00, 0x00, 0x00]); // unknown

    let mut proof_input = Vec::new();
    proof_input.extend_from_slice(server_challenge);
    proof_input.extend_from_slice(&blob);
    let nt_proof = hmac_md5(&ntlmv2_hash, &proof_input);

    let mut nt_response = Vec::new();
    nt_response.extend_from_slice(&nt_proof);
    nt_response.extend_from_slice(&blob);

    // Assemble Type 3.
    let lm_response = [0u8; 24];
    let domain_u = utf16le(domain);
    let user_u = utf16le(user);
    let host_u = utf16le("LANCER");

    let mut payload = Vec::new();
    let mut offset = 64u32; // fixed header size
    let mut buf = |data: &[u8], off: &mut u32, payload: &mut Vec<u8>| -> [u8; 8] {
        let len = data.len() as u16;
        let sb = {
            let mut sb = [0u8; 8];
            sb[0..2].copy_from_slice(&len.to_le_bytes());
            sb[2..4].copy_from_slice(&len.to_le_bytes());
            sb[4..8].copy_from_slice(&off.to_le_bytes());
            sb
        };
        payload.extend_from_slice(data);
        *off += len as u32;
        sb
    };
    let lm_sb = buf(&lm_response, &mut offset, &mut payload);
    let nt_sb = buf(&nt_response, &mut offset, &mut payload);
    let dom_sb = buf(&domain_u, &mut offset, &mut payload);
    let user_sb = buf(&user_u, &mut offset, &mut payload);
    let host_sb = buf(&host_u, &mut offset, &mut payload);
    let sess_sb = buf(&[], &mut offset, &mut payload);

    let mut m = Vec::new();
    m.extend_from_slice(SIGNATURE);
    m.extend_from_slice(&3u32.to_le_bytes()); // MessageType = 3
    m.extend_from_slice(&lm_sb);
    m.extend_from_slice(&nt_sb);
    m.extend_from_slice(&dom_sb);
    m.extend_from_slice(&user_sb);
    m.extend_from_slice(&host_sb);
    m.extend_from_slice(&sess_sb);
    m.extend_from_slice(&NEG_FLAGS.to_le_bytes());
    debug_assert_eq!(m.len(), 64);
    m.extend_from_slice(&payload);
    Some(b64(&m))
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn md4_known_vectors() {
        // MD4("") = 31d6cfe0d16ae931b73c59d7e0c089c0
        assert_eq!(hex::encode(md4(b"")), "31d6cfe0d16ae931b73c59d7e0c089c0");
        // MD4("abc") = a448017aaf21d8525fc10ae87aa6729d
        assert_eq!(hex::encode(md4(b"abc")), "a448017aaf21d8525fc10ae87aa6729d");
    }
    #[test]
    fn type1_is_ntlmssp() {
        let t1 = base64::engine::general_purpose::STANDARD.decode(type1()).unwrap();
        assert_eq!(&t1[0..8], SIGNATURE);
        assert_eq!(&t1[8..12], &[1, 0, 0, 0]);
    }
}
