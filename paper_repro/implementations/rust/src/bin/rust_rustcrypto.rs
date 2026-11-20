//! Rust Crypto (crate `rsa` 0.9.7, RustCrypto) — protocolo publicado. Padrão conferido em
//! Rust/Rust Crypto/benches/carregar-*.rs dos autores (commit 1b3ffe0), reimplementado de forma independente:
//!  - RsaPublicKey::from_public_key_pem / RsaPrivateKey::from_pkcs8_pem;
//!  - encrypt(&mut thread_rng, Pkcs1v15Encrypt, m) / decrypt(Pkcs1v15Encrypt, c) — decifração SEM blinding
//!    explícito (`decrypt`, não `decrypt_blinded`), exatamente a chamada dos autores; é a variante associada ao
//!    ataque Marvin citado no artigo (§4.2, RUSTSEC-2023-0071);
//!  - geração: RsaPrivateKey::new(&mut rng, bits) + RsaPublicKey::from (e = 65537).
#[path = "../harness.rs"]
mod harness;

use harness::{die, run, Args, Lib};
use rand::rngs::ThreadRng;
use rsa::pkcs8::{DecodePrivateKey, DecodePublicKey};
use rsa::{Pkcs1v15Encrypt, RsaPrivateKey, RsaPublicKey};

struct RustCryptoLib {
    pub_key: Option<RsaPublicKey>,
    priv_key: Option<RsaPrivateKey>,
    gen_key: Option<RsaPrivateKey>,
    rng: ThreadRng,
}

impl Lib for RustCryptoLib {
    fn meta(&self) -> String {
        "{\"id\":\"rust_rustcrypto\",\"language\":\"Rust\",\"library\":\"Rust Crypto\",\"library_version\":\"rsa 0.9.7\",\"runtime\":\"rustc\",\"padding\":\"pkcs1v15\"}".to_string()
    }
    fn load(&mut self, a: &Args) {
        if a.padding.as_deref().map_or(false, |p| p != "pkcs1v15") {
            die(2, "Rust Crypto: só pkcs1v15 (Pkcs1v15Encrypt)");
        }
        let pubpem = std::fs::read_to_string(a.key("public.pem")).unwrap_or_else(|_| die(5, "public.pem"));
        let privpem = std::fs::read_to_string(a.key("private.pem")).unwrap_or_else(|_| die(5, "private.pem"));
        self.pub_key = Some(RsaPublicKey::from_public_key_pem(&pubpem).unwrap_or_else(|_| die(5, "chave pública")));
        self.priv_key = Some(RsaPrivateKey::from_pkcs8_pem(&privpem).unwrap_or_else(|_| die(5, "chave privada")));
    }
    fn enc(&mut self, m: &[u8]) -> Result<Vec<u8>, String> {
        self.pub_key.as_ref().unwrap().encrypt(&mut self.rng, Pkcs1v15Encrypt, m).map_err(|e| e.to_string())
    }
    fn dec(&mut self, c: &[u8]) -> Result<Vec<u8>, String> {
        self.priv_key.as_ref().unwrap().decrypt(Pkcs1v15Encrypt, c).map_err(|e| e.to_string())
    }
    fn keygen(&mut self, bits: u32) {
        let k = RsaPrivateKey::new(&mut self.rng, bits as usize).unwrap_or_else(|_| die(5, "RsaPrivateKey::new"));
        let _p = RsaPublicKey::from(&k);
        self.gen_key = Some(k);
    }
    fn keyinfo(&mut self) -> (u64, usize) {
        use rsa::traits::PublicKeyParts;
        let k = self.gen_key.take().unwrap();
        let e: u64 = k.e().to_string().parse().unwrap_or(0);
        (e, k.n().bits())
    }
}

fn main() {
    run(&mut RustCryptoLib { pub_key: None, priv_key: None, gen_key: None, rng: rand::thread_rng() });
}
