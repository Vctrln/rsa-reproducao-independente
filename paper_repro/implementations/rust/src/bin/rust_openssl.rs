//! Rust OpenSSL (crate `openssl`) — protocolo publicado. Padrão conferido em Rust/openssl/benches/carregar-*.rs dos
//! autores (commit 1b3ffe0), reimplementado de forma independente:
//!  - Rsa::public_key_from_pem / private_key_from_pem;
//!  - public_encrypt / private_decrypt com Padding::PKCS1 (PKCS#1 v1.5), buffer de rsa.size() alocado a cada operação;
//!  - geração: Rsa::generate(bits) (e = 65537).
#[path = "../harness.rs"]
mod harness;

use harness::{die, run, Args, Lib};
use openssl::pkey::{Private, Public};
use openssl::rsa::{Padding, Rsa};

#[derive(Default)]
struct OpensslLib {
    pub_key: Option<Rsa<Public>>,
    priv_key: Option<Rsa<Private>>,
    gen_key: Option<Rsa<Private>>,
}

impl Lib for OpensslLib {
    fn meta(&self) -> String {
        format!("{{\"id\":\"rust_openssl\",\"language\":\"Rust\",\"library\":\"Rust OpenSSL\",\"library_version\":\"openssl crate 0.10.81 ({})\",\"runtime\":\"rustc\",\"padding\":\"pkcs1v15\"}}",
                openssl::version::version())
    }
    fn load(&mut self, a: &Args) {
        if a.padding.as_deref().map_or(false, |p| p != "pkcs1v15") {
            die(2, "Rust OpenSSL: só pkcs1v15 (Padding::PKCS1)");
        }
        let pubpem = std::fs::read(a.key("public.pem")).unwrap_or_else(|_| die(5, "public.pem"));
        let privpem = std::fs::read(a.key("private.pem")).unwrap_or_else(|_| die(5, "private.pem"));
        self.pub_key = Some(Rsa::public_key_from_pem(&pubpem).unwrap_or_else(|_| die(5, "chave pública")));
        self.priv_key = Some(Rsa::private_key_from_pem(&privpem).unwrap_or_else(|_| die(5, "chave privada")));
    }
    fn enc(&mut self, m: &[u8]) -> Result<Vec<u8>, String> {
        let k = self.pub_key.as_ref().unwrap();
        let mut out = vec![0; k.size() as usize];
        let n = k.public_encrypt(m, &mut out, Padding::PKCS1).map_err(|e| e.to_string())?;
        out.truncate(n);
        Ok(out)
    }
    fn dec(&mut self, c: &[u8]) -> Result<Vec<u8>, String> {
        let k = self.priv_key.as_ref().unwrap();
        let mut out = vec![0; k.size() as usize];
        let n = k.private_decrypt(c, &mut out, Padding::PKCS1).map_err(|e| e.to_string())?;
        out.truncate(n);
        Ok(out)
    }
    fn keygen(&mut self, bits: u32) {
        self.gen_key = Some(Rsa::generate(bits).unwrap_or_else(|_| die(5, "Rsa::generate")));
    }
    fn keyinfo(&mut self) -> (u64, usize) {
        let k = self.gen_key.take().unwrap();
        let e: u64 = k.e().to_dec_str().unwrap().parse().unwrap_or(0);
        (e, k.n().num_bits() as usize)
    }
}

fn main() {
    run(&mut OpensslLib::default());
}
