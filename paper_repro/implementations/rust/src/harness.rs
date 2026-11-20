//! Harness comum Rust do protocolo publicado — mesmo contrato e mesma saída do harness C/C++
//! (paper_repro/implementations/CONTRACT.md). Cada operação é cronometrada com std::time::Instant (monotônico);
//! média e DP populacional por conjunto. Verificação fora do cronômetro; divergência sai com código 4.
//!
//! DIVERGÊNCIA EM RELAÇÃO AO CÓDIGO DOS AUTORES: os autores usavam Criterion, cujo parâmetro 10/100/1000/10000 NÃO era usado
//! (`|b, &_size| b.iter(...)`) — o Criterion escolhe sozinho o número de iterações e amostras. Aqui o tamanho do
//! conjunto é respeitado de fato, como no protocolo descrito no artigo.

use std::io::{BufRead, Write};
use std::path::PathBuf;
use std::time::Instant;

pub struct Args {
    pub mode: String,
    pub keydir: String,
    pub bits: u32,
    pub msg: Option<String>,
    pub sets: Option<String>,
    pub padding: Option<String>,
    pub input: Option<String>,
    pub keygen_rounds: u32,
}

impl Args {
    pub fn key(&self, f: &str) -> PathBuf {
        PathBuf::from(&self.keydir).join(self.bits.to_string()).join(f)
    }
}

pub trait Lib {
    fn meta(&self) -> String;
    fn load(&mut self, a: &Args);
    fn enc(&mut self, m: &[u8]) -> Result<Vec<u8>, String>;
    fn dec(&mut self, c: &[u8]) -> Result<Vec<u8>, String>;
    /// Gera uma chave (só isto é cronometrado) e a guarda.
    fn keygen(&mut self, bits: u32);
    /// Fora do cronômetro: (expoente público, bits do módulo) da chave gerada; descarta-a.
    fn keyinfo(&mut self) -> (u64, usize);
}

pub fn die(code: i32, msg: &str) -> ! {
    eprintln!("erro: {}", msg);
    let _ = std::io::stdout().flush();
    std::process::exit(code)
}

fn hex(b: &[u8]) -> String {
    b.iter().map(|x| format!("{:02x}", x)).collect()
}

fn unhex(s: &str) -> Vec<u8> {
    let s = s.trim();
    (0..s.len() / 2).map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap_or_else(|_| die(2, "hex inválido"))).collect()
}

fn parse() -> Args {
    let v: Vec<String> = std::env::args().skip(1).collect();
    if v.is_empty() {
        die(2, "uso: <version|bench|encrypt|decrypt|hold> [opções]");
    }
    let mut a = Args { mode: v[0].clone(), keydir: String::new(), bits: 0, msg: None, sets: None, padding: None,
                       input: None, keygen_rounds: 1 };
    let mut i = 1;
    while i < v.len() {
        if i + 1 >= v.len() {
            die(2, "opção sem valor");
        }
        let val = v[i + 1].clone();
        match v[i].as_str() {
            "--keydir" => a.keydir = val,
            "--bits" => a.bits = val.parse().unwrap_or(0),
            "--msg" => a.msg = Some(val),
            "--sets" => a.sets = Some(val),
            "--padding" => a.padding = Some(val),
            "--in" => a.input = Some(val),
            "--keygen-rounds" => a.keygen_rounds = val.parse().unwrap_or_else(|_| die(2, "--keygen-rounds")),
            o => die(2, &format!("opção desconhecida: {}", o)),
        }
        i += 2;
    }
    if a.mode != "version" && ![2048, 3072, 4096].contains(&a.bits) {
        die(2, "--bits obrigatório");
    }
    if a.mode != "version" && a.mode != "keygen" && a.keydir.is_empty() {
        die(2, "--keydir obrigatório");
    }
    a
}

fn print_set(n: usize, op: &str, t: &[f64]) {
    let sum: f64 = t.iter().sum();
    let mean = sum / t.len() as f64;
    let mn = t.iter().cloned().fold(f64::INFINITY, f64::min);
    let mx = t.iter().cloned().fold(f64::NEG_INFINITY, f64::max);
    let sd = (t.iter().map(|x| (x - mean) * (x - mean)).sum::<f64>() / t.len() as f64).sqrt();
    println!("set,{},{},{},{:.9e},{:.9e},{:.9e},{:.9e},{:.9e}", n, op, t.len(), mean, sd, mn, mx, sum);
    let _ = std::io::stdout().flush();
}

fn keygen_rounds<L: Lib>(lib: &mut L, a: &Args) {
    for r in 1..=a.keygen_rounds {
        let t0 = Instant::now();
        lib.keygen(a.bits);
        let secs = t0.elapsed().as_secs_f64();
        let (e, nbits) = lib.keyinfo();
        println!("keygen,{},{},{:.9e},{},{}", a.bits, r, secs, e, nbits);
        let _ = std::io::stdout().flush();
    }
}

pub fn run<L: Lib>(lib: &mut L) {
    let a = parse();
    if a.mode == "version" {
        println!("{}", lib.meta());
        return;
    }
    if a.mode == "keygen" {
        // experimento independente de geração de chaves
        println!("meta,{}", lib.meta());
        keygen_rounds(lib, &a);
        println!("done");
        return;
    }
    if a.mode == "decrypt" {
        let path = a.input.clone().unwrap_or_else(|| die(2, "--in obrigatório"));
        let c = unhex(&std::fs::read_to_string(path).unwrap_or_else(|_| die(5, "leitura de --in")));
        lib.load(&a);
        let p = lib.dec(&c).unwrap_or_else(|e| die(4, &format!("decifração falhou: {}", e)));
        println!("{}", hex(&p));
        return;
    }
    let m = std::fs::read(a.msg.clone().unwrap_or_else(|| die(2, "--msg obrigatório")))
        .unwrap_or_else(|_| die(5, "leitura da mensagem"));
    if a.mode == "encrypt" {
        lib.load(&a);
        let c = lib.enc(&m).unwrap_or_else(|e| die(3, &format!("cifração falhou: {}", e)));
        println!("{}", hex(&c));
        return;
    }
    if a.mode == "hold" {
        lib.load(&a);
        let c = lib.enc(&m).unwrap_or_else(|e| die(4, &e));
        let p = lib.dec(&c).unwrap_or_else(|e| die(4, &e));
        println!("READY {}", hex(&p));
        let _ = std::io::stdout().flush();
        let mut line = String::new();
        let _ = std::io::stdin().lock().read_line(&mut line);
        return;
    }
    if a.mode != "bench" {
        die(2, "modo desconhecido");
    }
    let sets = a.sets.clone().unwrap_or_else(|| die(2, "--sets obrigatório"));
    println!("meta,{}", lib.meta());
    keygen_rounds(lib, &a);
    lib.load(&a);
    for s in sets.split(',') {
        let n: usize = s.parse().unwrap_or_else(|_| die(2, "--sets inválido"));
        let mut te = vec![0f64; n];
        let mut td = vec![0f64; n];
        for i in 0..n {
            let t0 = Instant::now();
            let c = lib.enc(&m);
            let t1 = Instant::now();
            let p = c.as_ref().map_err(|e| e.clone()).and_then(|c| lib.dec(c));
            let t2 = Instant::now();
            match p {
                Ok(ref p) if *p == m => {}
                _ => die(4, "verificação falhou: decifrado != mensagem"),
            }
            te[i] = (t1 - t0).as_secs_f64();
            td[i] = (t2 - t1).as_secs_f64();
        }
        print_set(n, "encrypt", &te);
        print_set(n, "decrypt", &td);
    }
    println!("done");
}
