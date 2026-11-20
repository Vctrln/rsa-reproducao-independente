'use strict';
/*
 * Harness comum JavaScript do protocolo publicado — mesmo contrato e mesma saída do harness C/C++
 * (paper_repro/implementations/CONTRACT.md). Cada operação é cronometrada com process.hrtime.bigint()
 * (monotônico, ns); os autores usavam performance.now(), também monotônico. Média e DP populacional por conjunto.
 *
 * lib = { meta(a), load(a), prepare(msgBuffer), enc() -> c, dec(c) -> p, cipherBytes(c) -> Buffer,
 *         cipherFromBytes(Buffer) -> c, plainBytes(p) -> Buffer, async keygen(bits) -> chave,
 *         keyinfo(chave) -> {e, nbits} (fora do cronômetro) }
 */
const fs = require('fs');
const path = require('path');

function die(code, msg) {
  process.stderr.write(`erro: ${msg}\n`);
  process.exit(code);
}

function parse(argv) {
  if (argv.length < 1) die(2, 'uso: <version|bench|encrypt|decrypt|hold> [opções]');
  const a = { mode: argv[0], keygenRounds: 1 };
  const map = { '--keydir': 'keydir', '--bits': 'bits', '--msg': 'msg', '--sets': 'sets', '--padding': 'padding',
                '--in': 'in', '--keygen-rounds': 'keygenRounds' };
  for (let i = 1; i < argv.length; i += 2) {
    if (!(argv[i] in map) || i + 1 >= argv.length) die(2, `opção inválida: ${argv[i]}`);
    a[map[argv[i]]] = argv[i + 1];
  }
  a.bits = Number(a.bits);
  a.keygenRounds = Number(a.keygenRounds);
  if (a.mode !== 'version' && ![2048, 3072, 4096].includes(a.bits)) die(2, '--bits obrigatório');
  if (a.mode !== 'version' && a.mode !== 'keygen' && !a.keydir) die(2, '--keydir obrigatório');
  a.key = (f) => path.join(a.keydir, String(a.bits), f);
  return a;
}

function printSet(n, op, t) {
  let sum = 0, mn = t[0], mx = t[0];
  for (const v of t) { sum += v; if (v < mn) mn = v; if (v > mx) mx = v; }
  const mean = sum / t.length;
  let ss = 0;
  for (const v of t) ss += (v - mean) * (v - mean);
  const f = (x) => x.toExponential(9);
  process.stdout.write(`set,${n},${op},${t.length},${f(mean)},${f(Math.sqrt(ss / t.length))},${f(mn)},${f(mx)},${f(sum)}\n`);
}

async function keygenRounds(lib, a) {
  for (let r = 1; r <= a.keygenRounds; r++) {
    const t0 = process.hrtime.bigint();
    const k = await lib.keygen(a.bits);
    const t1 = process.hrtime.bigint();
    const info = lib.keyinfo(k);
    process.stdout.write(`keygen,${a.bits},${r},${(Number(t1 - t0) * 1e-9).toExponential(9)},${info.e},${info.nbits}\n`);
  }
}

async function run(lib, argv) {
  const a = parse(argv);
  if (a.mode === 'version') { process.stdout.write(JSON.stringify(lib.meta(a)) + '\n'); return; }
  if (a.mode === 'keygen') {  // experimento independente de geração de chaves
    process.stdout.write(`meta,${JSON.stringify(lib.meta(a))}\n`);
    await keygenRounds(lib, a);
    process.stdout.write('done\n');
    return;
  }
  if (a.mode === 'decrypt') {
    lib.load(a);
    let p;
    try { p = lib.dec(lib.cipherFromBytes(Buffer.from(fs.readFileSync(a.in, 'ascii').trim(), 'hex'))); }
    catch (e) { die(4, `decifração falhou: ${e.message}`); }
    process.stdout.write(lib.plainBytes(p).toString('hex') + '\n');
    return;
  }
  if (!a.msg) die(2, '--msg obrigatório');
  const m = fs.readFileSync(a.msg);
  if (a.mode === 'encrypt') {
    lib.load(a);
    lib.prepare(m);
    let c;
    try { c = lib.enc(); } catch (e) { die(3, `cifração falhou: ${e.message}`); }
    process.stdout.write(lib.cipherBytes(c).toString('hex') + '\n');
    return;
  }
  if (a.mode === 'hold') {
    lib.load(a);
    lib.prepare(m);
    const p = lib.plainBytes(lib.dec(lib.enc()));
    process.stdout.write(`READY ${p.toString('hex')}\n`);
    await new Promise((res) => { process.stdin.once('data', res); process.stdin.once('end', res); });
    process.exit(0);
  }
  if (a.mode !== 'bench') die(2, 'modo desconhecido');
  if (!a.sets) die(2, '--sets obrigatório');
  process.stdout.write(`meta,${JSON.stringify(lib.meta(a))}\n`);
  await keygenRounds(lib, a);
  lib.load(a);
  lib.prepare(m);
  for (const s of a.sets.split(',')) {
    const n = Number(s);
    const te = new Array(n), td = new Array(n);
    for (let i = 0; i < n; i++) {
      const t0 = process.hrtime.bigint();
      const c = lib.enc();
      const t1 = process.hrtime.bigint();
      const p = lib.dec(c);
      const t2 = process.hrtime.bigint();
      if (!lib.plainBytes(p).equals(m)) die(4, 'verificação falhou: decifrado != mensagem');
      te[i] = Number(t1 - t0) * 1e-9;
      td[i] = Number(t2 - t1) * 1e-9;
    }
    printSet(n, 'encrypt', te);
    printSet(n, 'decrypt', td);
  }
  process.stdout.write('done\n');
}

function meta(id, library, version, padding, extra = {}) {
  return Object.assign({ id, language: 'JavaScript', library, library_version: version,
                         runtime: `node ${process.version}`, padding }, extra);
}

module.exports = { run, die, meta };
