'use strict';
/*
 * Forge (node-forge 1.3.1) — protocolo publicado. Padrão conferido em JavaScript/forge/{api.js,load/rsa_teste.js}
 * dos autores (commit 1b3ffe0), reimplementado de forma independente:
 *  - chaves: forge.pki.publicKeyFromPem / privateKeyFromPem;
 *  - cifração: publicKey.encrypt(forge.util.encodeUtf8(msg), 'RSA-OAEP', {md: forge.md.sha256.create()}),
 *    com um objeto de hash NOVO a cada chamada; o MGF1 usa o mesmo hash (padrão do forge, lib/pkcs1.js);
 *  - decifração: privateKey.decrypt(..., 'RSA-OAEP', {md: sha256}) e forge.util.decodeUtf8;
 *  - geração: forge.pki.rsa.generateKeyPair({bits, e: 0x10001}, callback). ATENÇÃO: com callback e em Node.js o
 *    forge 1.3.1 DELEGA a geração ao crypto.generateKeyPair nativo (lib/rsa.js, _detectNodeCrypto) — o tempo de
 *    geração do "Forge" é, na prática, o do OpenSSL embutido no Node. Reproduzido como os autores fizeram.
 * Com OAEP/SHA-256 o limite efetivo em RSA-2048 é 190 B; o limite declarado na Tabela 2 do artigo difere dele e
 * sua origem não foi encontrada no código dos autores. O teste de limites mede o valor efetivo.
 */
const fs = require('fs');
const path = require('path');
const forge = require(path.join(__dirname, '..', '..', 'vendor', 'node_modules', 'node-forge'));
const { run, die, meta } = require('./harness');

let pub, priv, message;

const lib = {
  meta: () => meta('js_forge', 'Forge', `node-forge ${require(path.join(__dirname, '..', '..', 'vendor', 'node_modules',
    'node-forge', 'package.json')).version}`, 'oaep-sha256', { keygen_delegates_to: 'node:crypto.generateKeyPair' }),
  load(a) {
    if (a.padding && a.padding !== 'oaep-sha256') die(2, 'Forge: só oaep-sha256 (código dos autores)');
    pub = forge.pki.publicKeyFromPem(fs.readFileSync(a.key('public.pem'), 'utf8'));
    priv = forge.pki.privateKeyFromPem(fs.readFileSync(a.key('private.pem'), 'utf8'));
  },
  prepare(m) { message = m.toString('utf8'); },
  enc: () => pub.encrypt(forge.util.encodeUtf8(message), 'RSA-OAEP', { md: forge.md.sha256.create() }),
  dec: (c) => forge.util.decodeUtf8(priv.decrypt(c, 'RSA-OAEP', { md: forge.md.sha256.create() })),
  cipherBytes: (c) => Buffer.from(c, 'binary'),
  cipherFromBytes: (b) => b.toString('binary'),
  plainBytes: (p) => Buffer.from(p, 'utf8'),
  keygen: (bits) => new Promise((res, rej) => forge.pki.rsa.generateKeyPair({ bits, e: 0x10001 },
    (err, kp) => (err ? rej(err) : res(kp)))),
  keyinfo: (kp) => ({ e: kp.publicKey.e.toString(), nbits: kp.publicKey.n.bitLength() }),
};

run(lib, process.argv.slice(2)).catch((e) => die(5, e.stack || String(e)));
