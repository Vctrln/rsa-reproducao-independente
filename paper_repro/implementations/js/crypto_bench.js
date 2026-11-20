'use strict';
/*
 * Crypto (módulo nativo do Node.js) — protocolo publicado. Padrão conferido em JavaScript/crypto/{api.js,
 * load/rsa_teste.js} dos autores (commit 1b3ffe0), reimplementado de forma independente:
 *  - a chave é mantida como TEXTO PEM e passada a publicEncrypt/privateDecrypt a cada chamada (o Node a
 *    interpreta a cada operação, como no código dos autores);
 *  - preenchimento padrão do Node: RSA_PKCS1_OAEP_PADDING com oaepHash SHA-1 (ver a Tabela 2 do artigo);
 *  - mensagem: Buffer.from(texto, 'utf8') dentro da operação; decifrado: toString('utf8');
 *  - geração: crypto.generateKeyPair('rsa', {modulusLength, PEM spki/pkcs8}) assíncrona (e = 65537).
 */
const crypto = require('crypto');
const fs = require('fs');
const { run, die, meta } = require('./harness');

let pubPem, privPem, message;

const lib = {
  meta: () => meta('js_crypto', 'Crypto', `node ${process.versions.node} / OpenSSL ${process.versions.openssl}`,
                   'oaep-sha1'),
  load(a) {
    if (a.padding && a.padding !== 'oaep-sha1') die(2, 'Crypto: só oaep-sha1 (padrão do publicEncrypt)');
    pubPem = fs.readFileSync(a.key('public.pem'), 'utf8');
    privPem = fs.readFileSync(a.key('private.pem'), 'utf8');
  },
  prepare(m) { message = m.toString('utf8'); },
  enc: () => crypto.publicEncrypt(pubPem, Buffer.from(message, 'utf8')),
  dec: (c) => crypto.privateDecrypt(privPem, c).toString('utf8'),
  cipherBytes: (c) => c,
  cipherFromBytes: (b) => b,
  plainBytes: (p) => Buffer.from(p, 'utf8'),
  keygen: (bits) => new Promise((res, rej) => crypto.generateKeyPair('rsa', {
    modulusLength: bits,
    publicKeyEncoding: { type: 'spki', format: 'pem' },
    privateKeyEncoding: { type: 'pkcs8', format: 'pem' },
  }, (err, pub, priv) => (err ? rej(err) : res({ pub, priv })))),
  keyinfo: (k) => {
    const d = crypto.createPublicKey(k.pub).asymmetricKeyDetails;
    return { e: d.publicExponent.toString(), nbits: d.modulusLength };
  },
};

run(lib, process.argv.slice(2)).catch((e) => die(5, e.stack || String(e)));
