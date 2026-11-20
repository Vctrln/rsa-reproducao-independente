package paper;

import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.SecureRandom;

import org.bouncycastle.asn1.pkcs.PrivateKeyInfo;
import org.bouncycastle.asn1.pkcs.RSAPrivateKey;
import org.bouncycastle.asn1.pkcs.RSAPublicKey;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.crypto.AsymmetricBlockCipher;
import org.bouncycastle.crypto.engines.RSAEngine;
import org.bouncycastle.crypto.generators.RSAKeyPairGenerator;
import org.bouncycastle.crypto.params.RSAKeyGenerationParameters;
import org.bouncycastle.crypto.params.RSAKeyParameters;
import org.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;

/**
 * Bouncy Castle (Java) — protocolo publicado. Padrão conferido em Java/Bouncy Castle/load/.../Carregar.java dos
 * autores (commit 1b3ffe0; bcprov-jdk18on 1.79 no pom.xml), reimplementado de forma independente:
 *  - API leve do BC: RSAEngine NOVO a cada operação, SEM preenchimento (ver a Tabela 2 do artigo);
 *  - cifração: String da mensagem -> getBytes("UTF-8") -> processBlock -> String hexadecimal (tudo no método medido);
 *  - decifração: hex -> bytes -> processBlock -> new String(...) (idem);
 *  - geração: RSAKeyPairGenerator, e = 0x10001, SecureRandom "SHA1PRNG", certeza 80 (valores dos autores).
 * Adaptação: os autores liam o PEM com PEMParser (bcpkix); aqui o PEM é decodificado em Base64 e interpretado pelas
 * MESMAS classes ASN.1 do bcprov (PrivateKeyInfo/RSAPrivateKey, SubjectPublicKeyInfo/RSAPublicKey).
 */
public class BouncyCastleBench extends Harness {
    private RSAKeyParameters pub;
    private RSAPrivateCrtKeyParameters priv;
    private String plainMessage;

    protected String meta() {
        return json("java_bouncycastle", "Bouncy Castle",
                org.bouncycastle.jce.provider.BouncyCastleProvider.class.getPackage().getImplementationVersion() == null
                        ? new org.bouncycastle.jce.provider.BouncyCastleProvider().getVersionStr()
                        : org.bouncycastle.jce.provider.BouncyCastleProvider.class.getPackage().getImplementationVersion(),
                "raw", "");
    }

    protected void load() throws Exception {
        if (padding != null && !padding.equals("raw")) die(2, "Bouncy Castle: só raw (RSAEngine)");
        RSAPublicKey rp = RSAPublicKey.getInstance(SubjectPublicKeyInfo.getInstance(pemToDer("public.pem")).parsePublicKey());
        pub = new RSAKeyParameters(false, rp.getModulus(), rp.getPublicExponent());
        RSAPrivateKey k = RSAPrivateKey.getInstance(PrivateKeyInfo.getInstance(pemToDer("private.pem")).parsePrivateKey());
        priv = new RSAPrivateCrtKeyParameters(k.getModulus(), k.getPublicExponent(), k.getPrivateExponent(),
                k.getPrime1(), k.getPrime2(), k.getExponent1(), k.getExponent2(), k.getCoefficient());
    }

    protected void prepare(byte[] message) { plainMessage = new String(message, StandardCharsets.UTF_8); }

    protected Object enc() throws Exception {
        byte[] data = plainMessage.getBytes("UTF-8");
        RSAEngine engine = new RSAEngine();
        engine.init(true, pub);
        return hex(engine.processBlock(data, 0, data.length));
    }

    protected Object dec(Object cipher) throws Exception {
        AsymmetricBlockCipher engine = new RSAEngine();
        engine.init(false, priv);
        byte[] c = unhex((String) cipher);
        return new String(engine.processBlock(c, 0, c.length), StandardCharsets.UTF_8);
    }

    protected byte[] cipherBytes(Object c) { return unhex((String) c); }
    protected Object cipherFromBytes(byte[] c) { return hex(c); }
    protected byte[] plainBytes(Object p) { return ((String) p).getBytes(StandardCharsets.UTF_8); }

    protected Object keygen(int bits) throws Exception {
        RSAKeyPairGenerator g = new RSAKeyPairGenerator();
        g.init(new RSAKeyGenerationParameters(new BigInteger("10001", 16), SecureRandom.getInstance("SHA1PRNG"), bits, 80));
        return g.generateKeyPair();
    }

    protected long[] keyinfo(Object key) {
        RSAKeyParameters p = (RSAKeyParameters) ((org.bouncycastle.crypto.AsymmetricCipherKeyPair) key).getPublic();
        return new long[] {p.getExponent().longValueExact(), p.getModulus().bitLength()};
    }

    public static void main(String[] a) { new BouncyCastleBench().run(a); }
}
