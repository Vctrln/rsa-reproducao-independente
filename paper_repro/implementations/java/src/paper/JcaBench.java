package paper;

import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

import javax.crypto.Cipher;

/**
 * Java Crypto (JCA/SunJCE) — protocolo publicado. Padrão conferido em Java/Crypto/load/.../Carregar.java dos autores
 * (commit 1b3ffe0), reimplementado de forma independente:
 *  - PEM -> Base64 -> PKCS8EncodedKeySpec / X509EncodedKeySpec -> KeyFactory "RSA";
 *  - Cipher.getInstance("RSA") NOVO a cada operação. No provedor SunJCE "RSA" = "RSA/ECB/PKCS1Padding"
 *    (PKCS#1 v1.5; ver a Tabela 2 do artigo); o teste de interoperabilidade confere isso;
 *  - geração: KeyPairGenerator "RSA" initialize(bits) (e = 65537, padrão do JDK).
 */
public class JcaBench extends Harness {
    private PublicKey pub;
    private PrivateKey priv;
    private String plainMessage;

    protected String meta() {
        return json("java_jca", "Java Crypto", System.getProperty("java.version") + " (SunJCE)", "pkcs1v15",
                ",\"transformation\":\"RSA\"");
    }

    protected void load() throws Exception {
        if (padding != null && !padding.equals("pkcs1v15")) die(2, "Java Crypto: só pkcs1v15 (\"RSA\")");
        KeyFactory kf = KeyFactory.getInstance("RSA");
        pub = kf.generatePublic(new X509EncodedKeySpec(pemToDer("public.pem")));
        priv = kf.generatePrivate(new PKCS8EncodedKeySpec(pemToDer("private.pem")));
    }

    protected void prepare(byte[] message) { plainMessage = new String(message, StandardCharsets.UTF_8); }

    protected Object enc() throws Exception {
        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.ENCRYPT_MODE, pub);
        return c.doFinal(plainMessage.getBytes("UTF-8"));
    }

    protected Object dec(Object cipher) throws Exception {
        Cipher c = Cipher.getInstance("RSA");
        c.init(Cipher.DECRYPT_MODE, priv);
        return c.doFinal((byte[]) cipher);
    }

    protected byte[] cipherBytes(Object c) { return (byte[]) c; }
    protected Object cipherFromBytes(byte[] c) { return c; }
    protected byte[] plainBytes(Object p) { return (byte[]) p; }

    protected Object keygen(int bits) throws Exception {
        KeyPairGenerator g = KeyPairGenerator.getInstance("RSA");
        g.initialize(bits);
        return g.generateKeyPair();
    }

    protected long[] keyinfo(Object key) {
        java.security.interfaces.RSAPublicKey p = (java.security.interfaces.RSAPublicKey) ((java.security.KeyPair) key).getPublic();
        return new long[] {p.getPublicExponent().longValueExact(), p.getModulus().bitLength()};
    }

    public static void main(String[] a) { new JcaBench().run(a); }
}
