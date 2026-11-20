package paper;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.Base64;

/**
 * Harness comum Java do protocolo publicado — mesmo contrato e mesma saída do harness C/C++
 * (paper_repro/implementations/CONTRACT.md). Cada operação é cronometrada com System.nanoTime (monotônico);
 * média e desvio padrão populacional por conjunto. Verificação fora do cronômetro; divergência sai com código 4.
 *
 * As bibliotecas guardam a mensagem em prepare() e a cifram em enc(), para reproduzir o padrão dos autores
 * (que convertiam a String da mensagem em bytes DENTRO do método medido pelo JMH).
 */
public abstract class Harness {
    protected String keydir;
    protected int bits;
    protected String padding;

    protected abstract String meta();
    protected abstract void load() throws Exception;
    protected abstract void prepare(byte[] message) throws Exception;
    protected abstract Object enc() throws Exception;
    protected abstract Object dec(Object cipher) throws Exception;
    protected abstract byte[] cipherBytes(Object cipher) throws Exception;
    protected abstract Object cipherFromBytes(byte[] c) throws Exception;
    protected abstract byte[] plainBytes(Object plain) throws Exception;
    /** Gera uma chave (só isto é cronometrado) e a devolve. */
    protected abstract Object keygen(int bits) throws Exception;
    /** Fora do cronômetro: {expoente público, bits do módulo} da chave gerada. */
    protected abstract long[] keyinfo(Object key) throws Exception;

    protected Path key(String file) { return Paths.get(keydir, Integer.toString(bits), file); }

    /** PEM -> DER (cabeçalhos e quebras de linha removidos, como no código Java Crypto dos autores). */
    protected byte[] pemToDer(String file) throws Exception {
        String s = Files.readString(key(file)).replaceAll("-----BEGIN [A-Z ]+-----", "")
                .replaceAll("-----END [A-Z ]+-----", "").replaceAll("\\s", "");
        return Base64.getDecoder().decode(s);
    }

    static void die(int code, String msg) {
        System.err.println("erro: " + msg);
        System.out.flush();
        System.exit(code);
    }

    static String hex(byte[] b) {
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x & 0xff));
        return sb.toString();
    }

    static byte[] unhex(String s) {
        s = s.trim();
        byte[] b = new byte[s.length() / 2];
        for (int i = 0; i < b.length; i++) b[i] = (byte) Integer.parseInt(s.substring(2 * i, 2 * i + 2), 16);
        return b;
    }

    static void printSet(long n, String op, double[] t) {
        double sum = 0, mn = t[0], mx = t[0];
        for (double v : t) { sum += v; mn = Math.min(mn, v); mx = Math.max(mx, v); }
        double mean = sum / t.length, ss = 0;
        for (double v : t) ss += (v - mean) * (v - mean);
        System.out.println(String.format(java.util.Locale.ROOT, "set,%d,%s,%d,%.9e,%.9e,%.9e,%.9e,%.9e",
                n, op, t.length, mean, Math.sqrt(ss / t.length), mn, mx, sum));
        System.out.flush();
    }

    public void run(String[] argv) {
        try {
            if (argv.length < 1) die(2, "uso: <version|bench|encrypt|decrypt|hold> [opções]");
            String mode = argv[0], msg = null, sets = null, in = null;
            int keygenRounds = 1;
            for (int i = 1; i < argv.length; i += 2) {
                if (i + 1 >= argv.length) die(2, "opção sem valor");
                String o = argv[i], v = argv[i + 1];
                switch (o) {
                    case "--keydir": keydir = v; break;
                    case "--bits": bits = Integer.parseInt(v); break;
                    case "--msg": msg = v; break;
                    case "--sets": sets = v; break;
                    case "--padding": padding = v; break;
                    case "--in": in = v; break;
                    case "--keygen-rounds": keygenRounds = Integer.parseInt(v); break;
                    default: die(2, "opção desconhecida: " + o);
                }
            }
            if (mode.equals("version")) { System.out.println(meta()); return; }
            if (bits != 2048 && bits != 3072 && bits != 4096) die(2, "--bits obrigatório");
            if (mode.equals("keygen")) {  // experimento independente de geração de chaves
                System.out.println("meta," + meta());
                keygenRounds(keygenRounds);
                System.out.println("done");
                System.out.flush();
                return;
            }
            if (keydir == null) die(2, "--keydir obrigatório");
            if (mode.equals("decrypt")) {
                load();
                Object p;
                try { p = dec(cipherFromBytes(unhex(Files.readString(Paths.get(in))))); }
                catch (Exception e) { die(4, "decifração falhou: " + e); return; }
                System.out.println(hex(plainBytes(p)));
                return;
            }
            if (msg == null) die(2, "--msg obrigatório");
            byte[] m = Files.readAllBytes(Paths.get(msg));
            if (mode.equals("encrypt")) {
                load();
                prepare(m);
                Object c;
                try { c = enc(); } catch (Exception e) { die(3, "cifração falhou: " + e); return; }
                System.out.println(hex(cipherBytes(c)));
                return;
            }
            if (mode.equals("hold")) {
                load();
                prepare(m);
                byte[] p = plainBytes(dec(enc()));
                System.out.println("READY " + hex(p));
                System.out.flush();
                new BufferedReader(new InputStreamReader(System.in, StandardCharsets.US_ASCII)).readLine();
                return;
            }
            if (!mode.equals("bench")) die(2, "modo desconhecido");
            if (sets == null) die(2, "--sets obrigatório");
            System.out.println("meta," + meta());
            keygenRounds(keygenRounds);
            load();
            prepare(m);
            for (String s : sets.split(",")) {
                int n = Integer.parseInt(s);
                double[] te = new double[n], td = new double[n];
                for (int i = 0; i < n; i++) {
                    long t0 = System.nanoTime();
                    Object c = enc();
                    long t1 = System.nanoTime();
                    Object p = dec(c);
                    long t2 = System.nanoTime();
                    if (!Arrays.equals(plainBytes(p), m)) die(4, "verificação falhou: decifrado != mensagem");
                    te[i] = (t1 - t0) * 1e-9;
                    td[i] = (t2 - t1) * 1e-9;
                }
                printSet(n, "encrypt", te);
                printSet(n, "decrypt", td);
            }
            System.out.println("done");
            System.out.flush();
        } catch (Exception e) {
            die(5, e.toString());
        }
    }

    void keygenRounds(int rounds) throws Exception {
        for (int r = 1; r <= rounds; r++) {
            long t0 = System.nanoTime();
            Object k = keygen(bits);
            long t1 = System.nanoTime();
            long[] info = keyinfo(k);
            System.out.println(String.format(java.util.Locale.ROOT, "keygen,%d,%d,%.9e,%d,%d", bits, r, (t1 - t0) * 1e-9,
                    info[0], info[1]));
            System.out.flush();
        }
    }

    static String json(String id, String lib, String version, String padding, String extra) {
        return String.format("{\"id\":\"%s\",\"language\":\"Java\",\"library\":\"%s\",\"library_version\":\"%s\","
                + "\"runtime\":\"%s %s\",\"padding\":\"%s\"%s}", id, lib, version,
                System.getProperty("java.vm.name"), System.getProperty("java.version"), padding, extra);
    }
}
