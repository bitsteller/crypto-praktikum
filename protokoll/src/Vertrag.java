/*
 * @(#)Skeleton.java
 */

import de.tubs.cs.iti.jcrypt.protokoll.*;
import de.tubs.cs.iti.jcrypt.chiffre.*;

import java.math.*;
import java.util.*;
import java.io.*;
import java.security.MessageDigest;

/**
 *
 */

public final class Vertrag implements Protocol
{
    /**
     *
     */

    static private int MinPlayer        = 2; // Minimal number of players
    static private int MaxPlayer        = 2; // Maximal number of players
    static private String NameOfTheGame = "ABBA";
    private Communicator com;

    public static final BigInteger ZERO = BigInteger.ZERO;
    public static final BigInteger ONE = BigInteger.ONE;
    public static final BigInteger NONE = BigInteger.ONE.negate();
    public static final BigInteger TWO = BigInteger.valueOf(2L);
    public static final BigInteger THREE = BigInteger.valueOf(3L);

    public void setCommunicator(Communicator com)
    {
        this.com = com;
    }

    // alice: shareSecret("asdf", 5, true);
    // bob: shareSecret("fdsa", 5, false);

    static Random rand = new Random();

    ElGamalCipher elGamalC_own;
    ElGamalSignature elGamalS_own;
    ElGamalCipher elGamalC_other;
    ElGamalSignature elGamalS_other;
    BigInteger p;

    public void tradeElGamal(boolean first) {

        {
            // note: q is p in elgamal (too lazy to refactor that, "never touch a running system")
            // we just use a local p here, since we use it rather often anyways
            p = new BigInteger("4988735951183711405443349413015910122453507015594895638933838601555750189585703700647655985269637551634513770201277370413860951650702374379627998821919409");
            BigInteger g = new BigInteger("4403105895869798297264918950735787070665047406714785361037216842427722734684061748868589917485012596281820467352001338223691996653533143166890875549812531");
            BigInteger y = new BigInteger("3670294064109445804998782973709772470002041046377612489028768098078250713079795031354099562309432613560558383306865142781216201315104971340333690591679721");
            BigInteger x = new BigInteger("4589946301809196862611751989088793376762175950291076147544077975213763218505486754450017554342955014202444667772016113058406939298289857995054770609176615");

            // Our own cipher
            elGamalC_own = new ElGamalCipher(p, g, y, x);
            elGamalS_own = new ElGamalSignature(p, g, y, x);
        }

        if(first) {

            // send public key: p, g, y
            com.sendTo(1, p.toString(16));
            com.sendTo(1, elGamalC_own.g.toString(16));
            com.sendTo(1, elGamalC_own.y.toString(16));

            // receive p, g, y
            {
                BigInteger p = new BigInteger(com.receive(),16);
                BigInteger g = new BigInteger(com.receive(),16);
                BigInteger y = new BigInteger(com.receive(),16);

                elGamalC_other = new ElGamalCipher(p, g, y);
                elGamalS_other = new ElGamalSignature(p, g, y);
            }

        } else {

            // receive p, g, y
            {
                BigInteger p = new BigInteger(com.receive(),16);
                BigInteger g = new BigInteger(com.receive(),16);
                BigInteger y = new BigInteger(com.receive(),16);

                elGamalC_other = new ElGamalCipher(p, g, y);
                elGamalS_other = new ElGamalSignature(p, g, y);
            }

            com.sendTo(0, p.toString(16));
            com.sendTo(0, elGamalC_own.g.toString(16));
            com.sendTo(0, elGamalC_own.y.toString(16));
        }

    }

    public void otSend(int to, BigInteger M0, BigInteger M1) {

        assert(elGamalC_own != null && elGamalS_own != null);
        assert(elGamalC_other != null && elGamalS_other != null);
        assert(p != null);

        // send random m0, m1 between 0 and p. m0 != m1
        BigInteger m0, m1; {
            m0 = BigIntegerUtil.randomBetween(ZERO, p);
            do {
                m1 = BigIntegerUtil.randomBetween(ZERO, p);
            } while(m0.equals(m1));
        }

        // send both
        com.sendTo(to, m0.toString(16));
        com.sendTo(to, m1.toString(16));

        // receive q
        BigInteger q = new BigInteger(com.receive(), 16);

        BigInteger s0, s1;
        BigInteger M0_dash, M1_dash;
        int s; {

            BigInteger k0, k1; {

                // k0 = decipher((q-m0) mod p)
                k0 = elGamalC_own.decipherBlock(q.subtract(m0).mod(p.pow(2)));
                //k0 = (q.subtract(m0).mod(p)); //without elgamal
                // k1 = decipher((q-m1) mod p)
                k1 = elGamalC_own.decipherBlock(q.subtract(m1).mod(p.pow(2)));
                //k1 = (q.subtract(m1).mod(p)); //without elgamal
            }

            //S0 = sign(k0)
            s0 = elGamalS_own.signBlock(k0);
            //S1 = sign(k1)
            s1 = elGamalS_own.signBlock(k1);

            // select random s in {0,1}
            s = new Random().nextBoolean() ? 1 : 0;

            // send M_strich_0 := (M0 + k_{s xor 0}) mod p
            M0_dash = M0.add(s == 1 ? k1 : k0).mod(p);
            // send M_strich_1 := (M1 + k_{s xor 1}) mod p
            M1_dash = M1.add(s == 0 ? k1 : k0).mod(p);

        }

        com.sendTo(to, M0_dash.toString(16));
        com.sendTo(to, M1_dash.toString(16));

        // send s0, s1
        com.sendTo(to, s0.toString(16));
        com.sendTo(to, s1.toString(16));

        // send s
        com.sendTo(to, Integer.toString(s));

    }

    public BigInteger otReceive(int to) {

        //receive m0,m1
        BigInteger[] m= new BigInteger[2];
        m[0] = new BigInteger(com.receive(), 16);
        m[1] = new BigInteger(com.receive(), 16);

        //select random b in {0,1}
        BigInteger b = new BigInteger(1, new Random());

        //select random k between 0 and p
        BigInteger k;
        do {
            k = new BigInteger(p.bitLength(), new Random());
        } while (k.compareTo(p) >= 0);

        //send q:= (crypt(k) + m_b) mod p^2
        BigInteger q = elGamalC_other.encipherBlock(k).add(m[b.intValue()]).mod(p.pow(2));
        //BigInteger q = k.add(m[b.intValue()]).mod(p); // without elgamal for debugging

        com.sendTo(to, q.toString(16));

        //receive M_strich_0, M_strich_1
        BigInteger[] M_strich= new BigInteger[2];
        M_strich[0] = new BigInteger(com.receive(), 16);
        M_strich[1] = new BigInteger(com.receive(), 16);

        //receive S0,S1
        BigInteger[] S= new BigInteger[2];
        S[0] = new BigInteger(com.receive(), 16);
        S[1] = new BigInteger(com.receive(), 16);

        //receive s
        BigInteger s = new BigInteger(com.receive(), 16);

        //compute M_{s ^ b} := M_strich_{s ^ b} - k
        BigInteger M_sb = M_strich[s.xor(b).intValue()].mod(p).subtract(k).mod(p);

        //compute k_quer := M_strich_{s ^ b ^ 1} - M_{s ^ b}
        BigInteger k_quer = M_strich[s.xor(b).xor(ONE).intValue()].subtract(M_sb).mod(p);
        BigInteger k_quer2 = M_strich[s.xor(b).intValue()].subtract(M_sb).mod(p);

        if(elGamalS_other.verifyBlock(k_quer, S[b.xor(ONE).intValue()])) {
            System.err.println("KNAVE! MASQUERADER! CHARLATAN!");
            System.exit(1);
        } else {
            if (elGamalS_other.verifyBlock(k_quer2, S[b.intValue()])) {
                // System.out.println("The signature was correct!");
            }
            else {
                System.err.println("OT signature mismatch!");
                System.exit(1);
            }
        }

        return M_sb;

    }

    public static BigInteger[] genRandomPHKeys(int n, BigInteger p_a) {

        BigInteger[] ret = new BigInteger[n];
        for(int i = 0; i < ret.length; i++) {
            do {
                ret[i] = BigIntegerUtil.randomBetween(ONE, p_a);
            } while(ret[i].gcd(p_a).compareTo(ONE) != 0);
        }

        return ret;
    }

    public static BigInteger[] genPHPuzzles(final BigInteger[] in, final BigInteger m, final BigInteger p_a) {

        BigInteger[] ret = new BigInteger[in.length];
        for(int i = 0; i < ret.length; i++) {
            ret[i] = m.modPow(in[i], p_a);
        }

        return ret;
    }

    public static String genVertrag(final BigInteger[] puzzles, String file) {
        // TODO
        return "vertrag.";
    }

    public static BigInteger genDigest(String in) {

        try {
            MessageDigest sha = MessageDigest.getInstance("SHA");
            sha.update(in.getBytes());
            byte[] digest = sha.digest();

            return new BigInteger(digest);
        } catch (Exception e) {
            e.printStackTrace();
            System.exit(1);
            return null;
        }
    }

    /** This ia Alice. */
    public void sendFirst () {

        tradeElGamal(true);
        com.sendTo(1, "elgamal check.");

        final int n = rand.nextInt(10)+1;
        final BigInteger p_a = new BigInteger(52, 100, rand);
        final BigInteger M; {
             BigInteger tmp;
             do {
                 tmp = new BigInteger(p_a.bitLength()-8, rand);
             } while(tmp.compareTo(p_a) >= 0);
             M = tmp;
        }

        com.sendTo(1, Integer.toString(n, 16));
        com.sendTo(1, p_a.toString(16));
        com.sendTo(1, M.toString(16));

        final BigInteger p_b = new BigInteger(com.receive(), 16);

        // generate pohlig hellman puzzles
        final BigInteger[] keys_a = Vertrag.genRandomPHKeys(n*2, p_a);
        final BigInteger[] puzzles_a = Vertrag.genPHPuzzles(keys_a, M, p_a);
        final BigInteger[] puzzles_b = new BigInteger[n];

        // trade puzzles
        for(int i = 0; i < n; i++) {
            // send every second puzzle
            com.sendTo(1, puzzles_a[i*2].toString(16));
            puzzles_b[i] = new BigInteger(com.receive(), 16);
        }

        {
            // generate the contract thingie
            String vertrag_a = genVertrag(keys_a, "vertrag.txt");
            BigInteger hash_a = genDigest(vertrag_a);
            BigInteger signature_a = elGamalS_own.signBlock(hash_a);

            com.sendTo(1, vertrag_a);
            com.sendTo(1, signature_a.toString(16));
        }

        String vertrag_b = com.receive();

        {
            BigInteger signature_b = new BigInteger(com.receive(), 16);

            if(elGamalS_other.verifyBlock(genDigest(vertrag_b), signature_b)) {
                // NONONONONO
                com.sendTo(1, "1");
                System.err.println("That's not bob's signature!");
                System.exit(1);
            }

            // Commence operation.
            com.sendTo(1, "0");

            String commence = com.receive();
            if(!commence.equals("0")) {
                System.err.println("Bob aborted.");
                System.exit(1);
            }

        }

        // Trade puzzles using the Geheimnisaustausch thingie.

    }

    /** This is Bob. */
    public void receiveFirst () {

        tradeElGamal(false);
        System.out.println(com.receive());

        final int n = Integer.parseInt(com.receive(), 16);
        final BigInteger p_a = new BigInteger(com.receive(), 16);
        final BigInteger M = new BigInteger(com.receive(), 16);

        final BigInteger p_b = new BigInteger(52, 100, rand);

        com.sendTo(0, p_b.toString(16));

        // generate pohlig hellman puzzles
        final BigInteger[] keys_b = Vertrag.genRandomPHKeys(n*2, p_b);
        final BigInteger[] puzzles_b = Vertrag.genPHPuzzles(keys_b, M, p_b);

        // trade puzzles
        final BigInteger[] puzzles_a = new BigInteger[n];
        for(int i = 0; i < n; i++) {
            puzzles_a[i] = new BigInteger(com.receive(), 16);
            // send every second
            com.sendTo(0, puzzles_b[i*2].toString(16));
        }

        {

            String vertrag_a = com.receive();
            BigInteger signature_a = new BigInteger(com.receive(), 16);

            {
                // generate the contract thingie
                String vertrag_b = genVertrag(keys_b, "vertrag.txt");
                BigInteger hash_b = genDigest(vertrag_b);
                BigInteger signature_b = elGamalS_own.signBlock(hash_b);

                com.sendTo(0, vertrag_a);
                com.sendTo(0, signature_a.toString(16));
            }

            if(elGamalS_other.verifyBlock(genDigest(vertrag_a), signature_a)) {
                // NONONONONO
                com.sendTo(0, "1");
                System.err.println("That's not alice's signature!");
                System.exit(1);
            }

            String commence = com.receive();
            if(!commence.equals("0")) {
                System.err.println("Alice aborted.");
                System.exit(1);
            }

            // Commence operation.
            com.sendTo(1, "0");
        }

        // Trade puzzles using the Geheimnisaustausch thingie.

    }

    public String nameOfTheGame () {
        return NameOfTheGame;
    }

    public int minPlayer ()
    {
        return MinPlayer;
    }

    public int maxPlayer ()
    {
        return MaxPlayer;
    }
}
