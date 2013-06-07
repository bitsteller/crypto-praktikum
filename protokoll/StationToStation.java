/*
 * @(#)Skeleton.java
 */

import de.tubs.cs.iti.jcrypt.protokoll.*;
import de.tubs.cs.iti.jcrypt.chiffre.*;

import java.math.*;
import java.util.*;

/**
 *
 */

public final class StationToStation implements Protocol
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

    /** This ia Alice. */
    public void sendFirst () {
        Random rand = new Random();

        BigInteger p, g, x_a, y_a; {

            // p = prime
            BigInteger q;
            do {
                q = new BigInteger(511, rand); // p = random 512 bit number
                p = q.multiply(TWO).add(ONE); // p = 2q+1
            } while(!p.isProbablePrime(42));

            // g = primitive wurzel mod p

            // same algorithm to find a generator
            BigInteger pMinusOne = p.subtract(ONE);
            do {
                // choose 2 < g < q, we should have a 50% probability of hitting a generating number here.
                g = BigIntegerUtil.randomBetween(THREE, pMinusOne, rand);
                // check if the required criteria for a generator of G applies
            } while(!p.modPow(q, p).equals(pMinusOne));

            // x_a \in Z_p
            x_a = BigIntegerUtil.randomBetween(TWO, p.subtract(TWO));

            // y_a = g^{x_a} mod p
            y_a = g.modPow(x_a, p);

        }

        // send p, g, y_a
        com.sendTo(2, p.toString());
        com.sendTo(2, g.toString());
        com.sendTo(2, y_a.toString());

        BigInteger K; {

            // receive y_b, cert_b, xm_b
            BigInteger y_b = new BigInteger(com.receive());
            BigInteger cert_b = new BigInteger(com.receive());
            BigInteger xm_b = new BigInteger(com.receive());

            // CHECK(cert_b)

            // K = y_b^{x_a} mod p
            K = y_b.modPow(x_a, p);

            // m_b = UNIDEA(K, xm_b)

            // test m_b == HASH(y_b*p + y_a)

            // xm_a = IDEA(K, HASH(y_a*p + y_b)

        }

        // send cert_a, xm_a

        // chat
    }

    /** This is Bob. */
    public void receiveFirst () {
        // receive p, g, y_a

        // x_b \in Z_p
        // K = y_a^{x_b} mod p
        // y_b = g^{x_b} mod p
        // xm_b = IDEA(K, HASH(y_b*p + y_a)

        // send y_b, cert_b, xm_b

        // receive cert_a, xm_a

        // CHECK(cert_a)
        // m_a = IDEA(K, xm_a)
        // test m_b == HASH(y_b*p + y_a)

        // chat

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
