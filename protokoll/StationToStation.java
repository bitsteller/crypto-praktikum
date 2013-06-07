/*
 * @(#)Skeleton.java
 */

import de.tubs.cs.iti.jcrypt.protokoll.*;

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
    private Communicator Com;

    public void setCommunicator(Communicator com)
    {
        Com = com;
    }

    /** This ia Alice. */
    public void sendFirst () {
        // p = prim
        // g = prime wurzel mod p
        // x_a \in Z_p
        // y_a = g^{x_a} mod p

        // send p, g, y_a

        // receive y_b, cert_b, xm_b

        // CHECK(cert_b)
        // K = y_b^{x_a} mod p
        // m_b = UNIDEA(K, xm_b)
        // test m_b == HASH(y_b*p + y_a)
        // xm_a = IDEA(K, HASH(y_a*p + y_b)

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
