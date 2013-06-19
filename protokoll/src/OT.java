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

public final class OT implements Protocol
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
        
    }

    /** This is Bob. */
    public void receiveFirst () {

    }
    
//    public static BigInteger crypt(BigInteger key, BigInteger msg) {
//
//    }
//
//    public static BigInteger decrypt(BigInteger key, BigInteger msg) {
//
//    }

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
