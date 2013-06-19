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
        //send public key: p, g, y
        //send random m1,m2 between 0 and p. m1 != m2
        
        //receive q
        
        //k0 = decipher((q-m0) mod p)
        //k1 = decipher((q-m0) mod p)
        //S0 = sign(k0)
        //S1 = sign(k1)
        //select random s in {0,1}
        
        //read messages to be send M0, M1 (between 0 and p)

        //send M_strich_0 := (M0 + k_{s xor 0}) mod p
        //send M_strich_1 := (M1 + k_{s xor 1}) mod p
        //send S0, S1
        //send s
    }

    /** This is Bob. */
    public void receiveFirst () {
        //receive p,g,y
        BigInteger p = new BigInteger(com.receive());
        BigInteger g = new BigInteger(com.receive());
        BigInteger y = new BigInteger(com.receive());

        //receive m0,m1
        BigInteger[] m= new BigInteger[2];
        m[0] = new BigInteger(com.receive());
        m[1] = new BigInteger(com.receive());

        //select random b in {0,1}
        BigInteger b = new BigInteger(1, new Random());
        
        //select random k between 0 and p
        BigInteger k;
        do {
            k = new BigInteger(p.bitLength(), new Random());
        } while (k.compareTo(p) >= 0);
        
        //send q:= (crypt(k) + m_b) mod p^2
        ElGamalCipher elgamal = new ElGamalCipher(p,g,y);
        BigInteger q = elgamal.encipherBlock(k).add(m[b.intValue()]).mod(p.pow(2));
        com.sendTo(0, q.toString());
        
        //receive M_strich_0, M_strich_1
        BigInteger[] M_strich= new BigInteger[2];
        M_strich[0] = new BigInteger(com.receive());
        M_strich[1] = new BigInteger(com.receive());
        
        //receive S0,S1
        BigInteger[] S= new BigInteger[2];
        S[0] = new BigInteger(com.receive());
        S[1] = new BigInteger(com.receive());
        
        //receive s
        BigInteger s = new BigInteger(com.receive());
        
        //compute M_{s ^ b} := M_strich_{s ^ b} - k
        BigInteger M_sb = M_strich[s.xor(b).intValue()].subtract(k);
        
        //compute k_quer := M_strich_{s ^ b ^ 1} - M_{s ^ b}
        BigInteger k_quer = M_strich[s.xor(b).xor(ONE).intValue()].subtract(M_sb);
        
        //check S_{b ^ 1} != k_quer (otherwise: betrayed!)
        if (S[b.xor(ONE).intValue()] == k_quer) {
            System.out.println("You have been betrayed!");
        }
        else {
            System.out.println("Congratulations! With a probability of 1/2 you were not betrayed!");
            System.out.println("The received secret is: " + M_sb);
        }
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
