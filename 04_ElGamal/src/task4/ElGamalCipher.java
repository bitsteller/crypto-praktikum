/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        ElGamalCipher.java
 * Beschreibung: Dummy-Implementierung der ElGamal-Public-Key-Verschlüsselung
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task4;

import java.io.*;
import java.math.*;
import java.util.*;

import de.tubs.cs.iti.jcrypt.chiffre.*;
import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;

/**
 * Dummy-Klasse für das ElGamal-Public-Key-Verschlüsselungsverfahren.
 *
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 22:06:35 CEST 2010
 */
public final class ElGamalCipher extends BlockCipher {

    /**
     * Entschlüsselt den durch den FileInputStream <code>ciphertext</code>
     * gegebenen Chiffretext und schreibt den Klartext in den FileOutputStream
     * <code>cleartext</code>.
     * <p>Das blockweise Lesen des Chiffretextes soll mit der Methode {@link
     * #readCipher readCipher} durchgeführt werden, das blockweise Schreiben des
     * Klartextes mit der Methode {@link #writeClear writeClear}.</p>
     *
     * @param ciphertext
     * Der FileInputStream, der den Chiffretext liefert.
     * @param cleartext
     * Der FileOutputStream, in den der Klartext geschrieben werden soll.
     */
    public void decipher(FileInputStream ciphertext, FileOutputStream cleartext) {

    }

    /**
     * Verschlüsselt den durch den FileInputStream <code>cleartext</code>
     * gegebenen Klartext und schreibt den Chiffretext in den FileOutputStream
     * <code>ciphertext</code>.
     * <p>Das blockweise Lesen des Klartextes soll mit der Methode {@link
     * #readClear readClear} durchgeführt werden, das blockweise Schreiben des
     * Chiffretextes mit der Methode {@link #writeCipher writeCipher}.</p>
     * 
     * @param cleartext
     * Der FileInputStream, der den Klartext liefert.
     * @param ciphertext
     * Der FileOutputStream, in den der Chiffretext geschrieben werden soll.
     */
    public void encipher(FileInputStream cleartext, FileOutputStream ciphertext) {

    }

    // did I do this public private thing right? :)
    // public key part
    public BigInteger g, q, h, y;
    // private key part
    private BigInteger x;

    public static final BigInteger ONE = BigInteger.ONE;
    public static final BigInteger TWO = BigInteger.valueOf(2L);
    public static final BigInteger THREE = BigInteger.valueOf(3L);

    /**
     * Erzeugt einen neuen Schlüssel.
     * 
     * @see #readKey readKey
     * @see #writeKey writeKey
     */
    public void makeKey() {

        Random rand = new Random();

        // trivial algorithm: get a 512 bit random number, check if it's a prime. rinse and repeat.
        do {
            BigInteger p = new BigInteger(512, rand); // p = random 512 bit number
            q = p.multiply(TWO).subtract(ONE); // q = 2p-1
        } while(q.isProbablePrime(42));

        // same algorithm to find a generator
        BigInteger pMinusOne = q.subtract(ONE);
        BigInteger pMinusOneDivTwo = pMinusOne.divide(TWO);
        do {
            // choose 2 < g < q, we should have a 50% probability of hitting a generating number here.
            g = BigIntegerUtil.randomBetween(THREE, q.subtract(ONE));
            // check if the required criteria for a generator of G applies
        } while(!g.modPow(pMinusOneDivTwo, q).equals(pMinusOne));

        // choose random x
        x = BigIntegerUtil.randomBetween(TWO, q.subtract(TWO));

        // also, y.
        y = g.modPow(x, q);

    }

    /**
     * Liest den Schlüssel mit dem Reader <code>key</code>.
     * 
     * @param key
     * Der Reader, der aus der Schlüsseldatei liest.
     * @see #makeKey makeKey
     * @see #writeKey writeKey
     */
    public void readKey(BufferedReader key) {

    }

    /**
     * Schreibt den Schlüssel mit dem Writer <code>key</code>.
     * 
     * @param key
     * Der Writer, der in die Schlüsseldatei schreibt.
     * @see #makeKey makeKey
     * @see #readKey readKey
     */
    public void writeKey(BufferedWriter key) {

    }
}
