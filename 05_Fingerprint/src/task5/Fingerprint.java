/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        Fingerprint.java
 * Beschreibung: Dummy-Implementierung der Hash-Funktion von Chaum, van Heijst
 *               und Pfitzmann
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task5;

import java.io.*;
import java.math.BigInteger;
import java.util.Random;

import de.tubs.cs.iti.jcrypt.chiffre.BigIntegerUtil;

/**
 * Dummy-Klasse für die Hash-Funktion von Chaum, van Heijst und Pfitzmann.
 *
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 22:20:18 CEST 2010
 */
public final class Fingerprint {

    /// regular CPHJ hash function, Z_q * Z_q -> Z*_p
    public BigInteger cph(BigInteger x1, BigInteger x2) {
        assert(x1.compareTo(q) < 0);
        assert(x2.compareTo(q) < 0);
        return g1.modPow(x1, p).multiply(g2.modPow(x2, p)).mod(p);
    }

    public BigInteger cphPrime(BigInteger x1, BigInteger x2) {
        if(x1.compareTo(q) >= 0) {
            int bl = x1.bitLength();
            x1 = cphPrime(x1.xor(x1.shiftRight(bl/2).shiftLeft(bl/2)), x1.shiftRight(bl/2));
        }
        if(x2.compareTo(q) >= 0) {
            int bl = x2.bitLength();
            x2 = cphPrime(x2.xor(x2.shiftRight(bl/2).shiftLeft(bl/2)), x2.shiftRight(bl/2));
        }

        return cph(x1, x2);
    }

    /**
     * Berechnet den Hash-Wert des durch den FileInputStream
     * <code>cleartext</code> gegebenen Klartextes und schreibt das Ergebnis in
     * den FileOutputStream <code>ciphertext</code>.
     * 
     * @param cleartext
     * Der FileInputStream, der den Klartext liefert.
     * @param ciphertext
     * Der FileOutputStream, in den der Hash-Wert geschrieben werden soll.
     */
    public String hash(String cleartext) {
        BigInteger text = new BigInteger(cleartext.getBytes());

        int bl = text.bitLength();
        BigInteger cipher = cphPrime(text.xor(text.shiftRight(bl/2).shiftLeft(bl/2)), text.shiftRight(bl/2));

        return cipher.toString(16);
    }

    public static final BigInteger ONE = BigInteger.ONE;
    public static final BigInteger TWO = BigInteger.valueOf(2L);
    public static final BigInteger THREE = BigInteger.valueOf(3L);

    // parameters
    BigInteger p, q, g1, g2;

    /**
     * Erzeugt neue Parameter.
     * 
     * @see #readParam readParam
     * @see #writeParam writeParam
     */
    public void makeParam() {
        Random rand = new Random();

        // q = prime
        // p = 2q+1, secure prime
        do {
            q = new BigInteger(511, rand); // p = random 512 bit number
            p = q.multiply(TWO).add(ONE); // p = 2q+1
        } while(!p.isProbablePrime(42));

        // same algorithm to find a generator
        BigInteger pMinusOne = p.subtract(ONE);
        do {
            // choose 2 < g < q, we should have a 50% probability of hitting a generating number here.
            g1 = BigIntegerUtil.randomBetween(THREE, pMinusOne, rand);
            // check if the required criteria for a generator of G applies
        } while(!g1.modPow(q, p).equals(pMinusOne));

        // same algorithm to find a generator
        do {
            // choose 2 < g < q, we should have a 50% probability of hitting a generating number here.
            g2 = BigIntegerUtil.randomBetween(THREE, pMinusOne, rand);
            // check if the required criteria for a generator of G applies
        } while(!g2.modPow(q, p).equals(pMinusOne) && !g2.equals(g1));

    }

    /**
     * Liest die Parameter mit dem Reader <code>param</code>.
     * 
     * @param param
     * Der Reader, der aus der Parameterdatei liest.
     * @see #makeParam makeParam
     * @see #writeParam writeParam
     */
    public void readParam(BufferedReader param) throws IOException {
        try {
            p = new BigInteger(param.readLine());
            q = p.subtract(ONE).divide(TWO);
            g1 = new BigInteger(param.readLine());
            g2 = new BigInteger(param.readLine());
        } catch(IOException e) {
            throw e;
        } catch(Exception e) {
            e.printStackTrace();
            System.exit(1);
        }
    }

    /**
     * Berechnet den Hash-Wert des durch den FileInputStream
     * <code>cleartext</code> gegebenen Klartextes und vergleicht das
     * Ergebnis mit dem durch den FileInputStream <code>ciphertext</code>
     * gelieferten Wert.
     */
    public boolean verify(String cleartext, String ciphertext) {
        return hash(cleartext).equals(ciphertext);
    }

    /**
     * Schreibt die Parameter mit dem Writer <code>param</code>.
     * 
     * @param param
     * Der Writer, der in die Parameterdatei schreibt.
     * @see #makeParam makeParam
     * @see #readParam readParam
     */
    public void writeParam(BufferedWriter param) throws IOException {
        param.write(p.toString());
        param.newLine();
        param.write(g1.toString());
        param.newLine();
        param.write(g2.toString());
        param.newLine();
        param.flush();
    }

    public static void main(String[] args) {

        Fingerprint f = new Fingerprint();

        // cheat
        if(args.length < 2)
            args = new String[] { "", "" };
        try {
            switch(args[0]) {
                case "makeParam":
                    f.makeParam();
                    f.writeParam(new BufferedWriter(new FileWriter(args[1])));
                    break;

                case "hash":
                    f.readParam(new BufferedReader(new FileReader(args[1])));
                    if(args[1].equals("")) {
                        System.err.println("no hash specified!");
                        System.exit(1);
                    }
                    String hash = f.hash(args[2]);
                    System.out.println(hash);
                    break;

                default:
                    System.err.println("Usage: $0 makeParam|hash paramFile [hash]");
                    System.exit(1);
            }
        } catch(Exception e) {
            e.printStackTrace();
            System.exit(2);
        }
    }

}
