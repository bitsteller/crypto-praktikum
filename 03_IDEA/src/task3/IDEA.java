/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        IDEA.java
 * Beschreibung: Dummy-Implementierung des International Data Encryption
 *               Algorithm (IDEA)
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task3;

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.FileOutputStream;

import java.math.BigInteger;
import java.nio.ByteBuffer;

import de.tubs.cs.iti.jcrypt.chiffre.BlockCipher;

/**
 * Dummy-Klasse für den International Data Encryption Algorithm (IDEA).
 *
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 21:57:35 CEST 2010
 */
public final class IDEA extends BlockCipher {

    /// a bigint with first 128 bits set, needed for some bitwise trickery in idea_subkeys
    protected final static BigInteger _128bits = BigInteger.valueOf(0L).setBit(128).subtract(BigInteger.ONE);

    /** generate subkeys.
     *
     * The first eight sub-keys are extracted directly from the key, with
     * K1 from the first round being the lower sixteen bits; further groups
     * of eight keys are created by rotating the main key left 25 bits
     * between each group of eight.
     *
     * @param key 128 bit BigInteger
     * @return an array of 52 sequential subkeys
     *
     */
    public static short[] idea_subkeys(BigInteger key) {
        // there should be no bits set after the 128th! this is basically key.length == 16
        assert(key.and(_128bits).equals(key));

        // allocate buffer space
        ByteBuffer buf = ByteBuffer.allocate(104);

        // BigInteger trickery: set 128th bit to make sure we get exactly 9
        // bytes, then skip the first one
        key = key.and(_128bits).setBit(128);
        buf.put(key.toByteArray(), 1, 16);
        // 8 keys + 6*8 keys = 56 keys
        for(int i = 0; i < 6; i++) {
            // shift left by 25 bits in 128-bit rotation, and filter first 128 bits only
            key = key.and(_128bits).shiftRight(103).or(key.shiftLeft(25)).setBit(128);
            // put 16 bytes, or 8 for the last round
            buf.put(key.toByteArray(), 1, i < 5 ? 16 : 8);
        }

        // there should be no bytes left for writing!
        assert(buf.remaining() == 0);

        // ok, get back to beginning, and write first 104 bytes into an array of 52 shorts
        short[] ret = new short[52];
        buf.flip();
        buf.asShortBuffer().get(ret, 0, 52);

        return ret;
    }

    public static void main_subkeys(String[] args) {
        // byte[] key = new byte[] { (byte) 0x42, (byte) 0x61, (byte) 0xce, (byte) 0xd1, (byte) 0xff, (byte) 0x55, (byte) 0xff, (byte) 0x1d,
        //                           (byte) 0xf2, (byte) 0x12, (byte) 0xfc, (byte) 0xfa, (byte) 0xaa, (byte) 0xff, (byte) 0x91, (byte) 0xff };

        assert(args.length == 1 && args[0].length() == 16);
        short[] subkeys = IDEA.idea_subkeys(new BigInteger(args[0].getBytes()));

        for(int i = 0; i < subkeys.length; i++) {
            System.out.println(String.format("%04x", subkeys[i]));
        }

    }

    /** One block of IDEA, consisting of 8.5 rounds of IDEA.
     *
     * @param in 64 bits of input to encrypt. may be altered!
     * @param out 64 bits of output
     * @param key 128 bit key
     *
     */
    public static void idea_block(char[] in, char[] out, short[] key) {
        assert(in.length == 8 && out.length == 8);
        assert(key.length == 8);
        // 1. get subkeys
        // 2. 8 idea rounds
        // 3. 1 idea half-round
    }

    /** One round of IDEA.
     * @param in 64 bits of input to encrypt. may be altered!
     * @param out 64 bits of output
     * @param key 96 bit key
     */
    public static void idea_round(char[] in, char[] out, short[] key, int key_offset) {
        assert(in.length == 8 && out.length == 8);
        assert(key.length >= key_offset +6);
    }

    /** One half-round of IDEA.
     * @param in 64 bits of input to encrypt. may be altered!
     * @param out 64 bits of output
     * @param key 64 bit key
     */
    public static void idea_halfround(char[] in, char[] out, short[] key, int key_offset) { 
        assert(in.length == 8 && out.length == 8);
        assert(key.length >= key_offset +4);
    }

    /**
     * Entschlüsselt den durch den FileInputStream <code>ciphertext</code>
     * gegebenen Chiffretext und schreibt den Klartext in den FileOutputStream
     * <code>cleartext</code>.
     *
     * @param ciphertext
     * Der FileInputStream, der den Chiffretext liefert.
     * @param cleartext
     * Der FileOutputStream, in den der Klartext geschrieben werden soll.
     */
    public void decipher(FileInputStream ciphertext, FileOutputStream cleartext) {

        // CBC here
        // 1. create IV
        // 2. do progressive cbc on inputstream

    }

    /**
     * Verschlüsselt den durch den FileInputStream <code>cleartext</code>
     * gegebenen Klartext und schreibt den Chiffretext in den FileOutputStream
     * <code>ciphertext</code>.
     * 
     * @param cleartext
     * Der FileInputStream, der den Klartext liefert.
     * @param ciphertext
     * Der FileOutputStream, in den der Chiffretext geschrieben werden soll.
     */
    public void encipher(FileInputStream cleartext, FileOutputStream ciphertext) {

        // CBC here

    }

    /**
     * Erzeugt einen neuen Schlüssel.
     * 
     * @see #readKey readKey
     * @see #writeKey writeKey
     */
    public void makeKey() {

        System.out.println("Dummy für die Schlüsselerzeugung.");
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
