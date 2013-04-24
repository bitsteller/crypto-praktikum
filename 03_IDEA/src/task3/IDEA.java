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

import de.tubs.cs.iti.jcrypt.chiffre.BlockCipher;

/**
 * Dummy-Klasse für den International Data Encryption Algorithm (IDEA).
 *
 * @author Martin Klußmann
 * @version 1.1 - Sat Apr 03 21:57:35 CEST 2010
 */
public final class IDEA extends BlockCipher {

    /** generate subkeys.
     *
     * The first eight sub-keys are extracted directly from the key, with
     * K1 from the first round being the lower sixteen bits; further groups
     * of eight keys are created by rotating the main key left 25 bits
     * between each group of eight.
     *
     * @return an array of 52 sequential subkeys
     *
     */
    public static char[] idea_subkeys(char[] key) {
        assert(key.length == 16);
        char[] ret = new char[104];

        // basic idea: put key in a biginteger, rotate as needed, put snapshots
        // into ret.

        return ret;
    }

    public static void idea_block(char[] in, char[] out, char[] key) {
        assert(in.length == 8 && out.length == 8);
        assert(key.length == 16);
        // 1. get subkeys
        // 2. 8 idea rounds
        // 3. 1 idea half-round
    }

    /** One round of IDEA.
     * @param in 64 bits of input to encrypt. may be altered!
     * @param out 64 bits of output
     * @param key 96 bit key
     */
    public static void idea_round(char[] in, char[] out, char[] key, int key_offset) { 
        assert(in.length == 8 && out.length == 8);
        assert(key.length >= key_offset +12);
    }

    /** One half-round of IDEA.
     * @param in 64 bits of input to encrypt. may be altered!
     * @param out 64 bits of output
     * @param key 64 bit key
     */
    public static void idea_halfround(char[] in, char[] out, char[] key, int key_offset) { 
        assert(in.length == 8 && out.length == 8);
        assert(key.length >= key_offset +8);
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
