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
import java.io.IOException;

import java.math.BigInteger;
import java.nio.*;
import java.util.Random;

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

    int[] keys_enc, keys_dec;

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
    public static int[] idea_subkeys(BigInteger key) {
        // there should be no bits set after the 128th! this is basically key.length == 16
        assert(key.and(_128bits).equals(key));

        // allocate buffer space
        int[] ret = new int[52];

        // BigInteger trickery: set 128th bit to make sure we get exactly 9
        // bytes, then skip the first one
        key = key.and(_128bits).setBit(128);
        byte[] buf = key.toByteArray();
        for(int j = 0; j < 16; j+=2)
            ret[j] = buf[j] | (buf[j+1] << 8);

        // 4 keys + 6*8 keys = 52 keys
        for(int i = 0; i < 6; i++) {
            // shift left by 25 bits in 128-bit rotation, and filter first 128 bits only
            key = key.shiftRight(103).or(key.shiftLeft(25)).and(_128bits).setBit(128);
            assert(key.toByteArray().length == 17 && key.toByteArray()[0] == 0x01);
            // put 16 bytes, or 8 for the last round
            for(int j = 0, end = i < 5 ? 16 : 8; j < end; j+=2)
                ret[i*6+j] = buf[j+1] | (buf[j+2] << 8);
        }

        return ret;
    }

    /** generate decryption keys.
     *
     * implementation concept: http://www.quadibloc.com/crypto/co040302.htm
     *
     * @param keys_enc 52 subkeys to generate decryption keys for
     * @return an array of 52 sequential decryption subkeys
     *
     */
    public static int[] idea_deckeys(int[] keys_enc) {

        BigInteger addMod = BigInteger.valueOf(65536L);
        BigInteger multMod = BigInteger.valueOf(65537L);

        // allocate buffer space
        IntBuffer buf = IntBuffer.allocate(52);

        /*
            The first four subkeys for decryption are:

            KD(1) = 1/K(49)
            KD(2) =  -K(50)
            KD(3) =  -K(51)
            KD(4) = 1/K(52)
        */
        buf.put(BigInteger.valueOf(keys_enc[48]).modInverse(multMod).intValue());
        buf.put(-keys_enc[49]);
        buf.put(-keys_enc[50]);
        buf.put(BigInteger.valueOf(keys_enc[51]).modInverse(multMod).intValue());

        /*
            The following is repeated eight times, adding 6 to every decryption key's index and subtracting 6 from every encryption key's index:
        */
        for(int i = 0; i < 48; i+=6) {

            /*
                KD(5)  =   K(47)
                KD(6)  =   K(48)
            */
            buf.put(keys_enc[46 -i]);
            buf.put(keys_enc[47 -i]);

            /*
                KD(7)  = 1/K(43)
                KD(8)  =  -K(45)
                KD(9)  =  -K(44)
                KD(10) = 1/K(46)
            */
            buf.put(BigInteger.valueOf(keys_enc[42 -i]).modInverse(multMod).intValue());
            buf.put(-keys_enc[44 -i]);
            buf.put(-keys_enc[43 -i]);
            buf.put(BigInteger.valueOf(keys_enc[47 -i]).modInverse(multMod).intValue());

        }

        // there should be no bytes left for writing!
        assert(buf.remaining() == 0);

        // ok, get back to beginning, and write first 104 bytes into an array of 52 ints
        int[] ret = new int[52];
        buf.flip();
        buf.get(ret, 0, 52);

        return ret;

    }

    public static void main_subkeys(String[] args) {
        // byte[] key = new byte[] { (byte) 0x42, (byte) 0x61, (byte) 0xce, (byte) 0xd1, (byte) 0xff, (byte) 0x55, (byte) 0xff, (byte) 0x1d,
        //                           (byte) 0xf2, (byte) 0x12, (byte) 0xfc, (byte) 0xfa, (byte) 0xaa, (byte) 0xff, (byte) 0x91, (byte) 0xff };

        assert(args.length == 1 && args[0].length() == 16);
        int[] subkeys = IDEA.idea_subkeys(new BigInteger(args[0].getBytes()));

        for(int i = 0; i < subkeys.length; i++) {
            System.out.println(String.format("%04x", subkeys[i]));
        }

    }

    /** One block of IDEA, consisting of 8.5 rounds of IDEA.
     *
     * @param in 64 bits of input to encrypt. may be altered!
     * @param out 64 bits of output
     * @param key 52 subkeys
     *
     */
    public static void idea_block(int[] in, int[] out, int[] subkeys) {
        assert(in.length == 4 && out.length == 4);
        assert(subkeys.length == 52);

        // 8 idea rounds
        for(int i = 0; i < 8; i+=2) {
            // swap around in/out. note that the "in" array is used for temp
            // values and thus destroyed in the process.
            idea_round(in, out, subkeys, (i+0)*6);
            idea_round(out, in, subkeys, (i+1)*6);
        }

        // 1 idea half-round
        idea_halfround(in, out, subkeys, 48);

    }

    /** One round of IDEA.
     * @param in 64 bits of input to encrypt. may be altered!
     * @param out 64 bits of output
     * @param key 96 bit key
     */
    public static void idea_round(int[] in, int[] out, int[] key, int key_offset) {
        assert(in.length == 4 && out.length == 4);
        assert(key.length >= key_offset +6);

        // first layer
        out[0] = (int) (in[0] * key[key_offset+0] & 0xffff);
        out[1] = (int) (in[1] + key[key_offset+1] & 0xffff);
        out[2] = (int) (in[2] + key[key_offset+2] & 0xffff);
        out[3] = (int) (in[3] * key[key_offset+3] & 0xffff);

        // intermediate values
        in[0] = (int) ( (out[0] ^ out[2]) * key[key_offset+4] & 0xffff);
        in[1] = (int) ( (out[1] ^ out[3]) + in[0] & 0xffff);
        in[2] = (int) ( in[1] + key[key_offset+5] & 0xffff);
        in[3] = (int) ( in[0] + in[2] & 0xffff);

        // bottom xor-layer
        out[0] = (int) (out[0] ^ in[2]);
        out[1] = (int) (out[2] ^ in[2]);
        out[2] = (int) (out[1] ^ in[3]);
        out[3] = (int) (out[3] ^ in[3]);

    }

    /** One half-round of IDEA.
     * @param in 64 bits of input to encrypt. may be altered!
     * @param out 64 bits of output
     * @param key 64 bit key
     */
    public static void idea_halfround(int[] in, int[] out, int[] key, int key_offset) {
        assert(in.length == 4 && out.length == 4);
        assert(key.length >= key_offset +4);

        // we use our time here to make sure with some assertions that the
        // down-casting does not shave off any of our precision
        out[0] = (int) (in[0] * key[key_offset+0] & 0xffff);
        assert(out[0] == (in[0] * key[key_offset+0] & 0xffff));

        out[1] = (int) (in[2] + key[key_offset+1] & 0xffff);
        assert(out[1] == (in[2] + key[key_offset+1] & 0xffff));

        out[2] = (int) (in[1] + key[key_offset+2] & 0xffff);
        assert(out[2] == (in[1] + key[key_offset+2] & 0xffff));

        out[3] = (int) (in[3] * key[key_offset+3] & 0xffff);
        assert(out[3] == (in[3] * key[key_offset+3] & 0xffff));

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
        try {
            byte[] initVectorBytes = new byte[8];

            ciphertext.read(initVectorBytes);
            int[] initVector = convertByteArrayToShortIntArray(initVectorBytes);

            byte[] ciphertextBytes = new byte[8];
            ciphertext.read(ciphertextBytes);

            int[] lastCipherBlock = initVector;
            while (ciphertextBytes.length == 8) {
                int[] ciphertextBlock = convertByteArrayToShortIntArray(ciphertextBytes);

                int[] intermediate = new int[4];
                idea_block(ciphertextBlock, intermediate, this.keys_dec);

                int[] cleartextBlock = new int[4];
                for (int i = 0; i < 4; i++) {
                    cleartextBlock[i] = (int) (intermediate[i] ^ lastCipherBlock[i]);
                }

                cleartext.write(convertShortIntArrayToByteArray(cleartextBlock));

                ciphertext.read(ciphertextBytes);
            }
        } catch (IOException e) {
            System.out.println("Decipher failed, could not read ciphertext or write cleartext.");
            e.printStackTrace();
        }
    }

    
    private static int[] convertByteArrayToShortIntArray (byte[] bytes) {
        int[] ints = new int[bytes.length/2];
        IntBuffer intBuf = ByteBuffer.wrap(bytes)
                .order(java.nio.ByteOrder.BIG_ENDIAN).asIntBuffer();
        for (int i = 0; i<8; i+=2) {
            intBuf.get(ints[i]);
            intBuf.get(ints[i+1]);
        }
        return ints;
    }
    
    private static byte[] convertShortIntArrayToByteArray (int[] ints) {
        ByteBuffer byteBuf = ByteBuffer.allocate(2*ints.length);
        for (int i = 0; i < ints.length; i++) {
            byteBuf.put((byte) (ints[i] >> 8));
            byteBuf.put((byte) (ints[i]));
            
            i++;
        }
        
        return byteBuf.array();
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
        try {
            byte[] initVectorBytes = new BigInteger(64, new Random())
                    .toByteArray();
            ciphertext.write(initVectorBytes); // write init vector as 0. block into ciphertext

            int[] initVector = convertByteArrayToShortIntArray(initVectorBytes);

            byte[] cleartextBytes = new byte[8];
            cleartext.read(cleartextBytes);

            int[] lastCipherBlock = initVector;
            while (cleartextBytes.length == 8) {
                int[] cleartextBlock = convertByteArrayToShortIntArray(cleartextBytes);

                int[] input = new int[4];
                for (int i = 0; i < 4; i++) {
                    input[i] = (int) (cleartextBlock[i] ^ lastCipherBlock[i]);
                }

                int[] ciphertextBlock = new int[4];

                idea_block(input, ciphertextBlock, this.keys_enc);
             
                ciphertext.write(convertShortIntArrayToByteArray(ciphertextBlock));

                cleartext.read(cleartextBytes);
            }
        } catch (IOException e) {
            System.out
                    .println("Encipher failed, could not read cleartext or write ciphertext.");
            e.printStackTrace();
        }
    }

    /**
     * Erzeugt einen neuen Schlüssel.
     * 
     * @see #readKey readKey
     * @see #writeKey writeKey
     */
    public void makeKey() {

        byte[] key = new byte[] { (byte) 0x42, (byte) 0x61, (byte) 0xce, (byte) 0xd1, (byte) 0xff, (byte) 0x55, (byte) 0xff, (byte) 0x1d,
                                  (byte) 0xf2, (byte) 0x12, (byte) 0xfc, (byte) 0xfa, (byte) 0xaa, (byte) 0xff, (byte) 0x91, (byte) 0xff };

        keys_enc = idea_subkeys(new BigInteger(key));
        keys_dec = idea_deckeys(keys_enc);

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
    
    public static void main(String[] args) throws IOException {
        FileInputStream input = new FileInputStream(args[1]);
        FileOutputStream output = new FileOutputStream(args[2]);
        IDEA v = new IDEA();
        v.makeKey();

        if (args[0].equals("encipher")) {
            v.encipher(input, output);
            return;
        }
        else if (args[0].equals("decipher")) {
            v.decipher(input, output);
            return;
        }
        else {
                System.out.println("Usage: $0 encipher|decipher infile outfile");
        }

    }
}
