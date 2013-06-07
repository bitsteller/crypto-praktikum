import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;

import java.math.BigInteger;
import java.nio.*;
import java.util.*;

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
    protected final static BigInteger multMod = BigInteger.valueOf(65537L);

    public int[] keys_enc, keys_dec;
    
    
    IDEA(BigInteger key) {
        byte[] key_bytes = key.and(_128bits).toByteArray();
        keys_enc = idea_subkeys(key_bytes);
        keys_dec = idea_deckeys(keys_enc);
    }

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
    public static int[] idea_subkeys(byte[] key) {
        int[] encryptKeys = new int[52];

        int k1;

        for ( k1 = 0; k1 < 8; ++k1 )
            encryptKeys[k1] =
                ( ( key[2 * k1] & 0xff ) << 8 ) | ( key[ 2 * k1 +1] & 0xff );

        for ( ; k1 < 52; ++k1 )
            encryptKeys[k1] =
                ( ( encryptKeys[k1 - 8] << 9 ) |
                  ( encryptKeys[k1 - 7] >>> 7 ) ) & 0xffff;

        return encryptKeys;
    }

    /** generate decryption keys.
     *
     * implementation concept: http://www.quadibloc.com/crypto/co040302.htm
     * INFO AT LINK NOT EVEN CORRECT for the last four keys
     *
     * @param keys_enc 52 subkeys to generate decryption keys for
     * @return an array of 52 sequential decryption subkeys
     *
     */
    public static int[] idea_deckeys(int[] keys_enc) {

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
            if(i == 42) {
                buf.put(-keys_enc[43 -i]);
                buf.put(-keys_enc[44 -i]);
            } else {
                buf.put(-keys_enc[44 -i]);
                buf.put(-keys_enc[43 -i]);
            }
            buf.put(BigInteger.valueOf(keys_enc[45 -i]).modInverse(multMod).intValue());

        }

        // there should be no bytes left for writing!
        assert(buf.remaining() == 0);

        // ok, get back to beginning, and write first 104 bytes into an array of 52 ints
        int[] ret = new int[52];
        buf.flip();
        buf.get(ret, 0, 52);

        return ret;

    }

    public static void mainx(String[] args) {
        byte[] key = new byte[] { (byte) 0x42, (byte) 0x61, (byte) 0xce, (byte) 0xd1, (byte) 0xff, (byte) 0x55, (byte) 0xff, (byte) 0x1d,
                                  (byte) 0xf2, (byte) 0x12, (byte) 0xfc, (byte) 0xfa, (byte) 0xaa, (byte) 0xff, (byte) 0x91, (byte) 0xff };

        assert(args.length == 1 && args[0].length() == 16);
        int[] subkeys = IDEA.idea_subkeys(key); //args[0].getBytes()));
        int[] deckeys = IDEA.idea_deckeys(subkeys); //args[0].getBytes()));

        for(int i = 0; i < subkeys.length; i++) {
            System.out.println(String.format("%04x %04x", subkeys[i], deckeys[i]));
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

        for(int i = 0; i < out.length; i++)
            out[i] &= 0xffff;

    }

    /** One round of IDEA.
     *
     * Implements this algorithm:
     * http://en.wikipedia.org/wiki/File:International_Data_Encryption_Algorithm_InfoBox_Diagram.svg
     *
     * @param in 64 bits of input to encrypt. may be altered!
     * @param out 64 bits of output
     * @param key 96 bit key
     */
    public static void idea_round(int[] in, int[] out, int[] key, int key_offset) {
        assert(in.length == 4 && out.length == 4);
        assert(key.length >= key_offset +6);

        // first layer
        out[0] = mul(in[0], key[key_offset+0]);
        out[1] = in[1] + key[key_offset+1];
        out[2] = in[2] + key[key_offset+2];
        out[3] = mul(in[3], key[key_offset+3]);

        // intermediate values
        in[0] = mul(out[0] ^ out[2], key[key_offset+4]);
        in[1] = (out[1] ^ out[3]) + in[0];
        in[2] = mul(in[1], key[key_offset+5]);
        in[3] = in[0] + in[2];

        // bottom xor-layer
        out[0] = out[0] ^ in[2];
        int SDKFJSDF = out[1];
        out[1] = out[2] ^ in[2];
        out[2] = SDKFJSDF ^ in[3];
        out[3] = out[3] ^ in[3];

    }

    /** Multiplication modulo 65537L.
     *
     */
    public static int mul(int a, int b) {
        return BigInteger.valueOf(a & 0xffff).multiply(BigInteger.valueOf(b & 0xffff)).mod(multMod).intValue();
    }

    /** One half-round of IDEA.
     *
     * Implements this algorithm:
     * http://en.wikipedia.org/wiki/File:International_Data_Encryption_Algorithm_InfoBox_Diagram_Output_Trans.png
     *
     * @param in 64 bits of input to encrypt. may be altered!
     * @param out 64 bits of output
     * @param key 64 bit key
     */
    public static void idea_halfround(int[] in, int[] out, int[] key, int key_offset) {
        assert(in.length == 4 && out.length == 4);
        assert(key.length >= key_offset +4);

        out[0] = mul(in[0], key[key_offset+0]);
        out[1] = in[2] + key[key_offset+1];
        out[2] = in[1] + key[key_offset+2];
        out[3] = mul(in[3], key[key_offset+3]);

    }
    
    /**
     * Converts an array of bytes to an array of ints filled with 2 bytes each.
     * The size of the in array has to be even. The out array must have the half size of the byte array.
     * @param in Array of bytes
     * @param out Int Array to write the short values in
     */
    private static void convertByteArrayToShortIntArray(byte[] in, int[] out) {
        assert(in.length % 2 == 0);
        assert( (in.length+1) / 2 == out.length);
        for (int i = 0; i < in.length; i+=2) {
            out[i/2] = ((in[i] & 0xff) << 8) | (in[i+1] & 0xff);
        }
    }
    
    /**
     * Converts an array full of ints with 2 bytes in each int to a byte array.
     * The out array must have the doubled size of the in array
     * @param in Int array containing short values
     * @param out Byte array
     */
    private static void convertShortIntArrayToByteArray (int[] in, byte[] out) {
        assert(in.length == (out.length+1) / 2);
        for (int i = 0; i < out.length; i+=2) {
            out[i] = (byte) (in[i/2] >>> 8);
            out[i+1] = (byte) (in[i/2]);
        }
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
    public void decipher(InputStream ciphertext, OutputStream cleartext) {

        try {

            // buffer for 8 bytes at a time
            byte[] block_byte = new byte[8];
            // current ciphertext block (to be encrypted)
            int[] block_int = new int[4];
            // lastCipherBlock for CBC, starting with IV
            int[] block_last = new int[4];
            int[] block_tmp = new int[4];
            int[] block_cipher = new int[4];;

            // read IV from first block
            ciphertext.read(block_byte);
            convertByteArrayToShortIntArray(block_byte, block_last);

            int bytes_read;

            while ( (bytes_read = ciphertext.read(block_byte)) > 0) {
                assert(bytes_read == 8);

                // convert to ints of 16 bits each
                convertByteArrayToShortIntArray(block_byte, block_cipher);
                System.arraycopy(block_cipher, 0, block_tmp, 0, block_last.length);

                // encrypt block with IDEA
                idea_block(block_cipher, block_int, this.keys_dec);
                //System.arraycopy(block_cipher, 0, block_int, 0, block_last.length); //test: without IDEA
                
                // CBC: xor with last block
                for (int i = 0; i < 4; i++) {
                    block_int[i] ^= block_last[i];
                }

                System.arraycopy(block_tmp, 0, block_last, 0, block_last.length);

                convertShortIntArrayToByteArray(block_int, block_byte);

                // write to output
                cleartext.write(block_byte);

            }
        } catch (IOException e) {
            System.out
                    .println("Encipher failed, could not read cleartext or write ciphertext.");
            e.printStackTrace();
        }
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
    public void encipher(InputStream cleartext, OutputStream ciphertext) {
        try {
            // buffer for 8 bytes at a time
            byte[] block_byte = new byte[8];
            // current ciphertext block (to be encrypted)
            int[] block_int = new int[4];
            // lastCipherBlock for CBC, starting with IV
            int[] block_last = new int[4];
            new Random().nextBytes(block_byte);
            ciphertext.write(block_byte); // write init vector as 0. block into ciphertext
            convertByteArrayToShortIntArray(block_byte, block_last);

            int bytes_read;

            while ( (bytes_read = cleartext.read(block_byte)) > 0) {
                // if there aren't enough bytes, fill with zeroes
                if(bytes_read < 8)
                    Arrays.fill(block_byte, bytes_read-1, 8, (byte) 0);

                // convert to ints of 16 bits each
                convertByteArrayToShortIntArray(block_byte, block_int);

                // CBC: xor with last block
                for (int i = 0; i < 4; i++) {
                    block_int[i] ^= block_last[i];
                }

                // encrypt block with IDEA
                idea_block(block_int, block_last, this.keys_enc);
                //System.arraycopy(block_int, 0, block_last, 0, block_last.length); //test: without IDEA
                
                convertShortIntArrayToByteArray(block_last, block_byte);

                // write to output
                ciphertext.write(block_byte);

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

        keys_enc = idea_subkeys(key);
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

    public void decipher(FileInputStream arg0, FileOutputStream arg1) {
        this.decipher((InputStream)arg0, (OutputStream)arg1);
    }

    public void encipher(FileInputStream arg0, FileOutputStream arg1) {
        this.encipher((InputStream) arg0, (OutputStream) arg1);
    }
}
