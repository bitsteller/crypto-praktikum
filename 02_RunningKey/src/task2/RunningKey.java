/*
 * jCrypt - Programmierumgebung für das Kryptologie-Praktikum
 * Studienarbeit am Institut für Theoretische Informatik der
 * Technischen Universität Braunschweig
 * 
 * Datei:        RunningKey.java
 * Beschreibung: Dummy-Implementierung der Chiffre mit laufendem Schlüssel
 * Erstellt:     30. März 2010
 * Autor:        Martin Klußmann
 */

package task2;

import java.io.*;
import java.util.*;

import de.tubs.cs.iti.jcrypt.chiffre.*;

/**
 * Dummy-Klasse für die Chiffre mit laufendem Schlüssel.
 * 
 * @author Martin Klußmann
 * @version 1.0 - Tue Mar 30 16:23:47 CEST 2010
 */
public class RunningKey extends Cipher {

	String keystreamFilename = "";

	/**
	 * Analysiert den durch den Reader <code>ciphertext</code> gegebenen
	 * Chiffretext, bricht die Chiffre bzw. unterstützt das Brechen der Chiffre
	 * (ggf. interaktiv) und schreibt den Klartext mit dem Writer
	 * <code>cleartext</code>.
	 * 
	 * @param ciphertext
	 *            Der Reader, der den Chiffretext liefert.
	 * @param cleartext
	 *            Der Writer, der den Klartext schreiben soll.
	 */
	public void breakCipher(BufferedReader ciphertext, BufferedWriter cleartext) {

	}

	/**
	 * Entschlüsselt den durch den Reader <code>ciphertext</code> gegebenen
	 * Chiffretext und schreibt den Klartext mit dem Writer
	 * <code>cleartext</code>.
	 * 
	 * @param ciphertext
	 *            Der Reader, der den Chiffretext liefert.
	 * @param cleartext
	 *            Der Writer, der den Klartext schreiben soll.
	 */
	public void decipher(BufferedReader ciphertext, BufferedWriter cleartext) {
		try {
			BufferedReader keystream = new BufferedReader(new FileReader(
					this.keystreamFilename));
			
			int charCipher;
			while ((charCipher = ciphertext.read()) != -1) {
				charCipher = charMap.mapChar(charCipher);
				int charKey = charMap.mapChar(keystream.read());
				if (charCipher != -1) { //skip invald characters
					int charClear = (charCipher - charKey) % modulus;
					charClear = charMap.remapChar(charClear);
					cleartext.write(charClear);
				}
			}
			cleartext.close();
			ciphertext.close();
			keystream.close();
		} catch (FileNotFoundException e) {
			System.out.println("Error: keystream file not found :-(");
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println("Error: Could not read or write file :-(");
			e.printStackTrace();
		}
	}

	/**
	 * Verschlüsselt den durch den Reader <code>cleartext</code> gegebenen
	 * Klartext und schreibt den Chiffretext mit dem Writer
	 * <code>ciphertext</code>.
	 * 
	 * @param cleartext
	 *            Der Reader, der den Klartext liefert.
	 * @param ciphertext
	 *            Der Writer, der den Chiffretext schreiben soll.
	 */
	public void encipher(BufferedReader cleartext, BufferedWriter ciphertext) {
		try {
			BufferedReader keystream = new BufferedReader(new FileReader(
					this.keystreamFilename));
			
			int charClear;
			while ((charClear = cleartext.read()) != -1) {
				charClear = charMap.mapChar(charClear);
				int charKey = charMap.mapChar(keystream.read());
				if (charClear != -1) { //skip invald characters
					int charCipher = (charClear + charKey) % modulus;
					charCipher = charMap.remapChar(charCipher);
					ciphertext.write(charCipher);
				}
			}
			cleartext.close();
			ciphertext.close();
			keystream.close();
		} catch (FileNotFoundException e) {
			System.out.println("Error: keystream file not found :-(");
			e.printStackTrace();
		} catch (IOException e) {
			System.out.println("Error: Could not read or write file :-(");
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

		System.out.println("Dummy für die Schlüsselerzeugung.");
	}

	/**
	 * Liest den Schlüssel mit dem Reader <code>key</code>.
	 * 
	 * @param key
	 *            Der Reader, der aus der Schlüsseldatei liest.
	 * @see #makeKey makeKey
	 * @see #writeKey writeKey
	 */
	public void readKey(BufferedReader key) {

	}

	/**
	 * Schreibt den Schlüssel mit dem Writer <code>key</code>.
	 * 
	 * @param key
	 *            Der Writer, der in die Schlüsseldatei schreibt.
	 * @see #makeKey makeKey
	 * @see #readKey readKey
	 */
	public void writeKey(BufferedWriter key) {

	}

	public static void main(String[] args) throws IOException {
		// read from input file, or stdin
		BufferedReader input = args.length > 1 ? new BufferedReader(
				new FileReader(args[1])) : new BufferedReader(
				new InputStreamReader(System.in));
		// use output file, if any, or stdout
		BufferedWriter output = args.length > 2 ? new BufferedWriter(
				new FileWriter(args[2])) : new BufferedWriter(new PrintWriter(
				System.out));

		RunningKey v = new RunningKey(26);
		v.keystreamFilename = "keystream.txt";
		v.charMap = new CharacterMapping(v.modulus);

		if (args[0].equals("encipher")) {
			v.encipher(input, output);
			return;
		}
		else if (args[0].equals("decipher")) {
			v.decipher(input, output);
			return;
		}
		else if (args[0].equals("break")) {
			v.breakCipher(input, output);
			return;
		}
		else {
				System.out.println("Usage: $0 encipher|decipher|break [infile [outfile]]");
		}

	}

        HashSet<AbstractMap.SimpleEntry<Integer, Integer>>[] sumpieces;
        HashMap<String, Double> uniGrams, biGrams, triGrams;

        RunningKey(int modulus) {
        	this.modulus = modulus;
            charMap = new CharacterMapping(modulus);
            generateSumPieces();

            { // generate unigram hashmap
                Iterator<NGram> it = FrequencyTables.getNGramsAsList(1, charMap).iterator();
                while (it.hasNext()) {
                    NGram n = it.next();
                    uniGrams = new HashMap<String, Double>();
                    uniGrams.put(n.getCharacters(), n.getFrequency());
                }
            }
            { // generate digram hashmap
                Iterator<NGram> it = FrequencyTables.getNGramsAsList(2, charMap).iterator();
                while (it.hasNext()) {
                    NGram n = it.next();
                    biGrams = new HashMap<String, Double>();
                    biGrams.put(n.getCharacters(), n.getFrequency());
                }
            }
            { // generate trigram hashmap
                Iterator<NGram> it = FrequencyTables.getNGramsAsList(3, charMap).iterator();
                while (it.hasNext()) {
                    NGram n = it.next();
                    triGrams = new HashMap<String, Double>();
                    triGrams.put(n.getCharacters(), n.getFrequency());
                }
            }
        }


        private void generateSumPieces() {
            sumpieces = (HashSet<AbstractMap.SimpleEntry<Integer, Integer>>[]) new HashSet[modulus];
            for(int i = 0; i < modulus; i++)
                sumpieces[i] = new HashSet<AbstractMap.SimpleEntry<Integer, Integer>>();
            for(int i = 0; i < modulus; i++) {
                for(int j = 0; j < modulus; j++) {
                    sumpieces[(i+j) % modulus].add(new AbstractMap.SimpleEntry<Integer, Integer>(i, j));
                }
            }
        }

        public static void main_testpieces(String[] args) {
            RunningKey k = new RunningKey(26);

            Iterator<AbstractMap.SimpleEntry<Integer, Integer>> it = k.sumpieces[17].iterator();
            AbstractMap.SimpleEntry<Integer, Integer> x;
            while(it.hasNext()) {
                x = it.next();
                System.out.println(x);
            }

        }

}
