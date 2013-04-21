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

import java.io.BufferedReader;
import java.io.BufferedWriter;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.FileWriter;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.io.StringReader;

import de.tubs.cs.iti.jcrypt.chiffre.CharacterMapping;
import de.tubs.cs.iti.jcrypt.chiffre.Cipher;

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

		RunningKey v = new RunningKey();
		v.readKey(new BufferedReader(new StringReader("26 keystream.txt\n"))); // FIXME
		v.charMap = new CharacterMapping(v.modulus);

		switch (args[0]) {
		case "encipher":
			v.encipher(input, output);
			return;

		case "decipher":
			v.decipher(input, output);
			return;

		case "break":
			v.breakCipher(input, output);
			return;

		default:
			System.out
					.println("Usage: $0 encipher|decipher|break [infile [outfile]]");
		}

	}
}
