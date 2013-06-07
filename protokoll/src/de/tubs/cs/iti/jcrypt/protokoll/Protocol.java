/* Generated by Together */

package de.tubs.cs.iti.jcrypt.protokoll;


/**
 * Das Interface Protocol ist die Schnittstelle, die alle Protokolle(Spiele)
 * implementieren muessen, damit sie auf dem (unserem) Client-Server-Netzwerk
 * laufen. Durch dieses Interface bleibt die Austauschbarkeit
 * der Protokolle gewährleistet.
 * Es beinhaltet die Methoden, die wichtige Protokolldaten zurueckgeben, wie den
 * Namen des Spieles, sowie die minimale und maximale Anzahl der moeglichen
 * Spieler. Ausserdem muss im Spiel die Methode SetCommunicator() implementiert
 * sein, damit dem Spiel die Moeglichkeit der Kommunikation ?ber das Netzwerk
 * gegeben wird.
 * Als letztes muessen noch die Methoden sendFirst() und receiveFirst()
 * vom Spiel spezifiziert werden, damit die Clients diese bei Beginn des Spieles
 * auf dem Spiel ausfuehren koennen, je nachdem welches Protokoll zu erst
 * Daten sendet bzw. welche Daten empfangen.
 */

public interface Protocol {



    /**
     * Diese Methode weist dem Protokoll das Communicator-objekt com f?r die
     * Spielekommunikation zu.
     * @param com Objekt vom Typ Communicator
     */
    public void setCommunicator( Communicator Com );

    /**
     * Diese Methode gibt den Namen des Spieles zurueck.
     * @return<code>String</code> Name des Spieles
     */
    public String nameOfTheGame();

    /**
     * Diese Methode fuehrt der Client nach dem Laden des Spielprotokolls
     * auf dem Spiel auf, wenn es die Partei ist, die zuerst Daten sendet.
     */
    public void sendFirst();

    /**
     * Diese Methode fuehrt der Client nach dem Laden des Spielprotokolls
     * auf dem Spiel auf, wenn es die Partei ist, die zuerst Daten empfaengt.
     */
    public void receiveFirst();

    /**
     * Diese Methode gibt die minimale Anzahl an Spielern zurueck
     * @return<code>int</code> minimale Anzahl der Spieler
     * */
    public int minPlayer();

    /**
     * Diese Methode gibt die maximale Anzahl an Spielern zurueck
     * @return<code>int</code> maximale Anzahl der Spieler
     */
    public int maxPlayer();

}


