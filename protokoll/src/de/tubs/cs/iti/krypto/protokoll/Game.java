/* Generated by Together */

package de.tubs.cs.iti.jcrypt.protokoll;

import java.util.Vector;

/**
 * Eine Instanz der Klasse Game verwaltet je eine Spielrunde des
 * Spielprotokolls, das auf dem Server laeuft, z.B. Kniffel.
 * Hier werden die Spielerliste (in Form von ServerThreads) und weitere
 * spielrelevante Daten (Name, maximale/minimale Spielerzahl etc.) gespeichert.
 * Desweiteren werden diverse Methoden zur Verwaltung eines Spiels zur Verfuegung
 * gestellt, z.B. Spieler loeschen/hinzufuegen, Verbindung unterbrechen etc.
 * @author Wolfgang Schmiesing
 * @version 1.0
*/

public class Game {

    protected boolean is_running = false;
    private int currentPlayers;
    private int gameID;
    private int maxPlayer;
    private int minPlayer;
    private String nameOfTheGame;
    /**
      * @associates <{Netzwerk.ServerThread}>
      * @supplierCardinality 0..**/
    private Vector players;

    /**Konstruktor; erzeugt einen neuen Spieleintrag, der in der Server-eigenen
     * Liste gespeichert wird. Der ServerThread wird im Vector "players" und die
     * weiteren Parameter in entsprechenden Variablen gespeichert.
     * Als letztes wird die Spielerzahl ("1") dem Communicator geschickt.
     * @param serverThread ServerThread des Spielers
     * @param min minimale Spieleranzahl
     * @param max maximale Spieleranzahl
     * @param name Spielname
    */
    public Game( ServerThread serverThread, int min, int max, String name ) {
        currentPlayers = 1;
        players = new Vector();
        players.addElement( ( Object ) serverThread );
        nameOfTheGame = name;
        minPlayer = min;
        maxPlayer = max;
        gameID = serverThread.getGameID();
        serverThread.send( "1" + currentPlayers + " " + "0" );
    }

    /**Fuegt den ServerThread eines neuen Mitspielers zur bestehenden Spielerliste
     * hinzu und erhoeht die Spieleranzahl ("currentPlayers") um 1.
     * Danach wird die neue Spieleranzahl an alle Mitspieler im Vector "players"
     * gesendet.
     * @param thread Thread des neuen Spielers
    */
    public void add( ServerThread thread ) {
        players.addElement( ( Object ) thread );
        currentPlayers++;

        for ( int i = 0; i < players.size(); i++ ) {
            ServerThread player = ( ( ServerThread ) players.elementAt( i ) );
            player.send( "1" + currentPlayers + " " + i );
        }
    }

    /**Loescht einen Spieler (also seinen ServerThread) aus dem "players" Vector
     * und sendet die um eins verminderte Zahl an alle uebrigen Spieler.
     * @param number Nummer des zu loeschenden Spielers
    */
    public void delete( int number ) {
        players.remove( number );
        currentPlayers--;
        System.out.println( "removed player " + ( number + 1 ) + " from list" );

        for ( int i = 0; i < players.size(); i++ ) {
            ServerThread player = ( ( ServerThread ) players.elementAt( i ) );
            player.send( "1" + currentPlayers + " " + i );
        }
    }

    /**Diese Methode liefert die aktuelle Spieleranzahl zurueck.
     * @return <code>int</code> Spieleranzahl
    */
    public int getCurrentPlayers() {
        return currentPlayers;
    }

    /**Diese Methode liefert die Spiel-ID des Spiels zurueck
     * @return <code>int</code> Spiel-ID
    */
    public int getGameID() {
        return gameID;
    }

    /**Diese Methode liefert den Namen des Spiels zurueck
     * @return <code>String</code> Name des Spiels
    */
    public String getNameOfTheGame() {
        return nameOfTheGame;
    }

    /**Diese Methode liefert den Vektor mit den ServerThreads zurueck
     * @return <code>Vector</code> ServerThread-Vektor
    */
    public Vector getPlayers() {
        return players;
    }

    /**Diese Methode liefert zurück, ob das Spiel voll ist oder nicht
     * @return <code>boolean</code> boolean
    */
    public boolean isFull() {
      return (maxPlayer < currentPlayers);
    }
    
    /** Diese Methode unterbricht die Verbindung (im Fehlerfall) zu allen
     *  Spielern eines Spiels, wenn das Spiel bereits gestartet ist. Ist das Spiel
     *  ncoh nicht gestartet, so wird nur der Spieler, der den Fehler gemeldet hat
     *  aus dem Spiel entfernt.
     *  @param errorPlayer Spieler mit Fehlermeldung
     *  @param message Fehlerursache
     */
    public void shutdown( int errorPlayer, String message ) {
        if ( is_running ) {
            for ( int i = 0; i < players.size(); i++ ) {
                ServerThread player = ( ( ServerThread ) players.elementAt( i ) );

                if ( i != errorPlayer ) {
                    player.send( "0" + message );
                    player.closeConnection();
                    System.out.println( "game,shutdown: " + i );
                }
            }

            players.removeAllElements();
        } else {
            delete( errorPlayer );
        }
    }

    /**Sendet an alle Spieler die Nachricht, dass das Spiel gestartet werden kann.
     * Diese Methode wird vom ServerThread des ersten Spielers aufgerufen, nachdem dieser
     * den "Spiel starten"-Button betaetigt hat (siehe auch Diagramm "Spiel starten").
    */
    public void start() {
        this.is_running = true;

        for ( int i = 0; i < players.size(); i++ ) {
            ServerThread player = ( ( ServerThread ) players.elementAt( i ) );
            player.send( "1go" );
        }
    }
}

//$Log: Game.java,v $
//Revision 1.8  2001/07/03 21:52:17  y0013515
//minor updates
//
//Revision 1.7  2001/06/28 17:46:55  y0013515
//GUI.dispose() hinzugef?gt
//
//Revision 1.6  2001/06/27 22:04:46  y0013515
//update fuer das design und kleine aenderungen am netzwerk
//(kommentare)
//
//Revision 1.4  2001/06/21 18:36:24  y0013515
//netzwerk update mit kommentaren
//
//Revision 1.3  2001/06/20 23:13:58  y0013515
//alte files geloescht
//
//Revision 1.7  2001/06/18 08:06:08  y0013515
//NetzwerkUpdate:
//Socket-TimeOut eingestellt
//Fehlerbehandlung bei TimeOut Ueberschreitung hinzugefuegt
//
