/* Generated by Together */

package de.tubs.cs.iti.krypto.protokoll;

import java.net.*;
import java.io.*;
import java.util.*;

/**Die Klasse ServerThread uebernimmt eine Clientverbindung, nachdem diese durch
 * den Server initialisiert worden ist, so dass dieser fuer neue Verbindungen
 * wieder zur Verfuegung steht. Sie leitet Nachrichten an den Server weiter,
 * der diese dann (ueber einen weiteren ServerThread) an den entsprechenden
 * Ziel-Client sendet.
 * @author Wolfgang Schmiesing
 * @version 1.0
*/

public class ServerThread extends Thread {

    private Socket connection;
    private int gameID;
    private BufferedReader in;
    private int myNumber;
    private String nameOfTheGame;
    private PrintWriter out;
    private int playerNumber;
    private Server server;

    /**Konstruktor, uebernimmt eine Socket-Verbindung vom Server,
     * initialisiert die Ein-und Ausgabestreams des Sockets und speichert
     * seine Spielernummer, die er vom Server zugewiesen bekommt.
     * Diese wird dann zuletzt an den Communicator gesendet.
     * @param connection Socketverbindung
     * @param server Server-Objekt
     * @param cnt Spielernummer
     * @param gameID Spiel-ID
     * @param name Spielname
     * @exception IOException
     * @exception SocketException
    */
    public ServerThread( Socket connection, Server server, int cnt, int gameID,
                         String name ) {
        this.connection = connection;
        this.server = server;
        this.myNumber = cnt;
        this.gameID = gameID;
        this.nameOfTheGame = name;

        try {
            out = new PrintWriter( new BufferedWriter( new
                                   OutputStreamWriter( this.connection.getOutputStream() ) ) );
            in = new BufferedReader( new InputStreamReader(
                                         this.connection.getInputStream() ) );
        } catch ( IOException e ) {
            String log = "player " + ( myNumber + 1 ) + ":error creating ServerThread\n";
            System.out.print( log );
            this.server.log( log, server.getPort() );
        }

        send( "1" + Integer.toString( myNumber ) );  //sende die zugewiesene Spielernummer
        //an den Communicator
        try {
            this.connection.setSoTimeout( 1800000 );
            this.connection.setSoLinger( true, 6 );      //optional?
        }
        catch ( SocketException e ) {
            String log = "player " + ( myNumber + 1 ) + ": error setting socket options\n";
            System.out.print( log );
            this.server.log( log, server.getPort() );
        }
    }

    /**trennt die Socketverbindung zum entsprechenden Client
     * @exception IOException
     */
    public void closeConnection() {
        try {
            connection.close();
        } catch ( IOException e ) {
            String log = "player " + ( myNumber + 1 ) + ": error closing connection\n";
            System.out.print( log );
            server.log( log, server.getPort() );
        }
    }

    /**liefert die SpielID des zum ServerThread gehörigen Spiels zurueck
     * @return <code>int</code> Spiel-ID
    */
    public int getGameID() {
        return gameID;
    }

    /**Empfaengt einen String (blockiert solange, bis der eingestellte TimeOut
     * ueberschritten wurde) ueber die Socket-Verbindung vom Communicator-Objekt
     * des Clients.
     * @return <code>String</code> empfangene Daten
    */
    public String receive() throws InterruptedIOException, IOException {
	String s;
	int len;
	char[] c;
	StringWriter w = new StringWriter();
	PrintWriter result = new PrintWriter(w);

	// falls nichts zu lesen ist
	s = in.readLine();
	if (s == null) return null;

	// zuerst L"ange der zu empfangenen Daten lesen, dann Daten selbst
	len = Integer.parseInt(s);
	c = new char[len];
	if (in.read(c, 0, len) == -1)
	    System.out.println("ServerThread " + myNumber + " : error reading from socket!");

	
	/*
	while (s.equals("")) {
	    while(in.ready()) {	
		result.print(in.readLine());
		if (in.ready()) result.println();
	    }
	    result.flush();
	    w.flush();
	    s = w.toString();
	}
	*/

        return new String(c);
    }

    /**enthaelt den ausfuehrbaren Code des Threads; hier wird auf Nachrichten
     * gewartet, die dann ueber das Server-Objekt weitergeleitet werden koennen
     * (siehe Methode forward() des Servers). Die Zieladresse der Nachricht wird
     * ueberprueft, um dann die Nachricht an die entsprechende Server-Methode
     * weiterzugeben. Im Fehlerfall wird hier die Verbindung getrennt
     * und die Methode shutdown() auf dem Server aufgerufen,
     * um das Spiel zu entfernen.
     * @exception IOException
     * @exception InterruptedIOException
    */
    public void run() {
        while ( !isInterrupted() ) {
            //hier wird die Zieladresse (target) aus der Nachricht extrahiert
            try {
                String message = receive();
                //System.out.println("ServerThread "+myNumber+":"+" "+message);
                
		if ( message != null ) {
                    StringTokenizer ST = new StringTokenizer( message );
                    int target = Integer.parseInt( ST.nextToken() );
                    System.out.println( "sending message from " + myNumber + " to " + target );
                    //falls target="-1": Nachricht an Server; sonst Nachricht an Spieler x
                    if ( target >= -1 ) {
                        server.forward( gameID, message );
                    } else {
                        send( "1exit" );
                        server.deletePlayer( message + " " + gameID );
                        interrupt();

                        try {
                            connection.close();
                        } catch ( IOException ex ) {}

                    }

                }
                else {
                    String log = "Aborting game! Player "
                                 + ( myNumber + 1 ) + " has left the game\n";
                    System.out.print( log );
                    server.log( log, server.getPort() );
                    interrupt();
                    server.shutdown( nameOfTheGame + " "
                                     + myNumber + " " + gameID, log );
                }
            } catch ( InterruptedIOException e ) {
                String log = "Aborting game! TimeOut while receiving message"
                             + " from player " + ( myNumber + 1 ) + "\n";
                System.out.print( log );
                server.log( log, server.getPort() );
                interrupt();
                server.shutdown( nameOfTheGame + " " + myNumber + " " + gameID, log );
            }
            catch ( IOException e ) {
                String log = "Aborting game! Player "
                             + ( myNumber + 1 ) + " has left the game\n";
                System.out.print( log );
                server.log( log, server.getPort() );
                interrupt();
                server.shutdown( nameOfTheGame + " " + myNumber + " " + gameID, log );
            }
        }
    }

    /**Sendet den String "message" ueber die Socket-Verbindung an das Communicator-
     * Objekt des Clients.
     * @param message zu sendende Nachricht
    */

    public synchronized void send( String message ) {
	out.println(message.length());
        out.write( message );
        out.flush();
    }
}

//$Log: ServerThread.java,v $
//Revision 1.9  2001/07/03 21:52:18  y0013515
//minor updates
//
//Revision 1.7  2001/06/28 17:46:56  y0013515
//GUI.dispose() hinzugef?gt
//
//Revision 1.6  2001/06/27 22:04:46  y0013515
//update fuer das design und kleine Aenderungen am netzwerk
//(kommentare)
//
//Revision 1.4  2001/06/21 18:36:25  y0013515
//netzwerk update mit kommentaren
//
//Revision 1.3  2001/06/20 23:13:58  y0013515
//alte files geloescht
//
//Revision 1.7  2001/06/18 08:06:09  y0013515
//NetzwerkUpdate:
//Socket-TimeOut eingestellt
//Fehlerbehandlung bei TimeOut Ueberschreitung hinzugefuegt
//
