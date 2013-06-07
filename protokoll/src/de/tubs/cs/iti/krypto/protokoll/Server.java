/* Generated by Together */

package de.tubs.cs.iti.jcrypt.protokoll;

import java.net.*;
import java.io.*;
import java.util.*;

/**
 * Die Klasse Server implementiert ein eigenstaendiges Programm, das auf einem
 * Rechner gestartet wird, dessen Adresse den Spielern bekannt ist. Es soll bis
 * zu 50 Verbindungen mit Clients annehmen und die auf
 * diesen laufenden Spielprotokolle verwalten koennen.
 * @author Wolfgang Schmiesing
 * @version 1.0
 */

public class Server {

    private static int defaultPort = 4321;
    private Socket connection;
    private FileWriter fwriter;
    /**
     * @associates <{Game}>
     * @supplierCardinality 0..*
    */
    private Vector games;
    private BufferedReader in;
    private int port;
    private ServerSocket servSocket;

    /**Konstruktor, initialisiert die Variable servSocket durch Erzeugen eines
     * ServerSocket-Objekts auf dem angegebenen Port. Desweiteren wird der Vektor
     * "games" initialisiert, der die Spiele vom Typ Game enthalten wird.
     * @param port Portnummer
    */
    public Server( int port ) throws IOException {
        String log;
        this.port = port;
        servSocket = new ServerSocket( port );
        this.games = new Vector();
        log = "Hello! This is RoughNetzServer (listening on port " + port + "): Waiting for connections!\n";
        System.out.print( log );
        this.log( log, port );
    }

    /**Diese Methode dient zum Aufnehmen eines neuen Spielers. Sie verarbeitet die
     * in "data" enthaltenen Spielerdaten (Name des Spiels, minimale und maximale
     * Spieleranzahl des Spiels)  und entscheidet dann, ob der Spieler in ein
     * bestehendes Spiel vom Typ Game hinzugefuegt werden kann, oder ob ein neues
     * Objekt vom Typ "Game" erzeugt werden muss.
     * Dann wird ein eigener Thread fuer den neuen Spieler erzeugt, der in der
     * "players" Liste des jew. Game-Objekts abgespeichert wird.
     * @param data Daten des neuen Spielers
     * @exception NoSuchElementException
    */

    public synchronized void addPlayer( String data ) {
        try {
            boolean exists = false;
            int count = 1;
            String log = "";
            StringTokenizer ST = new StringTokenizer( data );
            ST.nextToken();         //Zieladresse, ist hier uninteressant
            String name = ST.nextToken();
            int min = Integer.parseInt( ST.nextToken() );
            int max = Integer.parseInt( ST.nextToken() );

            for ( int i = 0; i < games.size(); i++ ) {
                Game game = ( Game ) games.elementAt( i );

                if ( game.getNameOfTheGame().equals( name ) ) {
                    if ( game.is_running || game.isFull() ) {
                        count++;
                    } else {
                        ServerThread thread = new ServerThread( this.connection, this,
                                                                game.getCurrentPlayers(), game.getGameID(),
                                                                game.getNameOfTheGame() );
                        thread.start();
                        game.add( thread );
                        log = "server: player added in: " + name + ", ID:" + game.getGameID() + "\n";
                        System.out.print( log );
                        log( log, port );
                        exists = true;
                    }
                }
            }

            if ( !exists ) {
                ServerThread thread = new ServerThread( this.connection, this, 0, count, name );
                thread.start();
                games.addElement( ( Object ) new Game( thread, min, max, name ) );
                log = "server: started new game: " + name + " min" + min + " max" + max + "\n";
                System.out.print( log );
                log( log, port );
            }
        } catch ( NoSuchElementException e ) {
            String log = "server: corrupt message in method addPlayer\n";
            System.out.print( log );
            log( log, port );
        }
    }

    /**Diese Methode loescht einen Spieler aus einem Spiel, wenn dieser z.B. seinen
     * Client vor Beginn des Spiels beendet hat. Dazu wird die delete-Methode des
     * entsprechenden Game-Objekts aufgerufen.
     * @param data zu loeschender Spieler
     * @exception NoSuchElementException
    */
    public synchronized void deletePlayer( String data ) {
        try {
            String log;
            StringTokenizer ST = new StringTokenizer( data );
            ST.nextToken();
            String name = ST.nextToken();
            int player = Integer.parseInt( ST.nextToken() );
            int gameID = Integer.parseInt( ST.nextToken() );
            log = "server: deleting player " + player + " in Game " + name + " ID:" + gameID + "\n";
            System.out.print( log );
            log( log, port );

            for ( int i = 0; i < games.size(); i++ ) {
                Game game = ( Game ) games.elementAt( i );

                if ( game.getNameOfTheGame().equals( name ) && gameID == game.getGameID() ) {
                    game.delete( player );

                    if ( game.getPlayers().size() == 0 ) {
                        games.remove( i );
                        System.out.println( "server: game " + ( i + 1 )
                                            + " removed from list" );
                    }
                }
            }
        } catch ( NoSuchElementException e ) {
            String log = "server: corrupt message in method deletePlayer\n";
            System.out.print( log );
            log( log, port );
        }
    }

    /**Diese Methode dient zum Weiterleiten von Nachrichten zum Zielspieler,
     * der im String "data" enthalten ist. Sie wird vom sendenden ServerThread
     * aufgerufen und schickt die Nachricht ueber den Ziel-ServerThread an das
     * entsprechende Communicator-Objekt des Empfaengers. Die Variable "gameID"
     * (s. Klasse ServerThread) dient der Methode zur Unterscheidung von mehreren
     * Spielen des gleichen Typs. Auerdem werden Meldungen, die an den Server
     * direkt gehen, an die entsprechenden Methoden des Servers weitergeleitet
     * ("Spiel starten" und "Client beendet").
     * Diese Meldungen erkennt die Methode daran, dass die Zieladresse im
     * String "data" (normalerweise die Spielernummer des Empfaengers) negativ ist.
     * @param gameID Spiel-ID
     * @param data zu sendende Nachricht
     * @exception NoSuchElementException
    */

    public synchronized void forward( int gameID, String data ) {
        //hier wird der String in seine Einzelteile zerlegt
        //(Zieladresse, Name, Nachricht)
        try {
            StringTokenizer ST = new StringTokenizer( data );
            String player = ST.nextToken();
            String name = ST.nextToken();
            String msg = data.substring( name.length() + player.length() + 2 );
            int target = Integer.parseInt( player );

            //suche passendes Game-Objekt und sende die Nachricht an den Empfaenger
            for ( int i = 0; i < games.size(); i++ ) {
                Game game = ( Game ) games.elementAt( i );

                if ( game.getNameOfTheGame().equals( name ) && gameID == game.getGameID() ) {
                    if ( target != -1 ) {
                        ServerThread recipient = ( ( ServerThread )
                                                   game.getPlayers().elementAt( target ) );
                        recipient.send( "1" + msg );
                    } else {
                        //falls nachricht an server gerichtet ist (player "-1", nachricht "go"),
                        //teile mit, dass das Spiel gestartet werden kann
                        if ( msg.equals( "go" ) ) {
                            game.start();
                        }

                    }

                }

            }

        } catch ( NoSuchElementException e ) {
            String log = "server: corrupt message in method forward!\n";
            System.out.print( log );
            log( log, port );
        }
    }

    /**
     * Diese Methode liefert die Portnummer des Servers zurueck.
     * @return <code>int</code> Portnummer
     */
    public int getPort() {
        return port;
    }

    /**Diese Methode speichert die Nachrichten, die der Server
     * ausgibt in einer Log-Datei ab.
     * @param message Nachricht, die gespeichert werden soll
     * @param portnr Portnummer des Servers, (im Logfile integriert)
     * @exception IOException
    */
    public void log( String message, int portnr ) {
        try {
            fwriter = new FileWriter( "serverlog.log", true );
            fwriter.write( message );
            fwriter.close();
        } catch ( IOException e ) {
            System.out.println( "server: error during logfile operation" );
        }
    }

    /**In dieser Methode wird eine neue Instanz vom Typ Server erzeugt. Danach
     * werden innerhalb einer Endlosschleife Verbindungen angenommen, denen von
     * der Methode addPlayer ein eigener Thread zugewiesen wird und die in der
     * Liste "games" verwaltet werden.
     * @param args Kommandozeilenparameter
     * @exception IOException
     * @exception NumberFormatException
     * @exception InterruptedIOException
    */
    public static void main( String[] args ) {
        int newport = 0;
        String log = "";

        if ( args.length > 0 ) {
            args[ 0 ].trim();

            try {
                newport = Integer.parseInt( args [ 0 ] );
            } catch ( NumberFormatException e ) {
                if ( !args[ 0 ].equalsIgnoreCase( "-h" ) ) {
                    System.out.println( "server: Invalid argument" );
                } else {
                    System.out.println( "Syntax: java Server [port-number]" );
                }

                System.exit( 0 );
            }
        } else {
            newport = defaultPort;  //falls kein Port angegeben wurde
        }

        if ( newport < 1024 ) {   //teste, ob Portnummer gueltig ist
            System.out.println( "server: Invalid port number! Using default port " + defaultPort );
            newport = defaultPort;
        }

        try {
            Server serv = new Server( newport );

            while ( true ) {
                serv.connection = serv.servSocket.accept();   //blockiert, bis neuer
                //Client sich anmeldet
                serv.connection.setSoTimeout( 60000 );
                serv.in = new BufferedReader( new
                                              InputStreamReader( serv.connection.getInputStream() ) );
                String msg = serv.receive();
                serv.addPlayer( msg );   //hier werden die Spieldaten erwartet
                //(Spielname, min/maxPlayer)
                log = "server: Accepted new connection to client on port " + serv.connection.getPort() + "\n";
                System.out.print( log );
                serv.log( log, newport );
                log = "server:received data from new player: " + msg + "\n";
                System.out.print( log );
                serv.log( log, newport );
            }
        } catch ( InterruptedIOException e ) {
            System.out.println( "server: client not responding" );
        }
        catch ( IOException e ) {
            System.out.println( "server: error connecting to client" );
        }
    }

    /**Diese Methode empfaengt die Spieldaten,
     * die der Client bei der Anmeldung an den Server sendet.
     * @return <code>String</code> empfangene Nachricht
    */
    public String receive() throws InterruptedIOException, IOException {
        String s;
	int len;
	char[] c;

	// zuerst L"ange der zu empfangenen Daten lesen, dann die Daten selbst

	len = Integer.parseInt(in.readLine());
	c = new char[len];
	if (in.read(c, 0, len) == -1)
	    System.out.println("server: error receiving data!");

        return new String(c);
    }

    /**Diese Methode unterbricht die Verbindung zu den Spielern eines Spiels.
     * Sie wird vom ServerThread des Spielers aufgerufen, dessen Client die
     * Verbindung als erster unterbrochen hat. Nach Aufruf der Methode shutdown()
     * in Klasse Game wird dann das Spiel ggf. aus der Liste geloescht.
     * @param data Datenstring mit GameID, Spielname und Spielernummer
     * @param errmsg Grund fuer das Ende des Spiels
     * @exception NoSuchElementException
     */

    public synchronized void shutdown( String data, String errmsg ) {          //synchronized???
        try {
            String log;
            StringTokenizer ST = new StringTokenizer( data );
            String name = ST.nextToken();
            int player = Integer.parseInt( ST.nextToken() );
            int gameID = Integer.parseInt( ST.nextToken() );

            for ( int i = 0; i < games.size(); i++ ) {
                Game game = ( Game ) games.elementAt( i );

                if ( game.getNameOfTheGame().equals( name ) && gameID == game.getGameID() ) {
                    game.shutdown( player, errmsg );

                    if ( game.getPlayers().size() == 0 ) {
                        games.removeElementAt( i );
                        System.out.println( "server: game removed" );
                    }
                }
            }

            log = "server: shutting down player " + player + " in Game " + name + " ID:" + gameID + "\n";
            System.out.print( log );
            log( log, port );
        } catch ( NoSuchElementException e ) {
            String log = "server: corrupt message in method shutdown\n";
            System.out.print( log );
            log( log, port );
        }
    }
}

//$Log: Server.java,v $
//Revision 1.9  2001/07/03 21:52:17  y0013515
//minor updates
//
//Revision 1.8  2001/06/28 17:46:55  y0013515
//GUI.dispose() hinzugef?gt
//
//Revision 1.7  2001/06/27 22:04:46  y0013515
//update fuer das design und kleine Aenderungen am netzwerk
//(kommentare)
//
//Revision 1.3  2001/06/20 23:13:58  y0013515
//alte files geloescht
//
//Revision 1.8  2001/06/18 08:06:09  y0013515
//NetzwerkUpdate:
//Socket-TimeOut eingestellt
//Fehlerbehandlung bei TimeOut Ueberschreitung hinzugefuegt
//
