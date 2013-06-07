/* Generated by Together */

package de.tubs.cs.iti.jcrypt.protokoll;

import java.net.*;
import java.io.*;
import java.util.*;

/**
 * Die Klasse Client stellt im Grunde das Hauptprogramm dar.
 * Hier werden die Methoden realisiert, die fuer den Benutzer wichtig sind,
 * wie z.B. der Konstruktor Client, sowie die Methoden zum Anmelden/Abmelden
 * am/vom Server und zum Starten des Spiels.
 * @author Marcus Lagemann
 * @version 1b
 */

public class Client implements IClient {
    private static String defaultHost = "localhost";
    private static int defaultPort = 4321;
    private String logfile;

    private String protocolName;
    private int maxPlayer;
    private int minPlayer;
    private int port;
    private String host;

    /**
     * @supplierCardinality 1
     * @clientCardinality 1
     * @undirected
     */
    private ClientGUI myGUI;
    private Protocol protocol;

    /**
     * @supplierCardinality 1
     */
    private Communicator myCom;


    /**
     * Der Konstruktor von Client erzeugt ein neues ClientGUI-Objekt und ueber
     * gibt sich selbst dem ClientGUI-Objekt.
     * Zudem erzeugt er eine Log Datei.
     * @param userPort Der Anfangswert fuer den Port
     * @param userHost Der Anfangswert fuer den Host
     */
    public Client( int userPort, String userHost ) {
        port = userPort;
        host = userHost;

        int i = 0;

        GregorianCalendar cal = new GregorianCalendar();

        String date = cal.get( Calendar.DATE ) + "" +
                      ( cal.get( Calendar.MONTH ) + 1 ) + "" +
                      cal.get( Calendar.YEAR );

        File f = new File( "" );

        do {
            i++;
            logfile = "Client" + date + "-" + i + ".log";

            try {
                f = new File( logfile );
            } catch ( Exception e ) {
                System.out.println( e );
            }
        } while ( f.exists() );

        date = cal.get( Calendar.DATE ) + "." +
               ( cal.get( Calendar.MONTH ) + 1 ) + "." +
               cal.get( Calendar.YEAR );

        String log = "Roughnetz Client logfile " + logfile + " from " + date;

        System.out.println( log );

        log( log );

        myGUI = new ClientGUI( userPort, userHost );

        myGUI.setClient( this );

    }

    /**
      * gibt den Communicator zurueck
      * @return <code>int</code> Portnummer
      */
    public Communicator getCommunicator() {
        if ( myCom != null )
            return myCom;
        else
            return null;
    }

    /**
     * gibt den Namen des Protokolls zurueck
     * @return <code>String</code> Protokollname
     */
    public void setProtocolName( String newProtocolName ) {
        protocolName = newProtocolName;
        System.out.println( "new protocol name:" + protocolName + "!" );
        log( "new protocol name:" + protocolName + "!" );
    }

    /**
     * gibt den Namen des Protokolls zurueck
     * @return <code>String</code> Protokollname
     */
    public String getProtocolName() {
        return protocolName;
    }

    /**
     * gibt den Hostnamen zurueck
     * @return <code>String</code> Hostname
     */
    public String getHost() {
        return host;
    }

    /** setzt den Hostnamen
     * @param newHost zu setztender Hostname
     */
    public void setHost( String newHost ) {
        host = newHost;
        System.out.println( "New host: " + host );
        log( "New host: " + host );
        myGUI.printOutput( "Neuer Hostname ist " + host );
    }

    /**
     * gibt den Portnamen zurueck
     * @return <code>int</code> Portnummer
     */
    public int getPort() {
        return port;
    }

    /**Setzt die Port Nummer auf den angegebenen Wert, wenn dieser korrekt ist.
     * @param newPort zu setzende Portnummer
     */
    public boolean setPort( int newPort ) {
        if ( newPort > 1024 && newPort < 9999 ) {
            port = newPort;
            System.out.println( "New port: " + port );
            log( "New port: " + port );
            myGUI.printOutput( "Neue Portnummer ist " + port );
            return true;
        } else
            return false;
    }

    /** Versucht das Spielprotocol zu laden zu laden und gibt zurueck ob das
     *  erfolgreich war.
     *  @param protocolName Das zu ladende Spielprotokoll.
     *  @return <code>boolean</code> Spiel geldaden?
     */
    public boolean loadGame( String protocolName ) {
        System.out.println( "Try loading Protocol " + protocolName );
        log( "Try loading Protocol " + protocolName );
        myGUI.printOutput( "Versuche Protokoll " + protocolName + " zu laden" );
        protocol = null;

        try {
            // Lade Protokoll.
            protocol = ( Protocol ) Class.forName( protocolName ).newInstance();
        } catch ( java.lang.ClassNotFoundException e ) {
            myGUI.printOutput( "Protokoll-Klasse " + protocolName + " nicht gefunden!" );
            System.err.print( "java.lang.ClassNotFoundException : " + protocolName );
            log( "java.lang.ClassNotFoundException :" + protocolName );
        }
        catch ( java.lang.IllegalAccessException e ) {
            myGUI.printOutput( "Protokoll-Klasse " + protocolName +
                               " konnte nicht geladen werden" );
            System.err.print( "java.lang.IllegalAccessException : " + protocolName );
            log( "java.lang.IllegalAccessException : " + protocolName );
        }
        catch ( java.lang.InstantiationException e ) {
            myGUI.printOutput( "Protokoll-Klasse " + protocolName +
                               " konnte nicht geladen werden" );
            System.err.print( "java.lang.InstantiationException : " + protocolName );
            log( "java.lang.InstantiationException : " + protocolName );
        }
        catch ( Exception e ) {
            System.err.print( e.toString() );
            log( e.toString() );
        }

        if ( protocol != null )
            return true;
        else
            return false;
    }

    /**
     * Prueft, ob die Spieleranzahl die Mindestanzahl an Spielern erreicht
     * hat und aktiviert den Button "Spiel Starten".
     * @param newPlayerNumber Die neue Spieleranzahl
     */
    public void playerNumberChanged( int newPlayerNumber ) {
        if ( myCom.myNumber() == 0 ) {

            if ( newPlayerNumber >= minPlayer )
                myGUI.enableStartGame( true );

            if ( newPlayerNumber < minPlayer )
                myGUI.enableStartGame( false );
        }

        myGUI.printOutput( "" );
        log( "new player number: " + myCom.myNumber() );
    }

    /**
     * Besorgt sich zunaechst die spielrelevanten Daten von seinem Spielprotokoll.
     * Danach erzeugt sie ein neues Objekt vom Typ Communicator und
     * uebergibt diesem die Spieldaten sowie den gewuenschten Servernamen/Port.<br>
     * Als letztes ruft der Client noch die Methode setCommunicator() des
     * Spielprotokolls auf, um die neue Verbindung mit dem Spielprotokoll
     * zu verknuepfen.
     * @todo Java.lang.InstantiationException abfangen bei EIngabe von z.B. Client
     */
    public void connect() {
        String shortName = protocol.nameOfTheGame();
        minPlayer = protocol.minPlayer();
        maxPlayer = protocol.maxPlayer();
        System.out.println( "Try to connect to " + host + ":" + port );
        log( "Try to connect to " + host + ":" + port );
        myGUI.printOutput( "Versuche zu verbinden mit " + host + ":" + port );

        try {
            myCom = new Communicator( host, port, shortName, minPlayer, maxPlayer, this );
            protocol.setCommunicator( myCom );
            myGUI.enableConnectToServer( false );
            log( "Connected to Server, player number: " + myCom.myNumber() );
            System.out.println( "Wait for Players!" );
            log( "Wait for Players!" );
            myGUI.printOutput( "Warte auf weitere Spieler!" );
            boolean connected = true;


            if ( myCom.waitForPlayers() ) {
                System.out.println( "game startet!" );
                log( "game startet!" );
                myGUI.printOutput( "Spiel wird gestartet!" );
                myGUI.setVisible( false );

                if ( myCom.myNumber() > 0 )
                    protocol.receiveFirst();
                else
                    protocol.sendFirst();

                System.out.println( "game ended!" );

                log( "game ended!" );

                myGUI.printOutput( "Spiel ist zuende!" );

                myGUI.setVisible( true );

                myCom.sendTo( -2, String.valueOf( 0 ) );

                disconnect();

                myGUI.enableConnectToServer( true );
            }
        } catch ( UnknownHostException ex ) {
            myGUI.printOutput( host + " nicht gefunden!" );
            System.err.println( ex );
            log( ex + " : " + host );
        }
        catch ( IOException ex ) {
            myGUI.printOutput( "Verbindung fehlgeschlagen!" );
            System.err.println( ex );
            log( ex + " : " + host );
        }

    }

    /**
     * Ueberprueft, ob Communicator Objekt vorhanden ist, wenn dies der Fall ist,
     * wird an den Server die Abmelde-Nachricht geschickt und das Communicator
     * Objekt auf null gesetzt.
     */
    public void disconnect() {
        if ( myCom != null ) {
            myCom.sendTo( -2, String.valueOf( myCom.myNumber() ) );
            System.out.println( "Disconnecting from " + host + ":" + port );
            log( "Disconnecting from " + host + ":" + port );
            myCom = null;
            myGUI.printOutput( "Getrennt von " + host + ":" + port );
            myGUI.enableStartGame( false );
        }
    }

    /** Sendet dem Server die Nachricht zum Spielstart und started die Methode
     * SendFirst vom Protokoll.
     */
    public void startGame() {
        myCom.sendTo( -1, "go" );
    }

    /**
     * Testet ob bereits ein Communicator Objekt erzeugt wurde(also ob man am
     * Server angemeldet ist) und schickt dann, wenn notwendig dem Server, dass
     * er sich beendet. Dann wird der Client beendet.
     */
    public void exit() {
        if ( myCom != null )
            myCom.sendTo( -2, String.valueOf( myCom.myNumber() ) );

        log( "User exited Client." );

        System.exit( 0 );
    }

    /**
     * Diese Methode macht das Client Fenster wieder sichtbar, benachrichtigt den Anwender mittels
     * eines popUpFensters ueber den Abbruch des Spiels durch einen anderen Spieler und Schliesst
     * den Client danach. Die Methode wird vom Communicator aufgerufen, wenn ein anderer Spieler
     * das laufende Spiel abbricht.
     * @param message Nachricht, die ausgegeben werden soll
     **/
    public void end( String message ) {
        myGUI.setVisible( true );
        new popUpWindow( myGUI , message , true );
        log( "Client closed by Server." );
        System.exit( 0 );
    }

    /**Diese Methode speichert die Nachrichten, die der Server
      * ausgibt in einer Log-Datei ab.
      * @param message Nachricht, die gespeichert werden soll
     */
    public void log( String message ) {
        try {
            FileWriter fwriter = new FileWriter( logfile, true );
            fwriter.write( message + "\n" );
            fwriter.close();
        } catch ( IOException e ) {
            System.out.println( "client: error during logfile operation" );
        }
    }

    /**
     * Hauptprogramm: Hier werden die Eingabeparameter untersucht und verarbeitet
     * und der Client erzeugt.
     * @param args Array von Eingabe parametern
     */
    public static void main( String[] args ) {
        int port = defaultPort;
        String host = defaultHost;

        //Auf Eingabeparameter ueberpruefen und gegebenenfalls setzten.
        if ( args.length > 0 ) {
            for ( int i = 0;i < args.length;i++ ) {
                //Pruefen, ob ein Parameter den Port angibt.
                if ( ( args[ i ] = args[ i ].toLowerCase() ).startsWith( "-port=" ) ) {
                    try {
                        port = Integer.parseInt( args[ i ].substring(
                                                     args[ i ].indexOf( "=" ) + 1 ) );
                    } catch ( NumberFormatException e ) {
                        System.out.println( "Error parsing parameters!" );
                        System.out.println( "-->Exception:" + e +
                                            "\n Invalid port format! Using default port." );
                    }
                }

                //Pruefen, ob port richtiges Format hat.
                if ( port < 1024 || port > 9999 ) {
                    System.out.println( "Invalid port number! Using default port." );
                    port = defaultPort;
                }

                //Pruefen, ob ein Parameter den Hostnamen angibt;
                if ( ( args[ i ] = args[ i ].toLowerCase() ).startsWith( "-host=" ) ) {
                    try {
                        host = args[ i ].substring( args[ i ].indexOf( "=" ) + 1 );
                    } catch ( Exception e ) {
                        System.out.println( "Error parsing parameters!" );
                        System.out.println( "-->Exception:" + e + "\n Invalid host argument." );
                    }
                }

                if ( host.length() < 4 ) {
                    System.out.println( "Invalid host name" );
                    host = defaultHost;
                }
            }
        }

        //Neues Objekt von Client erzeugen.
        Client client = new Client( port, host );
    }
}

//
// $Log: Client.java,v $
// Revision 1.11  2001/07/04 22:09:46  y0013406
// changed javadoc comments
//
// Revision 1.10  2001/07/03 23:42:40  y0013406
// added some logging
//
// Revision 1.9  2001/07/03 23:04:36  y0013406
// minor updates
//
// Revision 1.8  2001/07/02 21:08:15  y0013406
// changed comments and tex-files
//
// Revision 1.7  2001/07/01 18:23:14  y0013406
// added logging
// added method log()
// changed constructor Client() (logging functions)
// added method end()
//
// Revision 1.6  2001/06/27 18:26:14  y0013406
// changed method connect() (repeats waitForPlayers when game ended)
// changed method playerNumberChanged() (now updates Label output)
//
// Revision 1.5  2001/06/21 15:22:26  y0013406
// changed comments
//
// Revision 1.4  2001/06/21 09:13:18  y0013406
// method connect() changed
//
// Revision 1.3  2001/06/19 15:12:23  y0013406
// corrected setPort()
//
// Revision 1.2  2001/06/19 14:46:17  y0013406
// improved method connect()
//
// Revision 1.1  2001/06/18 22:07:28  y0013406
// added Client and Client to Package stuff!
//
// Revision 1.8  2001/06/18 00:01:00  y0013406
// method loadGame() changed
// method startGame() changed
// method connect() changed
// replaced  the dummys with protocol.method calls
// now runs with the real protocol Kniffel!
//
// Revision 1.7  2001/06/17 23:16:51  y0013406
// method disconnect() changed
// method connect() changed
// method playerNumberChanged() corrected
// added several comments
// should be ready for testing
//
// Revision 1.6  2001/06/17 21:05:16  y0013155
// Kniffel.java ist lauffaehig, allerdings sind an einigen Stellen noch Dummys.
// Der Gesamtspielablauf funktioniert aber bereits.
// Marco
//
// Revision 1.5  2001/06/14 18:39:20  y0013406
// added methods in Client und ClientGUI
//
