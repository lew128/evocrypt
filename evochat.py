#!/usr/bin/python3

"""
Client and server classes for TCP connections, as well as a simple
chat implementation using the prng module.
"""

import pdb                  # a desperation measure
import sys
import time
import datetime
import socket
import select
import threading
import queue
import signal
import curses
import traceback
import getopt
import binascii
import struct
import random
import evoutils
from evocprngs import CRYPTO
from evornt    import RNT
from evoutils  import VERBOSITY_LEVEL, DEBUG_FD, debug, close_files_and_exit, \
                     print_stacktrace, print_stacktrace_exit



__version__   = "0.3"
__revision__  = "$$"
__date__      = "2014-02-08"
__author__    = "nobody@nowhere.com"
__copyright__ = "None"
__license__   = "None"
__filename__  = "evochat.py"
__history__   = """
    0.1 - 20140127 - started this file from scratch.
                28 - annoying problem with threading : could not start()
                     client or server.  Trivial to fix, added c_or_s in
                     the class data and then run() doesn't need args
                29 - couldn't work today
                30 - added signal handler and stdin lines sent/received.
                     added user message encryption/decryption
                        that worked the first time I tried it.
    0.2 - 20140208 - added documentation, cleaned up the code,
                     added datetime string to passphrase to init prng
                     added different send/recv prngs
          all those worked the first time.
    0.3 - 20180605 Converted to Python3, upgraded to use the new
          evocrypt functions. Major PITA, probably should have
          understood P3 better before beginning.
    """

class TCP() :
    """
    Client and server class for TCP.
    """

    def __init__( self, address, port, max_pdu ) :
        """
        Initialize private variables and set up the socket.
        """
        self.address            = address
        self.port               = port
        self.max_pdu            = max_pdu
        self.client_or_server   = None
        self.connecting_address = None
        self.connection         = None
        self.socket             = None

    def connect( self, client_or_server ) :
        """
        Connects a socket as client or server.
        """

        self.client_or_server = client_or_server

        if client_or_server in [ 'client', 'Client' ] :

            try :
                self.socket = socket.socket( socket.AF_INET, socket.SOCK_STREAM)

            except socket.error as the_error :
                errno, strerror = the_error.args
                sys.stderr.write( "socket [ERROR] %s\n" % strerror )
                sys.exit( 2 )

            except socket.herror as the_error :
                errno, strerror = the_error.args
                sys.stderr.write( "socket h address [ERROR] %s\n" % strerror )
                sys.exit( 2 )

            except socket.gaierror as the_error :
                errno, strerror = the_error.args
                sys.stderr.write( "socket g address [ERROR] %s\n" %
                strerror )
                sys.exit( 2 )

            except socket.timeout as the_error :
                errno, strerror = the_error.args
                sys.stderr.write( "socket timeout [ERROR] %s\n" %
                strerror )
                sys.exit( 2 )

            self.socket.settimeout( 10 )

            try :
                self.socket.connect( ( self.address, self.port ) )

            except socket.error as the_error :
                errno, strerror = the_error.args
                sys.stderr.write("[ERROR] %s\n" % strerror )
                sys.exit(2)

        elif client_or_server in [ 'server', 'Server' ] :
            try :
                self.socket = socket.socket( socket.AF_INET, socket.SOCK_STREAM)

            except socket.error as the_error :
                errno, strerror = the_error.args
                sys.stderr.write( "socket [ERROR] %s\n" % strerror )
                sys.exit( 2 )

            try :
                self.socket.bind( ( self.address, self.port ) )

            except socket.error as the_error :
                errno, strerror = the_error.args
                sys.stderr.write( "socket [ERROR] %s\n" % strerror )
                sys.exit( 2 )

            try :
                self.socket.listen( self.max_pdu )

            except socket.error as the_error :
                errno, strerror = the_error.args
                sys.stderr.write( "socket [ERROR] %s\n" % strerror )
                sys.exit( 2 )

            try :
                self.connection, self.connecting_address = self.socket.accept()

            except socket.error as the_error :
                errno, strerror = the_error.args
                sys.stderr.write( "socket [ERROR] %s\n" % strerror )
                sys.exit( 2 )

        else :
            print( "TCP : don't recognize Client or Server ", client_or_server )
            sys.exit( 0 )

    def set_max_pdu( self, max_pdu ) :
        """
        Sets the maximum PDU for the connection.
        """
        self.max_pdu = max_pdu

    def recv( self, max_pdu ) :
        """
        returns data from the socket connection.
        """
        return self.socket.recv( max_pdu )

    def send( self, data ) :
        """
        sends data.
        """
        self.socket.send( data )


    def select( self, tcp_list ) :
        """
        returns sockets in ready to read, write, error lists.
        """

        if not tcp_list :
            return None, None, None

        # construct the socket list from the tcp_list
        socket_list = []
        for tcp_socket in tcp_list :
            socket_list.append( tcp_socket )

        #
        # happens when the other side is closed
        #
        if not socket_list :
            return None, None, None

        try :
            ready_to_read, ready_to_write, in_error = \
                select.select( socket_list, [], [], 0 )

        except select.error as the_error :
            errno, strerror = the_error.args
            print( "select.error", select.error )
            print( "select.args", the_error.args )

        if in_error :
            print( "in_error" )

        return ready_to_read, ready_to_write, in_error 

class TCPThread( threading.Thread ) :
    """
    Sets up threads, the queues back to main and the PRNGs used for
    encoding sends and decoding recvs.
    """

    def __init__( self, passphrase, max_pdu, client_or_server,
                  server_ip_addr, system_type ) :

        self.queue_to_main   = queue.Queue()
        self.queue_from_main = queue.Queue()

        assert len( passphrase ) > 0, "you must supply a passphrase"
        assert client_or_server in [ 'Client', 'CLIENT', 'client' ] or \
               client_or_server in [ 'Server', 'SERVER', 'server' ], \
               "You must specify 'client' or 'server'"
        #
        # Don't want to reuse a passphrase as the opponent can decipher
        # the two streams if that happens. So client and server exchange
        # random numbers, eash side using its own number added to the
        # passphrase for sending.

        # Paranoia level should determine how many times the key was
        # changed, or added to, by exchanges of random numbers, each
        # time changing the RNT and the crypto, but that is for later.

        self.begin_time        = datetime.datetime.utcnow()

        self.passphrase       = passphrase
        self.system_type      = system_type
        self.server_ip_addr   = server_ip_addr
        self.max_pdu          = max_pdu
        self.tcp_server       = None
        self.connection       = None
        self.tcp_client       = None
        self.tcp_connection   = None
        self.event            = threading.Event()
        self.client_or_server = client_or_server
        
        self.send_crypto      = None
        self.recv_crypto      = None

        self.client_initial_message = 'initial message from client'
        self.server_initial_message = 'initial message from server'

        try :
            self.log_fd = open( CLIENT_OR_SERVER + '_THREAD.log', 'w' )

        except :
            errno, strerror = the_error.args
            print( " error '" + str( errno ) + "'" )
            print( " error '" + strerror + "'" )
            sys.exit( -2 )

        threading.Thread.__init__( self )
        self.setDaemon( True )
        

    def run( self ) :
        """
        runs client or server, depending on which this thread is.
        """
        # end the thread when the parent exits.

        if   self.client_or_server in [ 'client', 'Client' ] :
            self.run_client()

        elif self.client_or_server in [ 'server', 'Server' ] :
            self.run_server()

        else :
            print( "no client or server = '" + self.client_or_server + "'" )
            sys.exit( 0 )

    def run_client( self ) :
        """
        Begins the code for the thread.
        """

#        self.log_fd.write( bytes( "Running client thread\n", 'UTF-8' ) )
        self.log_fd.write( "Running client thread\n" )

        #
        # set up the client socket
        #
        self.tcp_client = TCP( self.server_ip_addr, 5336, self.max_pdu )
        self.tcp_client.connect( 'Client' )
#        self.connection = self.tcp_client.connection

        #
        # Send a standard message to server and also receive one.
        #
        self.tcp_client.send( self.client_initial_message.encode( 'utf-8' ) )
        plain_text = self.tcp_client.recv( self.max_pdu )
        sys.stdout.write( "'" + plain_text.decode( 'utf-8' )  + "'\n" )
        if plain_text.decode( 'utf-8' ) not in self.server_initial_message :
            self.log_fd.write( "message received from server is wrong = '" + \
                                str( plain_text ) + "'" )
            sys.exit( -1 )

        #
        # Send a random number to server and also receive one from server
        #
        random.seed()
        client_random_number = random.getrandbits( 64 )
        self.tcp_client.send( struct.pack( "@Q", client_random_number ) )

        server_random_number = struct.unpack( "@Q",
                               self.tcp_client.recv( self.max_pdu ) )[ 0 ]

        #
        # Use the random number to make the password unique, avoiding
        # the big danger of XOR ciphers.
        #
        client_passphrase = self.passphrase + hex( client_random_number )
        server_passphrase = self.passphrase + hex( server_random_number )

        send_cryptos = CRYPTO( server_passphrase, self.system_type, 1 )
        recv_cryptos = CRYPTO( client_passphrase, self.system_type, 1 )
        self.send_crypto  = send_cryptos.next()
        self.recv_crypto  = recv_cryptos.next()

        #
        # use the event to stop the thread.
        #
        self.event.wait( 1 )

        #
        # Now all messages go through the queues
        #
        while True :
            if not self.queue_from_main.empty() :
                queue_msg = self.queue_from_main.get()
                self.log_fd.flush()
                self.tcp_client.send( queue_msg )

            #
            # select to see if there is anything to receive
            #
            ready_to_read, ready_to_write, in_error = \
                        self.tcp_client.select( [ self.tcp_client.socket ] )

            if ready_to_read :
                recv_msg = self.tcp_client.recv( self.max_pdu )
                self.log_fd.flush()
                self.queue_to_main.put( recv_msg )

            else :
                self.event.wait( 1 )

        
    def run_server( self ) :
        """
        Begins the code for the thread.
        """

#        self.log_fd.write( bytes( "Running server thread\n", 'UTF-8' ) )
        self.log_fd.write( "Running server thread\n" )

        #
        # set up the server socket
        #
        self.tcp_server = TCP( self.server_ip_addr, 5336, self.max_pdu )
        self.tcp_server.connect( 'Server' )
        self.connection = self.tcp_server.connection

        #
        # Send a standard message to client and also receive one.
        #
        self.connection.send( self.server_initial_message.encode( 'UTF-8' ) )

        plain_text = self.connection.recv( self.max_pdu )
        sys.stdout.write( "'" + plain_text.decode( 'UTF-8' )  + "'\n" )
        if plain_text.decode( 'utf-8' ) not in self.client_initial_message :
            print( "message received from client is wrong : '" +
                   plain_text.decode( 'utf-8' ) + "'\n" ) 
            sys.exit( -1 )

        #
        # Send a random number to server and also receive one from server
        #
        random.seed()
        server_random_number = random.getrandbits( 64 )
        self.connection.send( struct.pack( "@Q", server_random_number ) )

        client_random_number = struct.unpack( "@Q",
                               self.connection.recv( self.max_pdu ) )[ 0 ]

        #
        # Use the random number to make the password unique, avoiding
        # the big danger of XOR ciphers.
        #
        client_passphrase = self.passphrase + hex( client_random_number )
        server_passphrase = self.passphrase + hex( server_random_number )

        send_cryptos = CRYPTO( client_passphrase, self.system_type, 1 )
        recv_cryptos = CRYPTO( server_passphrase, self.system_type, 1 )
        self.send_crypto  = send_cryptos.next()
        self.recv_crypto  = recv_cryptos.next()

        #
        # use the event to stop the thread.
        #
        self.event.wait( 1 )

        #
        # Now all messages go through the queues
        #
        while True :
            if not self.queue_from_main.empty() :
                queue_msg = self.queue_from_main.get()
                self.log_fd.flush()
                self.connection.send( queue_msg )

            #
            # select to see if there is anything to receive
            #
            ready_to_read, ready_to_write, in_error = \
                        self.tcp_server.select( [ self.connection ] )

            if ready_to_read :
                recv_msg = self.connection.recv( self.max_pdu )
                self.log_fd.flush()
                self.queue_to_main.put( recv_msg )

            else :
                self.event.wait( 1 )

def signal_handler( signum, frame ):
    """Handler for the pkill signal.

    SIGHUP Hang up : indicates that the terminal a process is using has closed.
        Daemons that don't run in a terminal often respond to this
        signal by rereading configuration files or restarting their
        logging tools.

    SIGINT Interrupt : end program operation. The kernel sends this signal
        when you press Ctrl+C.

    SIGQUIT Quit : terminate and leave a core file for debugging purposes.
        Normally initiated by a user action.

    SIGABRT Abort : terminate and leave a core file for debugging purposes.
        Normally initiated by a debugging process or self-detected error.

    SIGKILL Kill : end program operation ungracefully;
        the program may not save open files, etc.

    SIGTERM 15  Termination (ANSI)

    SIGUSR1 User signal 1 : Effect varies from one program to another.

    SIGUSR2 User signal 2 : Effect varies from one program to another.

    SIGTERM Terminate : end program operation gracefully
        (closing open files, etc.).

    SIGCONT Continue : resume processing; undo the effect of a SIGSTOP signal.

    SIGSTOP Stop : suspend program operation, similar (but not identical)
        to the effect of pressing Ctrl+Z.

    """
#    log( 'Signal handler called with signal : ' + str( signum ) )

    sys.exit( 0 )       # final exit
    if signum == signal.SIGINT  or signum == signal.SIGQUIT or \
       signum == signal.SIGABRT or signum == signal.SIGTERM :

#        log( "Signal to end the program and all dependent processes" )
        close_files_and_exit( None, None )

        print( "\n\n!!! Trying hard to exit!!! \n\n" )
        sys.exit( 0 )       # final exit


def display_msgs( screen, sent_msgs, received_msgs ) :
    """
    handles display of text.
    """
    screen.clear()
    screen.box()

    for in_index in range( len( received_msgs ) ):
        screen.addstr( 1 + in_index,  2, received_msgs[ in_index ],
                curses.A_NORMAL )

    for out_index in range( len( sent_msgs ) ):
        screen.addstr( 15 + out_index, 2, sent_msgs[ out_index ],
            curses.A_NORMAL )

    screen.addstr( 21, 2, ' '*50, curses.A_NORMAL )
    screen.move(   21, 2 )

    screen.refresh()

def collect_text( screen, input_strings, received_strings, display_flag ):
    """
    Event loop.
    """

    input_string = ''
    while True :
        the_char = screen.getch()

        if the_char == 127 :
            input_string = input_string[ : -1 ]

        elif the_char == ord( '\n' ) :

            if display_flag :
                #
                # truncate the input list and append the new string.
                #
                if len( input_strings ) > 5 :
                    del input_strings[ 0 ]

                input_strings.append( input_string )

            #
            # and display all messages
            #
            if display_flag :
                display_msgs( screen, input_strings, received_strings )

            return input_string


        else :
            input_string += chr( the_char )
#            LOG_FD.write( "input_str = '" + input_string + '\n' )

            if display_flag :
                screen.addstr( 21, 2, input_string, curses.A_NORMAL )
                screen.refresh()


def init_window( ) :
    """
    Initializes the window.
    """

    try:
        # Initialize curses
        stdscr = curses.initscr()

        # Turn off echoing of keys, and enter cbreak mode,
        # where no buffering is performed on keyboard input
        curses.noecho()
        curses.cbreak()

        # In keypad mode, escape sequences for special keys
        # (like the cursor keys) will be interpreted and
        # a special value like curses.KEY_LEFT will be returned
        stdscr.keypad(1)

        # Frame the interface area at fixed VT100 size
        screen = stdscr.subwin( 23, 79, 0, 0 )
        screen.box()
        screen.refresh()

    except:
        # In event of error, restore terminal to sane state.
        stdscr.keypad(0)
        curses.echo()
        curses.nocbreak()
        curses.endwin()
        traceback.print_exc()           # print(the exception
        print( "failed to initialize the window, exiting\n" )
        sys.exit( 0 )

    return screen, stdscr

###############
#
# Special-purpose code to handle getting the passphrase.
#
###############



def get_passphrase( screen ) :
    """
    Returns the passphrase.  Don't echo, do it twice, compare, etc.
    """

    sent_strings = []
    rcvd_strings = []
    while True :
        #
        # and display all messages
        #

        sent_strings.append( 'Please enter your passphrase' )
        display_msgs( screen, sent_strings, rcvd_strings )
        passphrase0  = collect_text( SCREEN, sent_strings, rcvd_strings,
                                                                    False)
        sent_strings[ 0 ] = ( 'Please re-enter your passphrase' )
        display_msgs( screen, sent_strings, rcvd_strings )
        passphrase1  = collect_text( SCREEN, sent_strings, rcvd_strings,
                                                                    False )

        if passphrase0 == passphrase1 :
            return passphrase0

        else :
            print( "so sorry, your passphrases did not match" )
            print( "Please try again" )

###############
#
# End of the passphrase code
#
###############

def get_server_ip_address( screen ) :
    """
    Takes user input for an absolute ip address or a text name.
    """
    sent_strings = []
    rcvd_strings = []

    sent_strings.append( "please enter the server address\n" )
    display_msgs( screen, sent_strings, rcvd_strings )
    server_ip_address  = collect_text( SCREEN, sent_strings, rcvd_strings,
                                                                    True )
#    server_ip_address = sys.stdin.readline()

    # there are a lot of checks I could do on that address
    # assume IPv4 for now.
    return server_ip_address

def usage() :
    """
    This provides 'help' and other usage information.
    """
    usage_info = """

    This program provides encrypted chat sessions between 2 individuals.
    It uses a home-grown crypto-quality PRNG for the link.

    For both --client and --server, you will need to supply a passphrase
    and server IPv4 address.

    The passprhase is used to construct an initial state of a cryptographic
    pseudorandom number generator.  A date and time string is appended to
    that passphrase to prevent using passphrases more than once, which
    allows easily deciphering all messages that do so.

    Thus, the server needs started in the same minute as the client.
    The PRNG is not initialized until the server IP is entered, so
    you can coordinate hitting the carriage return at the same time
    after entering the server IP address.

        --help  Invokes this usage function
        -h      Invokes this usage function

        --client
                Sets up the client and connects to the server.

        --server
                Sets up the server and waits for a client to connect.

        --test  adds a test to be executed. Current tests are:
                'encode' encodes an internal, fixed set of tests
                'decode' decodes an internal, fixed set of tests


    """
    print( usage_info )
    sys.exit( 0 )


#
# main begins here
#

if __name__ == "__main__" :

    SHORT_ARGS = "h"
    LONG_ARGS  = [  'help' , 'client', 'server', 'password=',
                    'ip_address=', 'system=', 'test=' ]

    print( __filename__ )
    print( __version__ )
    print( sys.argv[ 1 : ] )

    TEST_LIST         = []      # list of tests to execute
    CLIENT_OR_SERVER  = None
    SERVER_IP_ADDR    = None
    PASSPHRASE        = None
    SYSTEM_TYPE       = None

    try :
        OPTS, ARGS = getopt.getopt( sys.argv[ 1 : ], SHORT_ARGS, LONG_ARGS )

    except getopt.GetoptError as the_error :
        errno, strerror = the_error.args
        print( "getopt.GetoptError = '" + str( the_error ) + "'" )
        sys.exit( -2 )

    for o, a in OPTS :
        print( o, a )
        if o in ( "--help" ) or o in ( "-h" ) :
            usage()
            sys.exit( -2)

        if o in ( "--client" ) :
            CLIENT_OR_SERVER = 'Client'

        if o in ( "--server" ) :
            CLIENT_OR_SERVER = 'Server'

        if o in ( "--system" ) :
            SYSTEM_TYPE = a

        if o in ( "--password" ) :
            PASSPHRASE = a

        if o in ( "--ip_address" ) :
            SERVER_IP_ADDR = a

        if o in ( "--test" ) :
            TEST_LIST.append( a )
            print( "Test = '" + str( TEST_LIST ) + "'" )

    if not CLIENT_OR_SERVER :
        print( "You must specify --Client or --Server" )
        usage()

    else :
        #
        # Set up the display
        #
        SCREEN, STDSCR = init_window()
    
        #
        # get the passphrase.  Don't echo, do it twice, compare, etc.
        #
        if not PASSPHRASE :
            PASSPHRASE = get_passphrase( SCREEN )
    
        #
        # get the Server, if the client
        #
        if not SERVER_IP_ADDR :
#        if CLIENT_OR_SERVER in [ 'Client', 'CLIENT', 'client' ] :
            SERVER_IP_ADDR = get_server_ip_address( SCREEN )
        
        #
        # Set the signal handler for killing the program
        #
        # This isn't working yet for some reason, no doubt threads
        signal.signal( signal.SIGTERM , signal_handler )
        signal.signal( signal.SIGINT  , signal_handler )
        signal.signal( signal.SIGQUIT , signal_handler )
        signal.signal( signal.SIGABRT , signal_handler )
    
        #
        # Spin off the thread to handle encryption and ip comms
        #
        TCP_THREAD = TCPThread( PASSPHRASE, 1500, CLIENT_OR_SERVER,
                                SERVER_IP_ADDR, SYSTEM_TYPE )
        TCP_THREAD.start()
    #    sys.exit( 0 )
    
        #
        # This is main(), just in case you need reminded
        #
        time.sleep( 1 )
    
        try :
            LOG_FD = open( CLIENT_OR_SERVER + '.log', 'w' )
    
        except IOError as the_error :
            errno, strerror = the_error.args
            print( " error '" + strerror + "'" )
            sys.exit( -2 )

        try : 
            evoutils.DEBUG_FD = open( CLIENT_OR_SERVER + '_debug.log', 'w' )

        except IOError as the_error :
            errno, strerror = the_error.args
            print( " error '" + strerror + "'" )
            sys.exit( -2 )

        evoutils.DEBUG_FD.write( str( evoutils.DEBUG_FD ) + " " + str( LOG_FD ))
        evoutils.DEBUG_FD.flush()
        LOG_FD.write(   str( evoutils.DEBUG_FD ) + " " + str( LOG_FD ) )

        LOG_FD.write( "thread count = " + str( threading.activeCount()) + '\n' )
    
        SENT_STRINGS = []
        RCVD_STRINGS = []
    
        while True :
            if not TCP_THREAD.queue_to_main.empty() :
                CYPHER_TEXT = TCP_THREAD.queue_to_main.get()
                PLAIN_TEXT  = TCP_THREAD.recv_crypto.decrypt( CYPHER_TEXT, 1 )
                LOG_FD.flush()
    
                #
                # truncate the input list and append the new string.
                #
                if len( RCVD_STRINGS ) > 5 :
                    del RCVD_STRINGS[ 0 ]

                RCVD_STRINGS.append( PLAIN_TEXT )
                display_msgs( SCREEN, SENT_STRINGS, RCVD_STRINGS )

            INPUT_READY, OUTPUT_READY, EXCEPT_READY = \
                                    select.select( [sys.stdin], [], [], 1 )
            if INPUT_READY :
                PLAIN_TEXT  = collect_text( SCREEN, SENT_STRINGS,
                                                    RCVD_STRINGS, True )
                if PLAIN_TEXT in [ 'QUIT', 'Quit', 'quit',
                                   'EXIT', 'Exit', 'exit' ] :
                    LOG_FD.write(  "Quitting = '" + str( PLAIN_TEXT ) + '\n' )
                    print ("Quitting" )
                    TCP_THREAD.event.set()

                    # Set everything back to normal
                    STDSCR.keypad(0)
                    curses.echo()
                    curses.nocbreak()
                    curses.endwin()
                    traceback.print_exc()           # print(the exception

                    sys.exit( 0 )

                CYPHER_TEXT = TCP_THREAD.send_crypto.encrypt( PLAIN_TEXT, 1 )
                TCP_THREAD.queue_from_main.put( CYPHER_TEXT )
            else :
                TCP_THREAD.event.wait( 1 )


    if 'threads' in TEST_LIST :
        MAX_PDU = 1500
        SERVER_THREAD = TCPThread( PASSPHRASE, MAX_PDU, 'server',
                                   SERVER_IP_ADDR, SYSTEM_TYPE )
        CLIENT_THREAD = TCPThread( PASSPHRASE, MAX_PDU, 'client',
                                   SERVER_IP_ADDR, SYSTEM_TYPE )

