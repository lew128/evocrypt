#!/usr/bin/python3

"""
evoutils.py

Utility functions used by evo modules.

Current limitations of the code :

"""
__version__   = "0.1"
__revision__  = "$Id$"
__date__      = "2017-04-08"
__author__    = "nobody@nowhere.com"
__copyright__ = "None"
__license__   = "None"
__filename__  = "evoutils.py"
__history__   = """
0.1 - 20170408 - started this file.

TODO :
0) 

"""

import sys
import traceback
import getopt

#SINGLE_PROGRAM_FROM_HERE

VERBOSITY_LEVEL = 5
DEBUG_FD = None

def close_files_and_exit( fd_0, fd_1 ) :
    """
    Closes open files and prints the final 'exiting' statement.
    """

    debug( "!!! FAIL !!! close_files_and_exit : exiting",
            traceback.extract_stack(), 1 )

    if fd_0 :
        fd_0.write( "\n\n!!!! encountered an ERROR !!!!\n\n" )
        fd_0.write( "!!! FAIL !!! exiting\n\n" )
        fd_0.close()

    if fd_1 :
        fd_1.write( "\n\n!!!! encountered an ERROR !!!!\n\n" )
        fd_1.write( "!!! FAIL !!! exiting\n\n" )
        fd_1.close()

    if DEBUG_FD :
        DEBUG_FD.close()

    sys.exit( -1 )


def debug( the_debug_message, debug_object, debug_level ) :
    """
    Function debug
    Controls debugging output
        0 : only errors that cause the program to exit
        1 : errors that don't cause exits
        0 and 1 are also printed to stdout
        3 : name of called function
        4 : function's input parameters
        5 : details of internal workings
        6 : more detail

    Convention is that if the level is '1' for the, the info is also
    printed to stdout.
    """

    if debug_level is None :
        debug_level = 1

    if VERBOSITY_LEVEL > debug_level or \
        VERBOSITY_LEVEL == debug_level :
        if debug_object is None :
            if DEBUG_FD :
                DEBUG_FD.write( str( the_debug_message ) + "\n" )
                if debug_level in [ 0, 1, 3 ] :
                    print( the_debug_message )
                    print( str( traceback.extract_stack() ) + "\n" )
                    DEBUG_FD.write( str( traceback.extract_stack())
                                    + "\n" )
            else :
                print( the_debug_message )
        else :
            if DEBUG_FD :
                DEBUG_FD.write( the_debug_message + " : '" + \
                        str( debug_object ) + "'\n" )
                if debug_level in [ 0, 1, 3 ] :
                    print( the_debug_message + " : '" + \
                        str( debug_object ) + "'\n" )
                    print( str( traceback.extract_stack() ) + "\n" )
                    DEBUG_FD.write( str( traceback.extract_stack())
                                    + "\n" )
            else :
                print( "No DEBUG_FD\n" )
                print( "\n" + the_debug_message + " : '" + \
                       str( debug_object ) + "'" )
#                print str( traceback.extract_stack() ) + "\n" )

    else :
        if debug_level in [ 0, 1 ] :
            print( the_debug_message + " : " + str( debug_object ) )
            print( str( traceback.extract_stack() ) + "\n" )


    if DEBUG_FD:
        DEBUG_FD.flush()

    sys.stdout.flush()

    if debug_level == 0 :
        close_files_and_exit( None, None )


def print_stacktrace() :
    """
    Prints the stack trace.
    """
    stack = traceback.extract_stack()

    debug( "stack trace", stack, 0 )
    print( "stack", stack )

def print_stacktrace_exit( message, variable ) :
    """
    Prints the stack trace and exits
    """
    print_stacktrace()
    debug( message, variable, 0 )
    sys.exit( 0 )

#SINGLE_PROGRAM_TO_HERE

def usage() :
    """
    This provides 'help' and other usage information.
    """
    usage_info = """

        --test  <test name>
            adds a test to the list to be executed. can be repeated.
            
            Current tests are:
                'code'  encodes, then decodes plain text
    """
    print( usage_info )



#
# main begins here, generally test code for the module.
#
if __name__ == "__main__" :

    print( '#' + __filename__ )
    print( '#' + __version__ )
    print( '#' + str( sys.argv[ 1 : ] ) )

    # which ones need an '=' ?
    SHORT_ARGS = "ht="
    LONG_ARGS  = [  'help', 'test=' ]

    TEST_LIST = []      # list of tests to execute

    try :
        OPTS, ARGS = getopt.getopt( sys.argv[ 1 : ], SHORT_ARGS,
                                    LONG_ARGS )

    except getopt.GetoptError as err :
        print( "getopt.GetoptError = '" + str( err ) + "'" )
        sys.exit( -2 )

    for o, a in OPTS :
        print( "o = '" + o + "' a = '" + a )
        if o in ( "--help" ) or o in ( "-h" ) :
            usage()
            sys.exit( -2 )

        # note these options are sensitive to order, so new has to come
        # after password

        if o in ( "--test" ) :
            TEST_LIST.append( a )

    print( "Test list = ", TEST_LIST )

    if 'code' in TEST_LIST :
        print( "code test " )



