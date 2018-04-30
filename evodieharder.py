#!/home/lew/Downloads/Python-3.6.5/python
# -*- coding : UTF8 -*-

"""
evodieharder.py

This controls dieharder to manage long-running tests.  

It is part of a final acceptance test.

This design runs evocrypt and dieharder as subprocesses.

"""
__version__   = "0.1"
__revision__  = "$Id$"
__date__      = "2018-04-27"
__author__    = "nobody@nowhere.com"
__copyright__ = "None"
__license__   = "None"
__filename__  = "evodieharder.py"
__history__   = """
0.1 - 20180427 - started this file
"""

import os
import sys
import getopt
import time
import random 
import threading
import io
import multiprocessing as mp
import subprocess


from array      import array

#


def execute_processes( evocommand, diecommand, base_file_name ) :
    """
    This begins the processes and threads necessary to execute an
    evocrypt test and pipe stdout into the dieharder command. The intent
    is to emulate a command such as :

    ./evofolds.py --password umberalertness --test xadd0 2>
        evo_folds_xadd0.stderr | dieharder -a -g 200 -p 200 -t 200 >
        die_folds_xadd0.stdout 2> die_folds_xadd0.stderr
    """
    pass
    


def construct_dieharder_command( dtest_list, p_samples, t_samples, the_group,
                                 the_test ) :
    """
    Constructs the diehardervocrypt component of the total command
    dieharder -d x -d y -d z -g 200 -p <p_samples> -t <t_samples> >
    <group>_<test>.stdout 2> <group>_<test>.stderr
    """
    the_command = 'dieharder '
    for the_dtest in dtest_list :
        the_command += ' -d ' + the_dtest

    the_command += ' -p '     + str( p_samples ) + ' -t ' + str( t_samples )
    the_command += ' >> '     + the_group + '_' + the_test + '.stdout'
    the_command += ' 2> '     + the_group + '_' + the_test + '.stderr;'
    the_command += 'date >> ' + the_group + '_' + the_test + '.stdout' 

    return the_command

def construct_command( the_test ) :
    """
    Constructs the evocrypt component of the total command
    ./<name>.py --password umberalertness --test <the_test>
    """
    the_command = ''
    the_group = test_to_group( EVOCRYPT_GROUPS, the_test )
    the_command += 'date > ' + the_group + '_' + the_test + '.stdout;./' 
    the_command += GROUP_TO_FILE_NAMES[ the_group ] + '.py '
    the_arguments = '--password umberallert --test ' + the_test

    the_arguments += ' | ' + construct_dieharder_command( DIEHARDER_TEST_LIST,
                                        DIEHARDER_PSAMPLES, DIEHARDER_TSAMPLES,
                                        the_group, the_test )
        
    return the_command + the_arguments

def test_to_group( groups, the_test ) :
    """
    Searches the EVOCRYPT_GROUP dictonary for the tests.
    Inefficent, but who cares?
    """

    print( "ttg test : '" + the_test + "'" )
    for the_group in groups :
        print( "ttgroup[ the_test ] = ", groups[ the_group ] )
        if the_test in groups[ the_group ] :
            print( "ttgroup[ the_test ] = ", the_test )
            return the_group # == the base file name
    return None

def execute_command_in_forked_process( the_command_and_arguments, the_queue ) :
    """
    No comment needed with an excellent name like that!
    """
    print( "execute_command_in_forked_process : '" + 
            the_command_and_arguments + "'" )

    #    subprocess.run( args, *, stdin=None, input=None, stdout=None,
    #    stderr=None, shell=False, cwd=None, timeout=None, check=False,
    #    encoding=None, errors=None)

    os.system( the_command_and_arguments )

    the_queue.put( "DONE : ", the_command_and_arguments )
    while( True ) :
        time.sleep( 5 )


def monitor_processes( process_and_queue_list ) :
    """
    Checks all the queues, displays information from each.
    Checks all processes, says they closed if they close.

    Knowing the files are dieharder output, we could check for too many
    failures and know to stop the process?

    That would be getting lost in your testing process, however.
    """
    for this_tuple in process_and_queue_list :
        print( this_tuple[ 1 ].get())
        this_tuple[ 0 ].join()
    pass

def usage() :
    """
    This provides 'help' and other usage information.
    """
    usage_info = """
    --dieharder  
    -d      Dieharder test numbers put on the list.
            Defaults to 'all'

    --evocrypt  
    -e      Evocrypt individual test names put on the list.
            This allows control of individual test within a module.

    --group Group of evocrypt tests, e.g. 'hash', 'fold', ...
    --g     Those are put on a list, allowing tests of individual modules.

            If you specify groups, those tests are added before
                ndividual tests.
            If you specify 'all', additional tests will be executed
            twice.

    --help  Invokes this usage function
    -h      Invokes this usage function

    --psamples Number of P samples to be used by dieharder
    -p      Defaults to 200

    --tsamples Number of T samples to be used by dieharder
    -t      Defaults to 200

    """
    print( usage_info )

# These should be imported from the modules.
EVOCRYPT_TESTS = []
HASH_TESTS     = [ 'hash0', 'hash1' ]
FOLD_TESTS     = []
PRIME_TESTS    = []
RNT_TESTS      = []
PRNG_TESTS     = []
CPRNG_TESTS    = []

# main begins here, generally test code for the module.

if __name__ == "__main__" :

    SHORT_ARGS = "d=e=g=hp=t="
    LONG_ARGS  = [  'evocrypt=', 'dieharder=', 'help' , 'password=', 'test=',
                    'group=', 'psamples=', 'tsamples=' ]
    
    print( '#' + __filename__ )
    print( '#' + __version__ )
    print('#' + str( sys.argv[ 1 : ] ) )
    
    DIEHARDER_PSAMPLES = '200'
    DIEHARDER_TSAMPLES = '200'
    DIEHARDER_TEST_LIST = [] 
    EVOCRYPT_GROUP_LIST = []
    EVOCRYPT_TEST_LIST  = []
    GROUP_TO_FILE_NAMES = { 'fold'     : 'evofolds' ,
                            'hash'     : 'evohashes',
                            'rtn'      : 'evornt'   ,
                            'prime'    : 'evoprimes',
                            'prng'     : 'evoprngs' ,
                            'cprng'    : 'evocprngs',
                            'utils'    : 'evoutils' ,
                            'evocrypt' : 'evocrypt' ,
                           }
    EVOCRYPT_GROUPS     = { 
                            'fold'     : [ 'xor0', 'xor1', 'xadd0', 'xadd1' ],
                            'hash'     : [ 'hash0', 'hash1' ],
                            'rtn'      : [ 'wichman', 'randint', 'randint1',
                                           'randint2', 'next_random_value' ],
                            'prime'    : [],
                            'prng'     : [ 'lcg', 'well512', 'newlib', 'knuth',
                                           'lp5', 'lp256', 'cmwc4096', 'lfsr' ],
                            'cprng'    : [ 'hash_crypto', 'encode0', 'encode1'],
                            'utils'    : [],
                            'evocrypt' : [],
                           }

    # User can specify 'all' for both tests and groups
    # in which case, construct the lists below
    # [ 'evoutils', 'evoprimes', 'evofolds', 'evohashes',
    #   'evornt',   'evoprngs',  'evocprngs', 'evocrypt' ],

    try :
        OPTS, ARGS = getopt.getopt( sys.argv[ 1 : ], SHORT_ARGS, LONG_ARGS )
    
    except getopt.GetoptError as err :
        print( "getopt.GetoptError = ", err )
        sys.exit( -2 )
    
    for o, a in OPTS :
        print( "o = '" + o + "' a = '" + a )
        if o in ( "--help" ) or o in ( "-h" ) :
            usage()
            sys.exit( -2 )
    
        if o in ( "--dieharder" ) or o in ( '-d' ) :
            DIEHARDER_TEST_LIST.append( str( a ) )

        if o in ( "--evocrypt" ) or o in ( '-e' ) :
            EVOCRYPT_TEST_LIST.append( a )

        if o in ( "--group" ) or o in ( '-g' ) :
            if a == 'all' :
                EVOCRYPT_GROUP_LIST = list( EVOCRYPT_GROUPS.keys() )
            elif a in EVOCRYPT_GROUPS :
                EVOCRYPT_GROUP_LIST.append( str( a ) )
            else :
                print( "incorrect group", a )
    
        if o in ( "--psamples") or o in ( "-p" ) :
            DIEHARDER_PSAMPLES = str( a )
    
        if o in ( "--tsamples" ) or o in ( '-t' ) :
            DIEHARDER_TSAMPLES = str( a )
    
    if EVOCRYPT_GROUP_LIST :
        # Construct the list of tests
        for THIS_GROUP in list( EVOCRYPT_GROUPS.keys() ) :
            print( "THIS_GROUP = ", THIS_GROUP )
            for THIS_TEST in EVOCRYPT_GROUPS[ THIS_GROUP ] :
                print( "THIS_TEST = ", THIS_TEST )
                EVOCRYPT_TEST_LIST.append( THIS_TEST )
    
    # construct the dieharder command
    # command   = 'dieharder'
    # arguments = "-d 1 -g 200 -p 100 -t 100" 

    mp.set_start_method( 'fork' )
    print( 'After set_start_method( fork )' )

    # now apply dieharder to each of the necessary tests
    process_and_queues = [ ]    # tuples of process and queue
    print( EVOCRYPT_TEST_LIST )
    for THIS_TEST in EVOCRYPT_TEST_LIST :
        print( THIS_TEST )
        THE_COMMAND = construct_command( THIS_TEST )
        print( "the_command = '" + THE_COMMAND + "'" )

        THE_QUEUE = mp.Queue()

#        class multiprocessing.Process( group=None, target=None,
#                                       name=None, args=(), kwargs={}, *,
#                                       daemon=None)

        THE_PROCESS = mp.Process( target = execute_command_in_forked_process,
                        args = ( THE_COMMAND, THE_QUEUE ) )
        THE_PROCESS.start()
        process_and_queues.append( ( THE_PROCESS, THE_QUEUE ) )
        time.sleep( 10 )
        sys.exit( 0 )
