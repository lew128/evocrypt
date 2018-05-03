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
import multiprocessing as mp

#


def construct_dieharder_command( dtest_list, the_group, the_test ) :
    """
    Constructs the diehardervocrypt component of the total command
    dieharder -d x -d y -d z -g 200 -p <p_samples> -t <t_samples> >
    <group>_<test>.stdout 2> <group>_<test>.stderr
    """
    the_command = 'dieharder '
    if 'all' in dtest_list : # ignore any other dieharder test numbers
        the_command += '-a -g 200 ' 
    else :
        the_command += '-g 200 ' 
        for the_dtest in dtest_list :
            the_command += ' -d ' + the_dtest

    # Dieharder man page warns against changing these unless you know
    # what you are doing. I don't.
#    the_command += ' -p '     + str( p_samples ) + ' -t ' + str( t_samples )
    the_command += ' >> '     + the_group + '_' + the_test + '.stdout'
    the_command += ' 2> '     + the_group + '_' + the_test + '.stderr;'
    the_command += 'date >> ' + the_group + '_' + the_test + '.stdout' 

    return the_command

def construct_command( the_test ) :
    """
    Constructs the evocrypt component of the total command
    ./<name>.py --password umberalertness --test <the_test>

    The global variables are semi-permissible in a small program.
    """
    the_command = ''
    the_group = test_to_group( EVOCRYPT_GROUPS, the_test )
    stdout_file_name = the_group + '_' + the_test + '.stdout'
    the_command += 'date >> ' + stdout_file_name + ';./' 
    the_command += GROUP_TO_FILE_NAMES[ the_group ] + '.py '
    the_arguments = '--password umberallert --test ' + the_test

    the_arguments += ' 2> ' + GROUP_TO_FILE_NAMES[ the_group ]
    the_arguments += '_' + the_test + '.stderr'
    the_arguments += ' | ' + construct_dieharder_command( DIEHARDER_TEST_LIST,
                                        the_group, the_test )
        

    return the_command + the_arguments, stdout_file_name

def test_to_group( groups, the_test ) :
    """
    Searches the EVOCRYPT_GROUP dictonary for the tests.
    Inefficent, but who cares?
    """

    for the_group in groups :
        if the_test in groups[ the_group ] :
            return the_group # == the base file name
    return None

def execute_command_in_forked_process( the_command_and_arguments, the_queue  ) :
    """
    No comment needed with an excellent name like that!

    Too bad pylint doesn't like it.

    This begins the forked process. Os.System executes the command. This
    does not need the capabilities of subprocess.
    """

    try :
        os.system( the_command_and_arguments )

    except : # catch *all* exceptions
        the_error = sys.exc_info()[ 0 ]
        sys.stderr.write( "os.system() failed", str( the_error ) )
        the_queue.put( the_error )

    sys.stderr.write( "execution is DONE\n\n" + the_command_and_arguments \
                    + '\n\n' )
    the_queue.put( "execution is DONE : " + the_command_and_arguments + '\n\n' )
    time.sleep( 5 )
    sys.exit( 0 )


def monitor_processes( process_and_queue_list ) :
    """
    Checks all the queues, displays information from each.
    Checks all processes, says they closed if they close.

    Knowing the files are dieharder output, we could check for too many
    failures and know to stop the process?

    That would be getting lost in your testing process, however.
    """
    while True :
        for this_tuple in process_and_queue_list :
            the_process = this_tuple[ 0 ]
            the_queue   = this_tuple[ 1 ]
            if not the_queue.empty() :
                the_message = the_queue.get_nowait()

                if 'DONE'  in the_message :
                    sys.stderr.write( 'Found DONE : ' + str( this_tuple) + '\n')
                    the_process.join()
                    
                    # we have an empty slot in the process list
                    return
        time.sleep( 1 )

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

    These commands work :
        ./evodieharder.py --group fold --dieharder 2 2> dieharder.stderr
        ./evodieharder.py --group all  --dieharder 2 2> evodieharder.stderr
    """
    print( usage_info )

MAX_SIMULTANEOUS_TESTS = 4      # number of cores to be used in this test

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

    SHORT_ARGS = "b=d=e=g=hm="
    LONG_ARGS  = [  'evocrypt=', 'dieharder=', 'help' , 'password=', 'test=',
                    'group=', 'max_tests='  ]
    
#    print( '#' + __filename__ )
#    print( '#' + __version__ )
#    print('#' + str( sys.argv[ 1 : ] ) )
    
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
                            'cprng'    : [ 'hash_crypto', 'encode0',
                                           'encode1', 'encode2'],
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
#        print( "o = '" + o + "' a = '" + a )
        if o in ( "--help" ) or o in ( "-h" ) :
            usage()
            sys.exit( -2 )
    
        if o in ( "--dieharder" ) or o in ( '-d' ) :
            DIEHARDER_TEST_LIST.append( a )

        if o in ( "--evocrypt" ) or o in ( "-e" ) :
            EVOCRYPT_TEST_LIST.append( a )

        if o in ( "--group" ) or o in ( '-g' ) :
            if a == 'all' :
                EVOCRYPT_GROUP_LIST = list( EVOCRYPT_GROUPS.keys() )
            elif a in EVOCRYPT_GROUPS :
                EVOCRYPT_GROUP_LIST.append( a )
            else :
                print( "incorrect group", a )
                sys.exit( 0 )
    
            print( "EVOCRYPT_GROUP_LIST = ", EVOCRYPT_GROUP_LIST )

        if o in ( "--max_tests") or o in ( "-m" ) :
            MAX_SIMULTANEOUS_TESTS = int( a )
    
    if EVOCRYPT_GROUP_LIST :
        # Construct the list of tests
        for THIS_GROUP in list( EVOCRYPT_GROUPS.keys() ) :
            for THIS_TEST in EVOCRYPT_GROUPS[ THIS_GROUP ] :
                EVOCRYPT_TEST_LIST.append( THIS_TEST )
    
    # construct the dieharder command
    # command   = 'dieharder'
    # arguments = "-d 1 -g 200 -p 100 -t 100" 

    mp.set_start_method( 'fork' )

    # now apply dieharder to each of the necessary tests
    PROCESS_AND_QUEUES = [ ]    # tuples of process and queue
    CURRENT_N_TESTS    = 0
    for THIS_TEST in EVOCRYPT_TEST_LIST :
        sys.stderr.write('THIS_TEST = ' + THIS_TEST + "'\n")
        THE_COMMAND, STDOUT_FILE_NAME = construct_command( THIS_TEST )

        STDOUT_FILE = open( STDOUT_FILE_NAME, 'w' )
        STDOUT_FILE.write( THE_COMMAND + '\n\n' )
        STDOUT_FILE.close()

        THE_QUEUE = mp.Queue()

#        class multiprocessing.Process( group=None, target=None,
#                                       name=None, args=(), kwargs={}, *,
#                                       daemon=None)

        try :
            THE_PROCESS = mp.Process(
                        target = execute_command_in_forked_process,
                        args = ( THE_COMMAND, THE_QUEUE ) )
        except : # catch *all* exceptions
            e = sys.exc_info()[ 0 ]

        try :
            THE_PROCESS.start()
        except : # catch *all* exceptions
            e = sys.exc_info()[ 0 ]

        PROCESS_AND_QUEUES.append( ( THE_PROCESS, THE_QUEUE ) )

        CURRENT_N_TESTS += 1
        if CURRENT_N_TESTS >= MAX_SIMULTANEOUS_TESTS :
            monitor_processes( PROCESS_AND_QUEUES )

            # Monitor doesn't return until a process has ended
            sys.stderr.write( "Monitor_processes has returned\n" )
            CURRENT_N_TESTS -= 1

    # if there are no more tests, wait for all processes to finish
    while CURRENT_N_TESTS > 0 :
        monitor_processes( PROCESS_AND_QUEUES )
        CURRENT_N_TESTS -= 1

    sys.exit( 0 )
