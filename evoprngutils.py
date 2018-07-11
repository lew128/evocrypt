#!/usr/bin/python3

"""
evoprngutils.py

Utility functions used by evo prng modules.

Current limitations of the code :

"""
__version__   = "0.1"
__revision__  = "$Id$"
__date__      = "2018-07-08"
__author__    = "nobody@nowhere.com"
__copyright__ = "None"
__license__   = "None"
__filename__  = "evoprngutils.py"
__history__   = """
0.1 - 20180708 - started this file.

ODO :
0) 

"""

import sys
import getopt
import evoprimes 
from   evofolds  import FoldInteger
from   evohashes import HASHES

#SINGLE_PROGRAM_FROM_HERE

def generate_constants( the_rnt, integer_width, n_prngs ) :
    """
    computes big_prime, the multiplier, small_prime, the addition, and
    the lag
    """
    the_fold            = FoldInteger( )
    # hash_depth should be differently different than vector_depth
    # good enough for now.
    hashes = HASHES( the_rnt, integer_width, 31 )
    the_hash = hashes.next()

    the_hash.update( str( n_prngs ) + str( integer_width ) + 
                     hex( the_rnt.password_hash ) )
    hash_of_state = the_hash.intdigest()

    # small enough it doesn't mis-order the numbers, large enough
    # it won't be close to the calculated value
    folded_hash_of_state = \
            the_fold.fold_it( hash_of_state, integer_width )

    # multipliers and additive constants :
    # need 2 series of primes a good distance apart, say the low
    # range beginning from low at 10% to high at 40 and high range
    # beginning 60% to 90% We need N of each.
    # This is predictable from standard integer widths, so we also
    # need the entropy mixed into this.
    # return multiplier, constant, lag, increment

    entropy_bits = folded_hash_of_state ^ the_rnt.password_hash

    max_integer = 1 << integer_width

    while entropy_bits < max_integer :
        entropy_bits *= evoprimes.get_next_higher_prime( entropy_bits )

    # we need entropy bits to more bits than 3 * n_prngs
    entropy_bits *= evoprimes.get_next_higher_prime( entropy_bits )

    the_multiplier   = entropy_bits % int( max_integer * .9 )

    the_addition     = entropy_bits % int( max_integer * .1 )
    the_lag          = 1


    # 1/Nth of 30% of the total range >> 4
    the_increment    = int( ( the_multiplier * .3 ) / n_prngs )

    for _ in range( n_prngs ) :
        the_multiplier   = evoprimes.get_next_higher_prime( the_multiplier )
        the_addition     = evoprimes.get_next_higher_prime( the_addition )
        the_increment    = evoprimes.get_next_higher_prime( the_increment )
        # another bit of complexity for code breakers
        entropy_bits     = evoprimes.get_next_higher_prime( entropy_bits +
                                                      the_increment >> 4 )

        yield the_multiplier, the_addition, the_lag, the_increment

       # this weaves the password hash into every constant
        the_increment  -= entropy_bits & 0xFFF
        the_multiplier -= the_increment
        the_addition   += the_increment
        the_lag        += 2

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



