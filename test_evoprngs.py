#!/usr/bin/python3
"""
Tests of the evoprngs.py code.
"""

import sys
import unittest
import time
import random

from evoprimes import get_next_higher_prime
from evofolds  import FoldInteger
from evornt    import RNT
from evoprngs  import LCG, byte_rate, PRNGs

def count_zeros( the_list ) :
    """
    Zero should not be a returned value.
    """
    zero_tally = 0
    for the_value in enumerate( the_list ) :
        if the_value == 0 :
            zero_tally += 1
    return zero_tally

def count_duplicates( the_list ) :
    """
    A weak check for randomness, are any values the same?
    16M comparisons for the dumb way on a 4K grid, K**2
    same number of ops as to sort, cheaper operations
    """
    duplicate_tally = 0
    for i in range( len( the_list ) - 1 ) :
        this_random = the_list[ i ]
#        print( "i = ", i )
        for j in range( i + 1, len( the_list ) ) :
            if( this_random == the_list[ j ] ) :
                print( "duplicate = ", hex( this_random ) , "i = ", i,
                       "j = ", j )
                duplicate_tally += 1

    return duplicate_tally

class TestEvoPrngs( unittest.TestCase ) :
    """
    Unit test class for evoprngs.py
    """

    def setUp( self ) :
        """
        This is run before every test.
        """
        print( "\nsetup" )
        # instantiate a random number table
        # hard code desired RNT bytes and paranoia level for now
        # a random password so the runs are different.
        random.seed()
        password = 'TestEvoPrngs' + hex( random.getrandbits( 128 ) )
        self.the_rnt = RNT( 4096, password, 'desktop', 2 )

        self.the_fold = FoldInteger()
        # number of randoms, used to control length of  tests
        self.n_count  = 32 * 1024
        sys.stdout.flush()


    unittest.skip("demonstrating skipping")
    def test_lcg_width_rates( self ) :
        """
        Rate at different widths and depth.
        """
        print( "test_lcg_width_rates" )

        n_count = 1024 * 1024
        print( "rate test of n_count = " + str( n_count ) +
               "bytes from the non-crypto prngs" )

        lcg_depth      = 19
        paranoia_level = 1
        lag = 13
        results = []
        for integer_width in ( 64, 128, 256, 512 ) :

            max_integer = ( 1 << integer_width ) - 1
            #( seed, integer_width, n_integers, multiplier, constant, lag )
            big_prime   = get_next_higher_prime( ( max_integer * 4 ) / 5 )
            small_prime = get_next_higher_prime( ( max_integer * 2 ) / 5 )

            the_prng = LCG( self.the_rnt, integer_width, lcg_depth,
                            paranoia_level, big_prime, small_prime, lag )

            the_byte_rate = byte_rate( the_prng, integer_width, n_count )

            results.append( ( integer_width, the_byte_rate ) )

        print( results )
        sys.stdout.flush()

    unittest.skip("demonstrating skipping")
    def test_crypto_rate( self ) :
        """
        A check to be sure the rate hasn't dropped too far from any
        changes.
        """
        print( "\ntest_crypto_rate" )
        n_count = 1024*1024
        print( "rate test of n_count = " + str( n_count ) +
               "bytes from the crypto prngs" )

        multiplier = 0xfb8c542ca3937a15686986766247a4e5
        constant   = 0x15b7be9241d1d412f3ea0c7fb2f40c3e
        lag        = 7
        prng_generator = PRNGs()
        for prng_function in prng_generator.prng_functions :
            print( "This PRNG = ", prng_function )

            # the no-lcd numbers make for longer cycles in one of the
            # PRNGs.  Probably should use 129 bit numbers, just to
            # obsolete a bunch of their hardware 8).
            the_prng = prng_function( self.the_rnt, 128, 19, 1,
                                      multiplier, constant, lag )

            the_byte_rate = byte_rate( the_prng, 128, n_count )

            self.assertTrue( the_byte_rate > 200000 )
            print( "bytes/second = ", the_byte_rate )
        sys.stdout.flush()


#    @unittest.skip("demonstrating skipping")
    def test_lcg( self ) :
        """
        This steps the LCG through all combinations of selected values for
        integer width, number of integers in the LCG, lag and result width.
        This includes non-standard integer widths, important in reducing
        the ability of ASICs to speed up cracking these codes.

        It only records the worst time, a floor to the rate of new
        random numbers for this lowest-level unit in the crypto stack.
        """
        print( "\ntest_LCG" )
        # LCG( rnt, integer_width, n_integers, multiplier, constant, lag )

        results        = []
        paranoia_level = 1
        for lcg_width in range( 31, 261, 16 ) :

            for lcg_depth in [ 7, 11, 17, 23, 31 ] :

                for this_lag in range( 1, lcg_depth + 5, 2 ) :

                    print( "lcg_width = " + str( lcg_width ) +
                          " lcg_depth = " + str( lcg_depth ) + " lag = " +
                          str( this_lag ) )
                    max_int     = ( 1 << lcg_width ) - self.the_rnt.randint(
                                                          int( lcg_width / 5 ) )
                    big_prime   = get_next_higher_prime( ( max_int * 4 ) / 5 )
                    small_prime = get_next_higher_prime( ( max_int * 2 ) / 5 )

                    # the test for != 0 could fail for any width, of course,
                    # this is still probabilistic, but 24 bits is less probable.
                    for result_width in range( 24, 128, 9 ) :

                        time_begin  = int( time.time() )
                   #( rnt, integer_width, n_integers, multiplier, constant,lag)
                        the_lcg = LCG( self.the_rnt, lcg_width, lcg_depth,
                                   paranoia_level, big_prime, small_prime,
                                   this_lag )

                        prns = []
                        for _ in range( self.n_count ) :
                            the_random_value = the_lcg.next( result_width, 1 )
#                            print( hex( the_random_value ) )
                            self.assertTrue( the_random_value != 0 and
                                the_random_value  < 1 << result_width,
                                ( 'test_LCG', the_random_value,
                                  result_width, lcg_width, lcg_depth,
                                  paranoia_level, big_prime, small_prime,
                                  this_lag ) )

                            prns.append( the_random_value )
                        time_end = int( time.time() )
                        elapsed_time = time_end - time_begin
                        results.append( ( lcg_width, lcg_depth, this_lag,
                                         result_width, elapsed_time ) )

                        dups  = count_duplicates( prns )
                        zeros = count_zeros( prns )
                        self.assertTrue( dups == 0 and zeros == 0,
                                         ( dups, zeros, result_width, lcg_width,
                                           lcg_depth, paranoia_level, big_prime,
                                           small_prime, this_lag ) )
                        print( dups, lcg_width, lcg_depth, this_lag,
                               result_width, elapsed_time )
                        sys.stdout.flush()
        print( results )

    unittest.skip("demonstrating skipping")
    def test_prngs( self ) :
        """
        Basic check to be sure that all the functions work.
        """
        print( "\ntest_PRNGs" )

        return_value = True
        prngs = PRNGs()
        for integer_width in [ 64, 128, 256 ] :
            for vec_depth in [ 7, 29, 31, 43 ] :
                for paranoia_level in [ 1, 2, 3 ] :
                    for _ in range( 20 ) :
                        max_integer = ( 1 << integer_width ) - \
                                        random.getrandbits( 36 )
                        big_prime = get_next_higher_prime(
                                                int( ( max_integer * 4 ) / 5 ) )
                        small_prime = get_next_higher_prime( 
                                                int( ( max_integer * 1 ) / 5 ) )
                        lag = int( vec_depth / 2 )
                        # check the first 10 prns returned
                        the_prng = ( prngs.next( self.the_rnt, integer_width,
                               vec_depth, paranoia_level, big_prime,
                               small_prime, lag ))
                        print( the_prng )

                        prns = []
                        for _ in range( 10 ) :
                            prns.append( the_prng.next( 128, paranoia_level ) )

                        zeros = count_zeros( prns )
                        dups  = count_duplicates( prns )
                        if dups != 0 and zeros == 0 :
                            return_value &= dups

#                        print( return_value )
                    sys.stdout.flush()

        self.assertTrue( return_value )

if __name__ == '__main__':
#    sys.path.append( '../' )
    sys.path.insert( 0, '/home/lew/EvoCrypt' )

    unittest.main()
