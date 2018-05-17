#!/usr/bin/python3
"""
Tests of the evoprngs.py code.
"""

import sys
import unittest
import time
import copy


class TestEvoPrngs( unittest.TestCase ) :

    def setUp( self ) :
        """
        This is run before every test.
        """
        print( "\nsetup" )
        # instantiate a random number table
        # hard code desired RNT bytes and paranoia level for now
        self.the_rnt = RNT( 4096, 2, 'desktop', 'TestEvoFolds' )

        self.the_fold = FoldInteger()
        self.N        = 32 * 1024 


    @unittest.skip("demonstrating skipping")
    def test_lcg_width_rates( self ) :
        """
        Rate at different widths and depth.
        """
        N = 1024 * 1024
        print( "rate test of N = " + str( N ) +
               "bytes from the non-crypto prngs" )

        lcg_depth     = 32
        results = []
        for integer_width in ( 32, 64, 128, 256 ) :

            max_integer = ( 1 << INTEGER_WIDTH ) - 1
            #( seed, integer_width, n_integers, multiplier, constant, lag )
            big_prime   = get_next_higher_prime( ( max_integer * 4 ) / 5 )
            small_prime = get_next_higher_prime( ( max_integer * 2 ) / 5 )

            the_prng = LCG( "i0XE5013_13#A@A2$A3A(C*4&9^F$F!920",
                            integer_width, lcg_depth, big_prime, small_prime,
                            19 )

            the_byte_rate = byte_rate( the_prng, integer_width, N )

            results.append( integer_width, the_byte_rate )

        print( results )

    @unittest.skip("demonstrating skipping")
    def test_crypto_rate( self ) :
        """
        A check to be sure the rate hasn't dropped too far from any
        changes.
        """
        print( "\ntest_crypto_rate" )
        N = 1024*1024
        print( "rate test of N = " + str( N ) +
               "bytes from the crypto prngs" )
        for prng_function in CRYPTO_PRNG_FUNCTIONS :
            print( "This PRNG = ", prng_function )

            # the no-lcd numbers make for longer cycles in one of the
            # PRNGs.  Probably should use 129 bit numbers, just to
            # obsolete a bunch of their hardware 8).
            the_prng = prng_function( self.the_rnt, 19, 128, 32 )

            the_byte_rate = byte_rate( the_prng, 128, N )

            self.assertTrue( the_byte_rate > 200000 )
            print( "bytes/second = ", the_byte_rate )


    @unittest.skip("demonstrating skipping")
    def test_twister0( self ) :
        """
        A check for the twister returning the proper width value.
        """
        print( "\ntest_twister0" )
                     # ( rnt, result_width )
        the_twist = MersenneTwister( self.the_rnt, 64 )

        for result_width in [ 8, 16, 24, 32, 40, 48, 56, 64, 72, 80, 88,
                          96, 104, 112, 120, 128 ] :
            for i in range( 3 ) :
                the_random_value = the_twist.next( result_width, 1 )
                # test of != 0 is statistical, can fail, not often.
                # change the password if it happens, try again.
                self.assertTrue( the_random_value != 0 and
                                 the_random_value  < 1 << result_width,
                ( 'test_twister0', the_random_value, result_width ) )

    @unittest.skip("demonstrating skipping")
    def test_crypto( self ) :
        """
        Exercises encrypt() and decrypt() with the full range of paranoia
        levels.

        Currently fails for Twister, will take it out of the list until
        I fix that bug.
        """
        print( "\ntest_crypto" )
        for system_type in [ 'big', 'desktop', 'laptop', 'cellphone' ] :

            for paranoia_level in [ 1, 2, 3 ] :

                encrypt_crypto = CRYPTO( 'this is a phrase',
                                         system_type, paranoia_level )


                decrypt_crypto = CRYPTO( 'this is a phrase', 
                                         system_type, paranoia_level )

                # repeat to be sure there are no problems in transitions
                # from one message to another.
                plain_in = "this is a test case"
                i = 0
                while i < 4 :
                    encode = encrypt_crypto.next()
                    decode = decrypt_crypto.next()

                    # to make this work, we need to have encode and decode PRNGs
                    # processing the same number of characters.  dropping a
                    # character in transmission causes loss of the ability to
                    # stream.
                    cipher_text = encode.encrypt( plain_in, 1 )
                    plain_out   = decode.decrypt( cipher_text, 1 )

                    self.assertTrue( plain_in == plain_out,
                        ( 'test_crypto', encode, decode, plain_in, plain_out ) )

                    i += 1

    def test_LCG( self ) :
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

        results = []
        for lcg_width in range( 31, 261, 16 ) :

            for lcg_depth in [ 7, 11, 17, 23, 31 ] :

                for this_lag in range( 1, lcg_depth + 3, 3 ) :

                    max_int     = ( 1 << lcg_width ) - 1
                    big_prime   = get_next_higher_prime( ( max_int * 4 ) / 5 )
                    small_prime = get_next_higher_prime( ( max_int * 2 ) / 5 )

                    # the test for != 0 could fail for any width, of course,
                    # this is still probabilistic, but 24 bits is less probable.
                    for result_width in range( 24, 128, 9 ) :

                        time_begin  = int( time.time() )
                    #( rnt, integer_width, n_integers, multiplier, constant,lag)
                        the_lcg = LCG( self.the_rnt, lcg_width, lcg_depth,
                                    big_prime, small_prime, this_lag)

                        for i in range( self.N ) :
                            the_random_value = the_lcg.next( result_width, 1 )
#                            print( hex( the_random_value ) )
                            self.assertTrue( the_random_value != 0 and
                                 the_random_value  < 1 << result_width,
                           ( 'test_LCG', the_random_value, result_width ) )

                        time_end = int( time.time() )
                        elapsed_time = time_end - time_begin
                        results.append( ( lcg_width, lcg_depth, this_lag,
                                            result_width ) )

        print( results )

    def test_PRNGs( self )
    """
    Checks to be sure that all 8 of the functions are called.
    """
        print( "\ntest_PRNGs" )

        prngs = PRNGS()
        for integer_width in [ 64, 128, 256 ] :
            for vec_depth in [ 7, 29, 31, 43 ] :
                for paranoia_level in [ 1, 2, 3 ] :

                    for _ in range( 20 ) :
                        max_integer = ( 1 << integer_width ) - \
                                        random.getrandbits( 36 )
                        big_prime = get_next_higher_prime(
                                                int( ( max_integer * 4 ) / 5 )
                        small_prime = get_next_higher_prime( 
                                                int( ( max_integer * 1 ) / 5 )
                        lag = int( vec_depth / 2 )
                        print( prngs.next( self.the_rnt, bit_width,
                               integer_vector_depth, paranoia_level,
                               multiplier, constant, lag ))

if __name__ == '__main__':
#    sys.path.append( '../' )
    sys.path.insert( 0, '/home/lew/EvoCrypt' )
    from evoprimes import get_next_higher_prime
    from evofolds import FoldInteger
    from evornt   import RNT
    from evoprngs import LCG, byte_rate, PRNGs

    unittest.main()
