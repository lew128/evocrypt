#!/usr/bin/python3

import sys
import unittest


class TestEvoRNT( unittest.TestCase ) :

    def setUp( self ) :

        # instantiate a random number table
        # hard code desired RNT bytes and paranoia level for now
        self.the_rnt = RNT( 4096, 1, 'desktop', 'TestEvoFolds' )


    def test_new_rnt( self ) :
        original_table = copy.deepcopy( self.the_rnt.rnt )

        new_table = self.the_rnt.new_rnt( 999999883, 4096 )

        for i in range( int( 4096 / 16 ) ) :
            self.assertFalse( original_table[ i ] == new_table[ i ] )

    def test_bit_string_from_randoms_0( self ) :
        print( "test_bit_string_from_randoms_0" )
        n_long_integers = int( 4096 / 16 )

        # check whether the bitstring returns the integer on 64-bit
        # boundaries.
        for i in range( n_long_integers ) :
            bit_index = i * 64 
            bit_string = self.the_rnt.bit_string_from_randoms( bit_index, 64 )
            the_integer = self.the_rnt.rnt[ i ]
            self.assertTrue( bit_string == the_integer )

        # check whether the bitstring returns the integer on 1-bit boundaries.
        for i in range( n_long_integers ) :
            the_integer = self.the_rnt.rnt[ i ]
            for j in range( 64 ) :
                the_mask = 1 << j
                # i * 64 is a bit index.  63 - j begins with the lsb
                bit_index = i * 64 + 63 - j
                bit_string = self.the_rnt.bit_string_from_randoms( bit_index, 1)
                int_string = ( the_integer & the_mask) >> j
                self.assertTrue( bit_string == ( the_integer & the_mask) >> j )

        # check whether the bitstring returns 64-bit integer on 32-bit
        # index. This shows cross_integer access
        for i in range( n_long_integers ) :
            bit_index = i * 64 + 32
            bit_string = self.the_rnt.bit_string_from_randoms( bit_index, 64 )

            # this is for little endian machines, I should fix that.
            # most significant half of ith word + least sig half of i+1th word
            first_integer = self.the_rnt.rnt[ i ]
            first_integer = ( first_integer & 0xffffffff ) << 32
            secnd_integer = self.the_rnt.rnt[ i + 1 ] 
            secnd_integer = ( secnd_integer & 0xFFFFFFFF00000000 ) >> 32

            the_integer = first_integer + secnd_integer

            self.assertTrue( bit_string == the_integer )

    def test_bit_string_from_randoms_1( self ) :
        print( "test_bit_string_from_randoms_1" )
        n_long_integers = int( 4096 / 16 )

        # check whether the bitstring returns 128-bit integer on 32-bit
        # boundaries. This shows cross_integer access for 2 64-bit words
        for i in range( n_long_integers ) :
            bit_index = i * 64 + 32
            bit_string = self.the_rnt.bit_string_from_randoms( bit_index, 128 )

            # this is for little endian machines, I should fix that.
            # most significant half of ith word + least sig half of i+1th word
            first_integer = self.the_rnt.rnt[ i ]
            secnd_integer = self.the_rnt.rnt[ i + 1 ] 
            third_integer = self.the_rnt.rnt[ i + 2 ]
            
            first_integer =   first_integer & 0xffffffff
            third_integer = ( third_integer & 0xFFFFFFFF00000000 ) >> 32

            the_integer = ( first_integer << 96 ) + ( secnd_integer << 32 ) + \
                          third_integer

            bitstring_3 = bit_string & 0xffffffff
            self.assertFalse( bitstring_3 == third_integer )
            self.assertTrue( bit_string >> 96 == first_integer )
            self.assertTrue( bit_string >> 32 & (( 1 << 64 ) - 1 ) ==
                             secnd_integer )

    def test_randint( self ) :
        print( "test_randint" )
        # the correct test is dieharder, it passed on last test
        self.the_rnt.password_hash = 0X41F268A0AFC34ED1EFF8941BF984B71C

        # simple test of whether it returns a value in the rnt
        this_random = self.the_rnt.randint( 64 )
        n_long_integers = int( 4096 / 16 )
        for i in range( n_long_integers ) :
            self.assertFalse( this_random == self.the_rnt.rnt[ i ] )

        # test for whether the mean of the random numbers is centered
        # this is weak, dieharder is definitive, but takes forever.
        N = 1024*1024

        expected_mean = 1 << 63 # ( 1 << 64 ) / 2
        allowed_error = int( expected_mean * .005 )
        allowed_max  = expected_mean + allowed_error
        allowed_min  = expected_mean - allowed_error

        sum_of_randoms = 0
        for i in range( 1024*1024 ) :
            the_random      = self.the_rnt.randint( 64 )
            sum_of_randoms += the_random

        actual_mean = int( sum_of_randoms / N )

#        print( hex( expected_mean ), hex( allowed_error ) )
#        print( hex( sum_of_randoms ), actual_mean )
#        print( hex( actual_mean ), hex( allowed_max ), hex( allowed_min ) )

        self.assertTrue( actual_mean > allowed_min and
                         actual_mean < allowed_max )

    def test_scramble_list( self ) :
        """
        Does scramble work?
        """
        print( "test_scramble_list" )
        initial_list = [ '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a',
                      'b', 'c', 'd', 'e', 'f' ]
        scrambled_list = self.the_rnt.scramble_list( initial_list )

        self.assertTrue( scrambled_list != initial_list )
        for i in range( len( initial_list ) ) :
            self.assertTrue( initial_list[ i ] in scrambled_list,
            ( "This value is not in the scrambled list", initial_list[ i ] ) )

    def test_password_hash( self ) :
        """
        """
        print( "test_password_hash" )

        the_rnt = RNT( 4096, 2, 'this is a passphrase' )
        self.assertTrue( the_rnt.password_hash != 0, "password has was zero" )

if __name__ == '__main__':
#    sys.path.append( '../' )
    sys.path.insert( 0, '/home/lew/EvoCrypt' )

    import copy
    from evornt   import RNT

    unittest.main()
