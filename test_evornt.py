#!/usr/bin/python3
"""
unit tests of evornt
"""

import sys
import unittest

def count_duplicates( the_list ) :
    """
    A weak check for randomness, are any values the same?
    16M comparisons for the dumb way on a 4K grid, K**2
    same number of ops as to sort, cheaper operations
    """
    duplicate_tally = 0
    for i in range( len( the_list ) - 1 ) :
        this_random = the_list[ i ]
        for j in range( i + 1, len( the_list ) ) :
            if( this_random == the_list[ j ] ) :
                print( "duplicate = ", this_random, "i = ", i, "j = ", j
)
                duplicate_tally += 1

    return duplicate_tally


class TestEvoRNT( unittest.TestCase ) :
    """
    Unit test cases for evornt
    """

    def setUp( self ) :

        # instantiate a random number table
        # hard code desired RNT bytes and paranoia level for now
        # a random password so the runs are different.
        random.seed()
        password += 'TestEvoRNT'  + hex( random.getrandbits( 128 ) )
        self.the_rnt = RNT( 4096, password, 'desktop', 2 )

    def test_new_rnt( self ) :
        """
        test of the RNT method 'new_rnt()'
        """
        print( "\ntest_new_rnt\n" )

        original_table = copy.deepcopy( self.the_rnt.rnt )

        duplicates = count_duplicates( original_table ) 
        self.assertTrue( duplicates == 0, "original_table duplicates = " 
                          + str( duplicates ) )

        new_table = self.the_rnt.new_rnt( 999999883, 4096 )

        for i in range( int( 4096 / 16 ) ) :
            self.assertFalse( original_table[ i ] == new_table[ i ] )

        duplicates = count_duplicates( new_table ) 
        self.assertTrue( duplicates == 0, "new_table duplicates = "
                          + str( duplicates ) )

    def test_bit_string_from_randoms_0( self ) :
        """
        Unit test of 'bit_string_from_random_0'
        """
        print( "\ntest_bit_string_from_randoms_0\n" )
        n_long_integers = int( 4096 / 16 )

        # check whether the bitstring returns the integer on 64-bit
        # boundaries.
        for i in range( n_long_integers ) :
            bit_index = i * 64 
            bit_string = self.the_rnt.bit_string_from_randoms( bit_index, 64 )
            the_integer = self.the_rnt.rnt[ i ]
            self.assertTrue( bit_string == the_integer )

        # check whether the bitstring returns the integer on 1-bit boundaries.
        for i in range( n_long_integers ) :     # for each integer in the list
            the_integer = self.the_rnt.rnt[ i ] # get the integer at that bit
                                                # address in the 4096 bytes of
                                                # contiguous data
            for j in range( 64 ) :      # 64 bits per integer
                the_mask = 1 << j
                # i * 64 is a bit index.  63 - j begins with the lsb
                bit_index = i * 64 + 63 - j     # i*64 = word, 63-j = bit
                                                # beginning with least
                                                # significant bit
                # get a one-bit string as an integer, so 0x00 or 0x01
                bit_string = self.the_rnt.bit_string_from_randoms( bit_index, 1)
                
                # it comes back as the least significant bits so no need
                # for this
#                int_string = ( the_integer & the_mask) >> j

                self.assertTrue( the_integer & the_mask == bit_string << j,
                                 "j = " + str( j ) 
                                 + " bit_string = " + hex( bit_string )
                                 + " the_integer = " + hex( the_integer ) )

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
        """
        Unit test of 'bit_string_from_random_1'
        """
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

#            the_integer = ( first_integer << 96 ) + ( secnd_integer << 32 ) + \
#                          third_integer

            bitstring_3 = bit_string & 0xffffffff
            self.assertFalse( bitstring_3 == third_integer )
            self.assertTrue( bit_string >> 96 == first_integer )
            self.assertTrue( bit_string >> 32 & (( 1 << 64 ) - 1 ) ==
                             secnd_integer )

    def test_randint( self ) :
        """
        Unit test of randint()
        """
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
        item_count = 1024*1024

        expected_mean = 1 << 63 # ( 1 << 64 ) / 2
        allowed_error = int( expected_mean * .005 )
        allowed_max  = expected_mean + allowed_error
        allowed_min  = expected_mean - allowed_error

        sum_of_randoms = 0
        for i in range( item_count ) :
            the_random      = self.the_rnt.randint( 64 )
            sum_of_randoms += the_random

        actual_mean = int( sum_of_randoms / item_count )

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

        # statistical, will fail often for small lists
        self.assertTrue( scrambled_list != initial_list )
        for i in range( len( initial_list ) ) : # enumerate has no advantages
                                                # contrary to pylint
            self.assertTrue( initial_list[ i ] in scrambled_list,
            ( "This value is not in the scrambled list", initial_list[ i ] ) )

    def test_password_hash( self ) :
        """
        unit test of password_hash
        """
        print( "test_password_hash" )

        the_rnt = RNT( 4096, 'this is a passphrase', 'desktop', 2 )
        self.assertTrue( the_rnt.password_hash != 0, "password has was zero" )

if __name__ == '__main__':
#    sys.path.append( '../' )
    sys.path.insert( 0, '/home/lew/EvoCrypt' )

    import copy
    from evornt   import RNT

    unittest.main()
