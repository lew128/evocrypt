#!/usr/bin/python3

"""
This are simple tests which can detect a regression.  They check some
simple cases of one-bit differences in updates.

This is in addition to dieharder, the gold standard.  Dieharder is run
from the commandline for the module.
"""
import sys
import unittest
import copy

def countSetBits( the_integer ) :
    """ destructively counts the set bits in an integer """
    count = 0
    while( the_integer ) :
        count += the_integer & 1
        the_integer >>= 1
    return count
 
    BIT_POSITIONS    = [ 63, 60, 55, 50, 30, 24, 23, 9, 8, 7, 2, 1 ]

def tally_integer_bits( i, j, tally_array, to_be_tallied ) :
    """
    tallies each set bit in the appropriate bin

    Should be general wrt the string length.
    """
    if not j :
        for i in range( 64 ) :
            if ( 1 << i ) & to_be_tallied :
                tally_array[ i ] += 1
    else :
        for i in range( 64 ) :
            for j in range( 64 ) :
                if ( 1 << i ) & to_be_tallied :
                    tally_array[ i ][ j ] += 1

def analyze_and_print_xor_bits( xor_bits, bit_string_length ) :
    """
    Standard stats for the type of data.
    """

    row_tally_sums      =   [ 0 for _ in range( bit_string_length ) ]
    column_tally_sums   =   [ 0 for _ in range( bit_string_length ) ]

    total_tally_bits = 0
    for i in range( 12 ) :
        for j in range( 12 ) :
            row_tally_sums[ i ] += xor_bits[ i ][ j ]
            total_tally_bits += xor_bits[ i ][ j ]

    for i in range( 12 ) :
        for j in range( 12 ) :
            row_tally_sums[ i ] += xor_bits[ i ][ j ]

    # N*N = number of cells, but that count  should be adjusted by the
    # length of the diagonal, which doesn't contribute counts
    # adjustment is the diff in # of cells in a 
    mean_tally_bits = total_tally_bits / ( 12 ** 2 ) - \
                                         ( ( 12 ** 2 ) - ( 11 ** 2 ) )
    print( "\nmean_tally_bits = ", mean_tally_bits )
    for i in range( 12 ) :
        print( i, [ x for x in xor_bits[ i ] ] )

class TestEvoHashes( unittest.TestCase ) :

    def setUp( self ) :
        """ Only need to instantiate the RNT for these tests,
            as the RNT is mixed into the hashes
        """
        # instantiate a random number table
        # hard code desired RNT bytes and paranoia level for now
        self.the_rnt = RNT( 4096, 1, 'desktop', 'this is a passphrase' )

    def test_all( self ) :
        """
        This is a weak test, just confirms that the code does not fault
        and that a few of the the really dumb mistakes are not made.

        The real test is dieharder, but that cannot be run so often, it
        takes days.
        """
        for hash_function in HASH_FUNCTIONS :
            the_hash = hash_function( self.the_rnt, 64, 19 )

            for i in range( 100 ) :

                initial_hash_value = the_hash.intdigest()
                # it can't be zero
                self.assertTrue( initial_hash_value != 0 )
                # must be < 64 bits
                self.assertTrue( initial_hash_value < 1 << 64 )

                the_hash.update( 'more text' + str( i ) )

                updated_hash_value = the_hash.intdigest()
                self.assertTrue( updated_hash_value != 0 )
                self.assertTrue( updated_hash_value < 1 << 64 )

                self.assertTrue( initial_hash_value != updated_hash_value )
        
    def test_bits1( self ) :
        """
        a more comprehehsive test of bit changes and distribution.

        Design will move two bits independently across zeros and two
        zeroes across ones. The two-bit and two-zero cases being one bit
        different in the value used for the update. Then the updates
        must be 50% different, on average.

        11 May 2018. This works, it seems to me, although I had to think
        many minutes about some of these tests and conditions to understand
        why results are the way they are.

        Key piece of thinking is, I think : in each of 2 hashes about
        50% of the bits will be set.  At random, those will have the
        same value 50% of the time. Hash0 and 1 functions produce
        hashes that are about 33% for single bit differences.

        I don't think that is bad for this application, tho maybe makes
        it susceptable to a chosen plaintext break of some kind.

        So something new with HASH2.

        This tests each hash function against single and 2 combinations of
        single bits set at BIT_POSITIONS. Those values check for some
        obvious edge effects. This runs fast, more could be added.
        """

        BIT_POSITIONS = [ 63, 60, 55, 50, 30, 24, 23, 9, 8, 7, 2, 1 ]

        # 2D arrays of counts of changed bits with the change at each
        # location
        a_b_bits_changed  =   [ [ 0 for _ in range( len( BIT_POSITIONS ) ) ]
                                for _ in range( len( BIT_POSITIONS ) ) ]
        b_c_bits_changed  =   [ [ 0 for _ in range( len( BIT_POSITIONS ) ) ]
                                for _ in range( len( BIT_POSITIONS ) ) ]
        a_c_bits_changed  =   [ [ 0 for _ in range( len( BIT_POSITIONS ) ) ]
                                for _ in range( len( BIT_POSITIONS ) ) ]

        # 1D lists of tallies at each bit location in the string
        a_tally_array      =   [ 0 for _ in range( 64 ) ]
        b_tally_array      =   [ 0 for _ in range( 64 ) ]
        c_tally_array      =   [ 0 for _ in range( 64 ) ]
        a_b_tally_array    =   [ 0 for _ in range( 64 ) ]
        b_c_tally_array    =   [ 0 for _ in range( 64 ) ]
        a_c_tally_array    =   [ 0 for _ in range( 64 ) ]

        for hash_function in HASH_FUNCTIONS :
            the_hash = hash_function( self.the_rnt, 64, 19 )
            the_hash.save_int_vector()

            # for each element in the bit-positions list
            for i in range( len( BIT_POSITIONS ) ) :
                a_hash_update = 1 << BIT_POSITIONS[ i ]
                # against each other element in the bit-positions list
                for j in range( len( BIT_POSITIONS ) ) :
                    # i and j are equal on the diagonal
                    b_hash_update = 1 << BIT_POSITIONS[ j ]

                    # this assumes all hash conditions are equivalent
                    # maybe not, but first see if degenerate conditions
                    # then just copy the array before every hash update()

                    the_hash.update( a_hash_update )
                    a_hash_value     = the_hash.intdigest()

                    the_hash.restore_int_vector()
                    the_hash.update( b_hash_update )
                    b_hash_value     = the_hash.intdigest()

                    # avoid the ^ and also make blank diagonal
                    if i == j :
                        the_hash.restore_int_vector()
                        the_hash.update( a_hash_update ^ b_hash_update )
                    c_hash_value     = the_hash.intdigest()

                    xor_a_b_bit_diff = a_hash_value ^ b_hash_value
                    xor_b_c_bit_diff = b_hash_value ^ c_hash_value
                    xor_a_c_bit_diff = a_hash_value ^ c_hash_value

                    # totals of the number of bits changed
                    a_b_bits_changed[ i ][ j ] = countSetBits( xor_a_b_bit_diff)
                    b_c_bits_changed[ i ][ j ] = countSetBits( xor_b_c_bit_diff)
                    a_c_bits_changed[ i ][ j ] = countSetBits( xor_a_c_bit_diff)

                    # collect bit counts in each bit position as a first
                    # measure
                    tally_integer_bits( i, None, b_tally_array, b_hash_value )
                    tally_integer_bits( i, None, a_tally_array, a_hash_value )
                    tally_integer_bits( i, None, c_tally_array, c_hash_value )
                    tally_integer_bits( i, None, a_b_tally_array,
                                        xor_a_b_bit_diff)
                    tally_integer_bits( i, None, b_c_tally_array,
                                        xor_b_c_bit_diff)
                    tally_integer_bits( i, None, a_c_tally_array,
                                        xor_a_c_bit_diff)
                    
            print( "\n\nthe_hash = ", the_hash )
            print( "a_b_bits_changed = ", a_b_bits_changed )
 
            analyze_and_print_xor_bits( a_b_bits_changed, 64 )
            analyze_and_print_xor_bits( b_c_bits_changed, 64 )
            analyze_and_print_xor_bits( a_c_bits_changed, 64 )


    def test_bits2( self ) :
        """
        A good hash should switch 50% of the bits in a hash for every
        bit changed in the update.

        This test revealed a subtle bug : the function does not change enough
        bits, on average, for a 1-bit change in the input value.  It is also
        a seriously-weird case, strings of 1 bits, differing in the 2nd bit.

        HASH0 averages 31.219, HASH1 30.672.

        This is a subset of the test below.
        """
        for hash_function in HASH_FUNCTIONS :
            total_bits_changed = 0
            for bit_position in range( 1, 64 ) :
                first_update_value = 1 << bit_position
                second_update_value = first_update_value + 1
    
                first_hash = hash_function( self.the_rnt, 64, 19 )
                first_hash.update( first_update_value )
                first_hash_value = first_hash.intdigest()
    
                second_hash = hash_function( self.the_rnt, 64, 19 )
                second_hash.update( second_update_value )
                second_hash_value = second_hash.intdigest()
    
                xor_hash_value = first_hash_value ^ second_hash_value
                N_bits_changed = countSetBits( xor_hash_value )
                total_bits_changed += N_bits_changed
    
            average_bits_changed = total_bits_changed / 64
            print( "avg bits changed = ", average_bits_changed )            
            self.assertTrue( average_bits_changed > 30
                         and average_bits_changed < 34,
                         average_bits_changed )
    
    def test_bits3( self ) :
        """
        A good hash should switch 50% of the bits in a hash for every
        bit changed in the update.

        This test marches bits lsb to msb and adding 1 to make 1-bit
        differences.

        .avg bits changed =  32.359375
        avg bits changed =  31.671875
        .avg bits changed =  31.79265873015873
        total_bits_changed =  [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 1, 1, 0, 1, 11, 19, 27, 55, 71, 88, 127, 169, 178,
        188, 202, 209, 181, 139, 123, 92, 56, 37, 14, 9, 10, 2, 4, 0, 1,
        1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        avg bits changed =  31.645833333333332
        total_bits_changed =  [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 1, 0, 1, 2, 1, 12, 26, 37, 51, 72, 95, 128, 164, 190,
        193, 197, 207, 158, 154, 108, 86, 49, 36, 14, 15, 12, 5, 1, 1,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]

        ----------------------------------------------------------------------
        Ran 3 tests in 17.953s


        """
        
        # this would run forever, so N limits the length of the test
        N = 4 * 1024
        for hash_function in HASH_FUNCTIONS :
            bits_changed = [ 0 for i in range( 65 ) ]
            total_bits_changed   = 0
            test_count           = 0
            ms_bit_position      = 64    # 63 in the range statement
            current_update_value = 0
            while ms_bit_position :
                for bit_position in range( 1, ms_bit_position ) :
                    first_update_value = current_update_value + \
                                          ( 1 << bit_position ) 
                    second_update_value = first_update_value + 1
         
                    first_hash = hash_function( self.the_rnt, 64, 19 )
                    first_hash.update( first_update_value )
                    first_hash_value = first_hash.intdigest()
         
                    second_hash = hash_function( self.the_rnt, 64, 19 )
                    second_hash.update( second_update_value )
                    second_hash_value = second_hash.intdigest()
         
                    xor_hash_value = first_hash_value ^ second_hash_value
     
                    n_bits_changed = countSetBits( xor_hash_value )
                    bits_changed[ n_bits_changed ] += 1

                    total_bits_changed += n_bits_changed
     
                    test_count += 1 
            
                if test_count > N :
                    break

                current_update_value += 1 << ( ms_bit_position - 1 )
                ms_bit_position -= 1

            average_bits_changed = total_bits_changed / N

            print( "\ntotal_bits_changed = ", bits_changed )
            print( "avg bits changed = ", average_bits_changed )
            print( "total bits changed = ", total_bits_changed )
            self.assertTrue( average_bits_changed > 31
                         and average_bits_changed < 33,
                         average_bits_changed )

if __name__ == '__main__':
    sys.path.insert( 0, '/home/lew/EvoCrypt' )

    from   evornt    import RNT
    from   evohashes import HASH_FUNCTIONS, HASH0, HASH1

    unittest.main()
