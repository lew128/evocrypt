#!/usr/bin/python3

"""
This are simple tests which can detect a regression.  They check some
simple cases of one-bit differences in updates.

This is in addition to dieharder, the gold standard.  Dieharder is run
from the commandline for the module.
"""
import sys
import unittest
import random
from   evornt    import RNT
from   evohashes import HASH_FUNCTIONS

def count_set_bits( the_integer ) :
    """ destructively counts the set bits in an integer """
    count = 0
    while( the_integer ) :
        count += the_integer & 0x01
        the_integer >>= 1
    return count
 
def tally_integer_bits( number_of_dimensions, tally_array, to_be_tallied ) :
    """
    tallies each set bit in the appropriate bin

    Should be general wrt the string length.
    """
    if number_of_dimensions == 1 :
        for i in range( 64 ) :
            if ( 1 << i ) & to_be_tallied :
                tally_array[ i ] += 1

    elif number_of_dimensions == 2 :
        for i in range( 64 ) :
            for j in range( 64 ) :
                if ( 1 << i ) & to_be_tallied :
                    tally_array[ i ][ j ] += 1

def analyze_and_print_xor_bits( xor_bits, bit_string_length ) :
    """
    Standard stats for the type of data.

    a_b_bits_changed =  [
        [24, 38, 32, 36, 40, 28, 32, 32, 33, 32, 34, 24],
        [35, 29, 22, 32, 35, 34, 39, 32, 38, 33, 39, 33], 
        [34, 30, 25, 30, 36, 34, 34, 30, 30, 32, 28, 36],
        [31, 27, 28, 31, 33, 30, 38, 31, 36, 32, 28, 29],
        [27, 30, 28, 24, 36, 39, 29, 34, 29, 29, 28, 34],
        [34, 35, 24, 35, 35, 26, 31, 30, 34, 37, 34, 32],
        [33, 34, 37, 35, 33, 35, 31, 37, 26, 25, 36, 37],
        [36, 28, 33, 34, 36, 34, 30, 27, 30, 28, 33, 37],
        [37, 33, 33, 38, 41, 36, 38, 35, 34, 36, 36, 34],
        [28, 21, 37, 33, 36, 26, 28, 34, 37, 27, 24, 31],
        [30, 33, 32, 28, 36, 31, 34, 37, 28, 36, 27, 38],
        [38, 25, 31, 35, 33, 28, 31, 35, 34, 37, 34, 34]]

    """

    print( "analyze_and_print_xor_bits()\n", xor_bits, '\n', bit_string_length )

    # row-major order so summing across rows
    row_tally_sums       = [ 0 for _ in range( 12 ) ]
    column_tally_sums    = [ 0 for _ in range( 12 ) ]

    total_row_tally_bits = 0
    total_col_tally_bits = 0
    for i in range( 12 ) :
        for j in range( 12 ) :
            row_tally_sums[ i ]    += xor_bits[ i ][ j ]
            total_row_tally_bits   += xor_bits[ i ][ j ]

    for i in range( 12 ) :
        for j in range( 12 ) :
            column_tally_sums[ j ] += xor_bits[ i ][ j ]
            total_col_tally_bits   += xor_bits[ i ][ j ]

    # N*N = number of cells, but that count  should be adjusted by the
    # length of the diagonal, which doesn't contribute counts
    # adjustment is the diff in # of cells in a 
    mean_row_tally_bits = total_row_tally_bits / ( 12 ** 2 ) 
    mean_col_tally_bits = total_col_tally_bits / ( 12 ** 2 ) 
    
        # - \ ( ( 12 ** 2 ) - ( 11 ** 2 ) )

    print( "\nmean_row_tally_bits = ", mean_row_tally_bits )
    print( "\nmean_col_tally_bits = ", mean_col_tally_bits )

    return_value = True
    #for some reason, I can't make the 'and' work here
    if ( mean_row_tally_bits <= 30.0 ) or ( mean_row_tally_bits >= 34.0 ) :
        print( "row" )
        return_value &= False

    if ( mean_col_tally_bits <= 30.0 ) or ( mean_col_tally_bits >= 34.0 ) :
        print( "col" )
        return_value &= False

    return return_value

class TestEvoHashes( unittest.TestCase ) :
    """
    Unit test cases for evohash.py
    """

    def setUp( self ) :
        """ Need to instantiate the RNT for these tests,
            as the RNT is mixed into the hashes
        """
        # instantiate a random number table
        # hard code desired RNT bytes and paranoia level for now
        # a random password so the runs are different.
        random.seed()
        random_password = 'TestEvoHashes' + hex( random.getrandbits( 128 ) )
        self.the_rnt = RNT( 4096, random_password, 'desktop', 1 )

    def test_all( self ) :
        """
        This is a weak test, just confirms that the code does not fault
        and that a few of the the really dumb mistakes are not made.

        The real test is dieharder, but that cannot be run so often, it
        takes days, even on my AMD 16-core processor with a 32GB memory.
        """
        print( "\ntest_all\n" )

        # for some reason, this doesn't work, I assume another problem
        # with unittest?
        # hashes = HASHES( self.the_rnt, 64, 19 )
        # for the_hash in hashes.next() :
        for hash_function in HASH_FUNCTIONS :
            print( "the hash function = ", hash_function )

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
        
    def test_bits0( self ) :
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
        hashes that are about 32 for single bit differences, and all
        other differences, in fact. 32 is 64/2, it is exactly correct.

        So something new with HASH2.

        This tests each hash function against single and 2 combinations of
        single bits set at BIT_POSITIONS. Those values check for some
        obvious edge effects. This runs fast, more could be added.

        First to check with big changes, a different version of this
        test.  test_bit0 uses strings as the update, not at all minimal
        differences.

        For all of these, the mean tally bits is 30-32. Some regulartity
        from left to right in fewer bits changed to more, but not more
        than that. Patterns are the same binary vs replicated text strings
        of the hex, nearly the same numbers.

        So 31-33 is a natural boundary, exactly consistent with theory.
        This test was convincing, those are good hashes, however slow
        they are.
        """

        print( "\ntest_bits0\n" )

        bit_positions = [ 63, 60, 55, 50, 30, 24, 23, 9, 8, 7, 2, 1 ]

        # for each hash function, instantiate the_hash
        ret_value = True
        for hash_function in HASH_FUNCTIONS :
            print( "the hash function = ", hash_function )

            # 2D arrays of counts of changed bits with the change at each
            # location
            a_o_bits_changed  =   [ [ 0 for _ in range( len( bit_positions ) ) ]
                                    for _ in range( len( bit_positions ) ) ]
            b_o_bits_changed  =   [ [ 0 for _ in range( len( bit_positions ) ) ]
                                    for _ in range( len( bit_positions ) ) ]
            c_o_bits_changed  =   [ [ 0 for _ in range( len( bit_positions ) ) ]
                                    for _ in range( len( bit_positions ) ) ]
            a_b_bits_changed  =   [ [ 0 for _ in range( len( bit_positions ) ) ]
                                    for _ in range( len( bit_positions ) ) ]
            b_c_bits_changed  =   [ [ 0 for _ in range( len( bit_positions ) ) ]
                                    for _ in range( len( bit_positions ) ) ]
            a_c_bits_changed  =   [ [ 0 for _ in range( len( bit_positions ) ) ]
                                    for _ in range( len( bit_positions ) ) ]

            # 1D lists of tallies at each bit location in the string
            # does this need to be a loop with ranges, a full set of tests
            # at each? Overkill, but ...
            a_tally_array      =   [ 0 for _ in range( 64 ) ]
            b_tally_array      =   [ 0 for _ in range( 64 ) ]
            c_tally_array      =   [ 0 for _ in range( 64 ) ]
            o_tally_array      =   [ 0 for _ in range( 64 ) ]

            a_o_tally_array    =   [ 0 for _ in range( 64 ) ]
            b_o_tally_array    =   [ 0 for _ in range( 64 ) ]
            c_o_tally_array    =   [ 0 for _ in range( 64 ) ]

            a_b_tally_array    =   [ 0 for _ in range( 64 ) ]
            b_c_tally_array    =   [ 0 for _ in range( 64 ) ]
            a_c_tally_array    =   [ 0 for _ in range( 64 ) ]

            the_hash = hash_function( self.the_rnt, 64, 19 )
            # save the state so we can test updates against a standard
            the_hash.save_int_vector()

            o_hash_value = the_hash.intdigest()
            tally_integer_bits( 1, o_tally_array, o_hash_value )
            # for each element in the bit-positions list
            for i in range( len( bit_positions ) ) : # enumerate is not an
                                                     # improvement, contrary
                                                     # to pylint
                # for each element in the bit-positions list
                a_hash_update = 1 << bit_positions[ i ]
                # against each other element in the bit-positions list
                for j in range( len( bit_positions ) ) : # ditto enumerate
                    # i and j are equal on the diagonal
                    b_hash_update = 1 << bit_positions[ j ]

                    # restore hash state, update, get digest for a
                    the_hash.restore_int_vector()
                    the_hash.update( hex( a_hash_update ) * 3 )
                    a_hash_value     = the_hash.intdigest()

                    # restore hash state, update, get digest for b
                    the_hash.restore_int_vector()
                    the_hash.update( hex( b_hash_update ) * 5 )
                    b_hash_value     = the_hash.intdigest()

                    # restore hash state, update, get digest for c
                    # c is more or less random
                    the_hash.restore_int_vector()
                    the_hash.update( hex( a_hash_update ^ b_hash_update) * 7 )
                    c_hash_value     = the_hash.intdigest()

                    # the changed bits
                    xor_a_o_bit_diff = a_hash_value ^ o_hash_value
                    xor_b_o_bit_diff = b_hash_value ^ o_hash_value
                    xor_c_o_bit_diff = c_hash_value ^ o_hash_value

                    xor_a_b_bit_diff = a_hash_value ^ b_hash_value
                    xor_b_c_bit_diff = b_hash_value ^ c_hash_value
                    xor_a_c_bit_diff = a_hash_value ^ c_hash_value

                    # totals of the number of bits changed
                    a_o_bits_changed[ i ][ j ] =count_set_bits(xor_a_o_bit_diff)
                    b_o_bits_changed[ i ][ j ] =count_set_bits(xor_b_o_bit_diff)
                    c_o_bits_changed[ i ][ j ] =count_set_bits(xor_c_o_bit_diff)

                    a_b_bits_changed[ i ][ j ] =count_set_bits(xor_a_b_bit_diff)
                    b_c_bits_changed[ i ][ j ] =count_set_bits(xor_b_c_bit_diff)
                    a_c_bits_changed[ i ][ j ] =count_set_bits(xor_a_c_bit_diff)

                    # collect bit counts in each bit position as a first
                    # measure
                    tally_integer_bits( 1, a_tally_array, a_hash_value )
                    tally_integer_bits( 1, b_tally_array, b_hash_value )
                    tally_integer_bits( 1, c_tally_array, c_hash_value )

                    tally_integer_bits( 1, a_o_tally_array, xor_a_o_bit_diff )
                    tally_integer_bits( 1, b_o_tally_array, xor_b_o_bit_diff )
                    tally_integer_bits( 1, c_o_tally_array, xor_c_o_bit_diff )

                    tally_integer_bits( 1, a_b_tally_array, xor_a_b_bit_diff )
                    tally_integer_bits( 1, b_c_tally_array, xor_b_c_bit_diff )
                    tally_integer_bits( 1, a_c_tally_array, xor_a_c_bit_diff )
                    
            print( "\n\nthe_hash = ", the_hash )

            print( "\na_o_bits_changed = ", a_o_bits_changed )
            ret_value &= analyze_and_print_xor_bits( a_o_bits_changed, 64 )
            print( ret_value )

            print( "\nb_o_bits_changed = ", b_o_bits_changed )
            ret_value &= analyze_and_print_xor_bits( b_o_bits_changed, 64 )
            print( ret_value )

            print( "\nc_o_bits_changed = ", c_o_bits_changed )
            ret_value &= analyze_and_print_xor_bits( c_o_bits_changed, 64 )
            print( ret_value )

            print( "\na_b_bits_changed = ", a_b_bits_changed )
            ret_value &= analyze_and_print_xor_bits( a_b_bits_changed, 64 )
            print( ret_value )

            print( "\nb_c_bits_changed = ", b_c_bits_changed )
            ret_value &= analyze_and_print_xor_bits( b_c_bits_changed, 64 )
            print( ret_value )

            print( "\na_c_bits_changed = ", a_c_bits_changed )
            ret_value &= analyze_and_print_xor_bits( a_c_bits_changed, 64 )
            print( ret_value )

        self.assertTrue( ret_value == True, ret_value )


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

        TODO : the zero in the ones version, trip a flag and invert the
        hash update value.

        I maybe fixed things, now the different hashes are very uniform,
        31-33 changes for a single bit.  That is correct.

        Independent variables are the bit positions of the changes.
        Dependent variable is the number of bits in the resulting
        integer digest.
        """
        print( "\ntest_bits1\n" )

        # the positions the updates will have bits changed. This
        # produces a bit_position ** matrix that needs evaluated.
        bit_positions = [ 63, 60, 55, 50, 30, 24, 23, 9, 8, 7, 2, 1 ]

        ret_value = True
        for hash_function in HASH_FUNCTIONS :
            print( "hash function = " )
            # 2D arrays of counts of changed bits, each cell holding the
            # number of changed integer digest produced by the change of
            # update value.

            # 
            a_b_bits_changed  =   [ [ 0 for _ in range( len( bit_positions ) ) ]
                                    for _ in range( len( bit_positions ) ) ]
            b_c_bits_changed  =   [ [ 0 for _ in range( len( bit_positions ) ) ]
                                    for _ in range( len( bit_positions ) ) ]
            a_c_bits_changed  =   [ [ 0 for _ in range( len( bit_positions ) ) ]
                                    for _ in range( len( bit_positions ) ) ]

            a_o_bits_changed  =   [ [ 0 for _ in range( len( bit_positions ) ) ]
                                    for _ in range( len( bit_positions ) ) ]
            b_o_bits_changed  =   [ [ 0 for _ in range( len( bit_positions ) ) ]
                                     for _ in range( len( bit_positions ) ) ]
            c_o_bits_changed  =   [ [ 0 for _ in range( len( bit_positions ) ) ]
                                    for _ in range( len( bit_positions ) ) ]
            # 1D lists of tallies at each bit location in the string
            # does this need to be a loop with ranges, a full set of tests
            # at each? Overkill, but ...
            a_tally_array      =   [ 0 for _ in range( 64 ) ]
            b_tally_array      =   [ 0 for _ in range( 64 ) ]
            c_tally_array      =   [ 0 for _ in range( 64 ) ]
            o_tally_array      =   [ 0 for _ in range( 64 ) ]

            a_b_tally_array    =   [ 0 for _ in range( 64 ) ]
            b_c_tally_array    =   [ 0 for _ in range( 64 ) ]
            a_c_tally_array    =   [ 0 for _ in range( 64 ) ]
            a_o_tally_array    =   [ 0 for _ in range( 64 ) ]
            b_o_tally_array    =   [ 0 for _ in range( 64 ) ]
            c_o_tally_array    =   [ 0 for _ in range( 64 ) ]

            # this is the baseline against which the changes are
            # measured
            the_hash = hash_function( self.the_rnt, 64, 19 )
            # the order of digest() vs save_vector() doesn't matter, 
            # as digest doesn't write to the vector.
            o_hash_value     = the_hash.intdigest() # original hash value
            the_hash.save_int_vector()

            tally_integer_bits( 1, o_tally_array, o_hash_value )

            # for each element in the bit-positions list
            for i in range( len( bit_positions ) ) : # ditto enumerate
                a_hash_update = 1 << bit_positions[ i ]
                # against each other element in the bit-positions list
                for j in range( len( bit_positions ) ) : # ditto enumerate
                    # i and j are equal on the diagonal
                    b_hash_update = 0xFFFFFFFF ^ ( 1 << bit_positions[ j ] )

                    # A is the 1-bit marching over zeros
                    the_hash.restore_int_vector()
                    the_hash.update( a_hash_update )
                    a_hash_value     = the_hash.intdigest()

                    # B is the 0-bit marching over ones.
                    the_hash.restore_int_vector()
                    the_hash.update( b_hash_update )
                    b_hash_value     = the_hash.intdigest()

                    # C is a random big change so we can compare.
                    the_hash.restore_int_vector()
                    the_hash.update( a_hash_update ^ b_hash_update )
                    c_hash_value     = the_hash.intdigest()

                    # compare them all to the original
                    xor_a_o_bit_diff = a_hash_value ^ o_hash_value
                    xor_b_o_bit_diff = b_hash_value ^ o_hash_value
                    xor_c_o_bit_diff = c_hash_value ^ o_hash_value

                    # compare them to each other
                    xor_a_b_bit_diff = a_hash_value ^ b_hash_value
                    xor_b_c_bit_diff = b_hash_value ^ c_hash_value
                    xor_a_c_bit_diff = a_hash_value ^ c_hash_value

                    # totals of the number of bits changed
                    a_o_bits_changed[ i ][ j ] =count_set_bits(xor_a_o_bit_diff)
                    b_o_bits_changed[ i ][ j ] =count_set_bits(xor_b_o_bit_diff)
                    c_o_bits_changed[ i ][ j ] =count_set_bits(xor_c_o_bit_diff)

                    a_b_bits_changed[ i ][ j ] =count_set_bits(xor_a_b_bit_diff)
                    b_c_bits_changed[ i ][ j ] =count_set_bits(xor_b_c_bit_diff)
                    a_c_bits_changed[ i ][ j ] =count_set_bits(xor_a_c_bit_diff)

                    # collect bit counts in each bit position as a first
                    # measure
                    tally_integer_bits( 1, a_tally_array, a_hash_value )
                    tally_integer_bits( 1, b_tally_array, b_hash_value )
                    tally_integer_bits( 1, c_tally_array, c_hash_value )

                    tally_integer_bits( 1, a_o_tally_array, xor_a_o_bit_diff)
                    tally_integer_bits( 1, b_o_tally_array, xor_b_o_bit_diff)
                    tally_integer_bits( 1, c_o_tally_array, xor_c_o_bit_diff)

                    tally_integer_bits( 1, a_b_tally_array, xor_a_b_bit_diff)
                    tally_integer_bits( 1, b_c_tally_array, xor_b_c_bit_diff)
                    tally_integer_bits( 1, a_c_tally_array, xor_a_c_bit_diff)

            print( "\n\nthe_hash = ", the_hash )

            print( "\na_o_bits_changed = ", a_o_bits_changed )
            ret_value &= analyze_and_print_xor_bits( a_o_bits_changed, 64 )

            print( "\nb_o_bits_changed = ", b_o_bits_changed )
            ret_value &= analyze_and_print_xor_bits( b_o_bits_changed, 64 )

            print( "\nc_o_bits_changed = ", c_o_bits_changed )
            ret_value &= analyze_and_print_xor_bits( c_o_bits_changed, 64 )
                    
            print( "\na_b_bits_changed = ", a_b_bits_changed )
            ret_value &= analyze_and_print_xor_bits( a_b_bits_changed, 64 )

            print( "\nb_c_bits_changed = ", b_c_bits_changed )
            ret_value &= analyze_and_print_xor_bits( b_c_bits_changed, 64 )

            print( "\na_c_bits_changed = ", a_c_bits_changed )
            ret_value &= analyze_and_print_xor_bits( a_c_bits_changed, 64 )

        self.assertTrue( ret_value == True, ret_value )

    def test_bits2( self ) :
        """
        A good hash should switch 50% of the bits in a hash for every
        bit changed in the update.

        This test revealed a subtle bug : the function does not change enough
        bits, on average, for a 1-bit change in the input value.  It is also
        a seriously-weird case, strings of 1 bits, differing in the 2nd bit.

        HASH0 averages 31.219, HASH1 30.672.

        This is a subset of the test below, and is largely redundant
        with the 'c' in the above 2 tests.
        """
        print( "\ntest_bits2\n" )

        ret_value = True
        for hash_function in HASH_FUNCTIONS :
            print( "hash function = ", hash_function )

            total_bits_changed = 0
            for bit_position in range( 1, 64 ) :
                first_update_value = 1 << bit_position
                second_update_value = first_update_value + 1
    
                # always the same rnt, so the same initial state.
                # save/restore would be faster.
                first_hash = hash_function( self.the_rnt, 64, 19 )
                first_hash.update( first_update_value )
                first_hash_value = first_hash.intdigest()
    
                second_hash = hash_function( self.the_rnt, 64, 19 )
                second_hash.update( second_update_value )
                second_hash_value = second_hash.intdigest()
    
                xor_hash_value = first_hash_value ^ second_hash_value
                n_bits_changed = count_set_bits( xor_hash_value )
                total_bits_changed += n_bits_changed
    
            average_bits_changed = total_bits_changed / 64
            print( "avg bits changed = ", average_bits_changed )            
    
            ret_value &=(    average_bits_changed > 30
                         and average_bits_changed < 34 )

        self.assertTrue( ret_value == True, average_bits_changed )

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
        print( "\ntest_bits3\n" )
        
        # this would run forever, so N limits the length of the test
        number_of_tests = 4 * 1024
        ret_value       = True
        for hash_function in HASH_FUNCTIONS :
            print( "\nhash function = ", hash_function )

            bits_changed = [ 0 for _ in range( 65 ) ]
            total_bits_changed   = 0
            test_count           = 0
            ms_bit_position      = 64    # 63 in the range statement
            current_update_value = 0
            while ms_bit_position :
                for bit_position in range( 1, ms_bit_position ) :

                    first_update_value = current_update_value + \
                                          ( 1 << bit_position ) 
                    second_update_value = first_update_value + 1
         
                    # the same rnt, so always the same initial state
                    # save/restore would be faster.
                    first_hash = hash_function( self.the_rnt, 64, 19 )
                    first_hash.update( first_update_value )
                    first_hash_value = first_hash.intdigest()
         
                    second_hash = hash_function( self.the_rnt, 64, 19 )
                    second_hash.update( second_update_value )
                    second_hash_value = second_hash.intdigest()
         
                    xor_hash_value = first_hash_value ^ second_hash_value
     
                    n_bits_changed = count_set_bits( xor_hash_value )
#                    sys.stderr.write( hex( first_hash_value )  + ' ' +
#                                      hex( second_hash_value ) + ' ' +
#                                      hex( xor_hash_value )    + ' ' +
#                                      str( n_bits_changed )    + '\n' )
                    bits_changed[ n_bits_changed ] += 1

                    total_bits_changed += n_bits_changed
     
                    test_count += 1 
            
                if test_count > number_of_tests :
                    break

                current_update_value += 1 << ( ms_bit_position - 1 )
                ms_bit_position -= 1

            average_bits_changed = total_bits_changed / test_count

            print( "\ntest_count         = ", test_count )
            print( "\nbits_changed       = ", bits_changed )
            print( "avg bits changed     = ", average_bits_changed )
            print( "total bits changed   = ", total_bits_changed )
            if  ( average_bits_changed <= 30.0 ) or \
                ( average_bits_changed >= 34.0 ) :
                ret_value = False

        self.assertTrue( ret_value == True, average_bits_changed )

if __name__ == '__main__':
    sys.path.insert( 0, '/home/lew/EvoCrypt' )


    unittest.main()
