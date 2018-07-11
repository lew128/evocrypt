#!/usr/bin/python3

import sys
import unittest
import random
from   evornt   import RNT
from   evofolds import FoldInteger



class TestEvofolds( unittest.TestCase ) :

    def setUp( self ) :

        # instantiate a random number table
        # hard code desired RNT bytes and paranoia level for now
        random.random()
        password = 'TestEvoCrypt' + hex( random.getrandbits( 128 ) )
        self.the_rnt = RNT( 4096, password, 'desktop', 2 )
                                 
        self.the_fold = FoldInteger( )

    def test_next( self ) :
        fold_functions = []
        for i in range( len( self.the_fold.fold_functions ) ) :
            this_function = self.the_fold.next()
            if this_function not in fold_functions :
                fold_functions.append( this_function )

        self.assertEqual( len( fold_functions ),
                        len( self.the_fold.fold_functions ) )

    def test_fold( self ) :
        for i in range( 8, 256, 8 ) :
            k = ( 1 << i ) - 1
            for j in range( 4, 256, 4 ) :
                folded_value = self.the_fold.fold_it( k, j )
                self.assertTrue( folded_value < 1 << j )

    def test_all_folds( self ) :
        """
        Really, always write the fucking necessary comment so you don't
        have to understand your code again. It was hard enough the first
        time, and you chose to beat your head against the wall AGAIH!!!!

        Jesus Christ, not a hint of what I was thinking, pedestrian
        names except for the stats. Why choose 2bits?

        OK, the stat names did give me the hint. the 2bit loop folds a
        value 1-128, should be 256, but hey. must not have been my best
        day. The inner loops fold those in different ways.
        Simple stats are used to check that the folds don't have a
        systematic problem.
        """

        # each fold in the function list
        for i in range( len( self.the_fold.fold_functions ) ) :
            the_fold_function = self.the_fold.next()
            print(  "the_fold = ", the_fold_function )
            print( "i, expected_value, average_value, " + \
                   "sum_of_folded_values[i], " + \
                   "count_of_folded_valuesi]" )

            the_folds            =   [ 0 for _ in range( 
                                            len( self.the_fold.fold_functions))]
            sum_of_folded_values   = [ 0 for x in range( 9 ) ]
            count_of_folded_values = [ 0 for x in range( 9 ) ]
    
            # all bit patterns in 2**20
            for j in range( 1024*1024 ) :
    
                # fold all bit string to lengths from 1 through 9
                for k in range( 1, 9 ) :
                    folded_value                 = the_fold_function( j, k )

                    # tally and sums for each bit-width
                    sum_of_folded_values  [ k ] += folded_value
                    count_of_folded_values[ k ] += 1
#                    print( i, j, folded_value )
    
                    # the folded value must have been folded, which we
                    # can check from iteration info. The folded value must be
                    # less-than or equal to the value of the bit
                    # position just past the fold.
                    self.assertTrue( folded_value <= ( 1 << j ), 
                                    ( i, j, folded_value, the_fold_function  ) )

            for i in range( 2, 8 ) :
                if count_of_folded_values[ i ] > 0 :
                    expected_value = sum( [ x for x in range( 1 << i ) ] )
                    expected_value /= 1 << i
    
                    # These are averages of the folded values of different
                    # widths.
                    # All have i entries, and the low averages in narrow
                    # fields are due to the smaller numbers for the width.
                    # Yes, 2-bit fields should average 1+2+3/4 = 6/4 = 1.5
                    # 3-bit 6+4+5+6+7= 28/8 = 3.5
                    # 4-bit 28+8+9+10+11+12+13+14+15 = 120/16 = 7.5
                    average_value = sum_of_folded_values[ i ] / \
                                    count_of_folded_values[ i ]
 
                self.assertTrue( average_value + i * 0.1 > 
                                        expected_value
                                     and
                                     average_value - i * 0.1 < 
                                        expected_value )
                print( i, expected_value, average_value,
                       sum_of_folded_values[ i ], 
                       count_of_folded_values[ i ] )
#                    print( i, expected_value, sum_of_folded_values[ i ], 
#                           count_of_folded_values[ i ], average_value )
#                else :
#                        print( i, sum_of_folded_values[ i ], 
#                               count_of_folded_values[ i ], 0 )
        
if __name__ == '__main__':

    import os
    sys.path.insert( 0, '/home/lew/EvoCrypt' )

    unittest.main()

# Notes Wed 5 May 2018
# This could be automate more, and many more checks could be added to
# whether the fold was bit-wise correct, but does that testing job OK.
# The results are clean, expected == test values.
