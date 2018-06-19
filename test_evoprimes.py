#!/usr/bin/python3

import sys
import random
from evoprimes import rabin_miller, is_prime, generate_large_prime, \
                      get_next_higher_prime, get_next_lower_prime

import unittest


class TestEvoPrimes( unittest.TestCase ) :

    def test_rabin_miller( self ) :
        prime_numbers = [ 9999901, 9999907, 9999929, 9999931, 9999937,
                          9999943, 9999971, 9999973, 9999991,
                          10004444557, 999999999989, 999999999847,
                          99999999947, 99999999977, 999999883
                          ]
        for this_number in prime_numbers :
            print( this_number )
            self.assertTrue(  is_prime( this_number + 0 ) )
            self.assertFalse( is_prime( this_number + 1 ) )
            self.assertFalse( is_prime( this_number + 4 ) )

    def test_get_next_primes( self ) :
        random.seed()

        for bit_width in [ 63, 66, 127, 1230, 255, 258, 511, 514 ] :
            print( "bit_width = ", bit_width )
            for _ in range( 10 ) :
                the_prime = generate_large_prime( bit_width )
                lower_prime  = get_next_lower_prime( the_prime )
                higher_prime = get_next_higher_prime( the_prime )
                print( hex( lower_prime ), hex( higher_prime ) )
 
if __name__ == '__main__':
#    sys.path.append( '../' )
    sys.path.insert( 0, '/home/lew/EvoCrypt' )

    unittest.main()
