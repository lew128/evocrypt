#!/usr/bin/python3

import sys
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

 
if __name__ == '__main__':
#    sys.path.append( '../' )
    sys.path.insert( 0, '/home/lew/EvoCrypt' )

    from evoprimes import rabin_miller, is_prime

    unittest.main()
