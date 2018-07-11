#!/usr/bin/python3

import os
import sys
from array import array
import random
import shlex
import subprocess
import unittest

class TestDieharder( unittest.TestCase ) :

    def setUp( self ) :

        # instantiate a random number table
        # hard code desired RNT bytes and paranoia level for now
        self.fp = os.fdopen( sys.stdout.fileno(), 'wb' )

        self.bin_vector = array( 'L' )
        self.bin_vector.append( 0 )

        random()
        password = 'TestEvoDieHarder' + hex( random.getrandbits( 128) )
        self.the_rnt = RNT( 4096, password, 'desktop', 1 )
                         
    def test_1( self ) :

        command = "/home/lew/EvoCrypt/evornt.py --test randint |
dieharder -d 0 -p 100 -t 100 > dieharder_0.results"

        os.system( command ) 
#        args = shlex.split( command )
#        process = subprocess.Popen( args, shell=False )
#        print( "process = ", process )

#        N = 0
#        while N < 100 * 100 :
#            the_random = self.the_rnt.randint( 64 )
#            self.bin_vector[ 0 ] = the_random
#            self.bin_vector.tofile(  self.fp )
#            N += 1

        process.wait()

#        while True :

#            the_line = process.stdout.readline()

#            if the_line == "" : # EOF, process is ending.
#                break

#            if   'PASSED' in the_line :
#                self.assertTrue( True, "PASSED dieharder birthdays" )

#            elif 'WEAK' in the_line :
#                self.assertTrue( False, "WEAK   dieharder birthdays" )

#            elif 'FAIL' in the_line :
#                self.assertTrue( False, "FAILed dieharder birthdays" )

if __name__ == '__main__':
#    sys.path.append( '../' )
    sys.path.insert( 0, '/home/lew/EvoCrypt' )

    import copy
    from evornt   import RNT

    unittest.main()

