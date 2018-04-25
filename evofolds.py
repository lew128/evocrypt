#!/usr/bin/python3

"""
evofolds.py

Utility functions used by evo modules.

Current limitations of the code :

"""
__version__   = "0.1"
__revision__  = "$Id$"
__date__      = "2017-05-01"
__author__    = "nobody@nowhere.com"
__copyright__ = "None"
__license__   = "None"
__filename__  = "evofolds.py"
__history__   = """
0.1 - 20170501 - started this file.

TODO :
0) 

"""

import sys
import traceback
import getopt

#SINGLE_PROGRAM_FROM_HERE

# folds are suprisingly tricky, I did a lot of experimenting to find
# this set that pass dieharder.
# I could argue, however, that it doesn't matter, as even bad folds hide
# the random number generator behind them. However, all of these now
# mostly pass Dieharder, with only a few 'weak' results, about the same
# as Wichmann-Hill.
class FoldInteger() :
    """
    This is the general fold, invoking specific folds from the function
    list.
    """
    def __init__( self ) :
        """
        This class holds the list of functions and the next function
        """
        self.fold_functions  = [ self.fold_xor0, self.fold_xor1,
                                 self.fold_xor_add0, self.fold_xor_add1 ]
        self.next_fold_index = 0

#        rnt.scramble_list( self.fold_functions )

    def next( self ) :
        """
        returns the next fold function in the list.
        """
        the_fold_function = self.fold_functions[ self.next_fold_index ]
        self.next_fold_index += 1
        self.next_fold_index  %= len( self.fold_functions )

        return the_fold_function

    def fold_it( self, to_be_folded_value, bit_width ) :
        """
        Invokes one of the fold functions, the caller can't know which one.
        This is the preferred way to invoke a fold in the crypto functions.
        """
        assert bit_width > 0

        if to_be_folded_value < ( 1 << bit_width ) :
            return to_be_folded_value

        the_fold_function = self.next()
        return the_fold_function( to_be_folded_value, bit_width )

    def fold_xor0( self, to_be_folded_value, bit_width ) :
        """
         Uses xor of N-bit values beginning at the right end to fold
         N-bit values to bit_with bits
        """
        assert bit_width > 0

        out_value = 0
    
        the_mask = ( 1 << bit_width ) - 1
    
        out_value ^= to_be_folded_value & the_mask
        to_be_folded_value = to_be_folded_value >> bit_width
    
        while to_be_folded_value > 0 :
            out_value ^= to_be_folded_value & the_mask
            to_be_folded_value  = to_be_folded_value >> bit_width
    
        return out_value
    

    def fold_xor1( self, to_be_folded_value, bit_width ) :
        """
         Uses shifts and xor of N-bit values to fold N bit values
         to bitwidth bits
        """
        assert bit_width > 0

        out_value = 0
    
        the_mask = ( 1 << bit_width ) - 1
    
        out_value ^= to_be_folded_value & the_mask
        to_be_folded_value = to_be_folded_value >> bit_width
    
        while to_be_folded_value > 0 :
            out_value ^= to_be_folded_value & the_mask
            to_be_folded_value  = to_be_folded_value >> bit_width

            # a first simple variation
            if bit_width > 4 :
                bit_width -= 1
    
        return out_value
    
    # add0 and add1 did not work.
    
    def fold_xor_add0( self, to_be_folded_value, bit_width ) :
        """
         Uses xor and add of N-bit values beginning at the right end to fold
         N-bit values to bit_with bits
        """
        assert bit_width > 0

        out_value = 0
    
        the_mask = ( 1 << bit_width ) - 1
    
        out_value ^= to_be_folded_value & the_mask
        to_be_folded_value = to_be_folded_value >> bit_width
    
        while to_be_folded_value > 0 :
            if out_value & 0x01 :
                out_value ^= to_be_folded_value & the_mask
            else :
                out_value += to_be_folded_value & the_mask

            to_be_folded_value  = to_be_folded_value >> bit_width
    
        return out_value & the_mask
    
    def fold_xor_add1( self, to_be_folded_value, bit_width ) :
        """
        A minor variant of fold_xor_add0
        """
        assert bit_width > 0

        out_value = 0
    
        the_mask = ( 1 << bit_width ) - 1
    
        out_value ^= to_be_folded_value & the_mask
        to_be_folded_value = to_be_folded_value >> bit_width
    
        while to_be_folded_value > 0 :
            # a first simple variation
            if bit_width > 4 :
                bit_width -= 1
    
            if out_value & 0x01 :
                out_value ^= to_be_folded_value & the_mask
            else :
                out_value += to_be_folded_value & the_mask

            to_be_folded_value  = to_be_folded_value >> bit_width
    
        return out_value & the_mask
    

#SINGLE_PROGRAM_TO_HERE

def usage() :
    """
    This provides 'help' and other usage information.
    """
    usage_info = """

        --test  <test name>
            adds a test to the list to be executed. can be repeated.
            
            Current tests are:
                'code'  encodes, then decodes plain text
    """
    print( usage_info )


#
# main begins here, generally test code for the module.
#
if __name__ == "__main__" :

    import os
    from array import array
    from evornt import RNT
    from evohashes import HASH0

    print( '#' + __filename__)
    print( '#' + __version__ )
    print( '#' + str( sys.argv[ 1 : ] ) )

    # which ones need an '=' ?
    SHORT_ARGS = "ht="
    LONG_ARGS  = [  'help', 'password=', 'test=' ]

    TEST_LIST = []      # list of tests to execute
    PASSWORD = ''

    try :
        OPTS, ARGS = getopt.getopt( sys.argv[ 1 : ], SHORT_ARGS, LONG_ARGS )

    except getopt.GetoptError as msg :
        print( "getopt.GetoptError = '", msg )
        sys.exit( -2 )

    for o, a in OPTS :
        print( "o = '" + o + "' a = '" + a )

        if o in ( "--help" ) or o in ( "-h" ) :
            usage()
            sys.exit( -2 )

        if o in ( "--password" ) :
            PASSWORD = a

        if o in ( "--test" ) :
            TEST_LIST.append( a )


    print( "Test list = ", TEST_LIST )

    THE_FOLD = FoldInteger( )

    if TEST_LIST :
        SO = os.fdopen( sys.stdout.fileno(), 'wb' )
        BIN_VECTOR = array( 'L' )
        BIN_VECTOR.append( 0 )
    else :
        sys.exit( -1 )


    if 'simple' in TEST_LIST :
        for i in range( 32, 512, 32 ) :
            k = ( 1 << i ) - 1
            print( i, hex( k )  )
            print( hex( THE_FOLD.fold_it( k, 32 ) ) )


    if 'fold' in TEST_LIST :
        V_LONG_CONSTANT = 0X721A614B6C1C32C06F6EA721BF318B0030B29952AA7A607B8CEC23B4E423BD116E198C6DEB98C5492DDBA4B5179C72055AA3900E33EAEF01E8472171E55F19E721A614B6C1C32C06F6EA721BF318B0030B29952AA7A6F07B8CEC23B4E423BD116E198C6DEB98C5492DDBA4B5179C72055AA3900E33EAEF01E8472171E55F19EA98258446

        for i in range( 32, 512, 3 ) :
            print( i )
            print( ' xor0', hex( THE_FOLD.fold_xor0(  V_LONG_CONSTANT, i ) ))
            print( ' xor1', hex( THE_FOLD.fold_xor1(  V_LONG_CONSTANT, i ) ))
            print( 'xadd0', hex( THE_FOLD.fold_xor_add0( V_LONG_CONSTANT, i ) ))
            print( 'xadd1', hex( THE_FOLD.fold_xor_add1( V_LONG_CONSTANT, i ) ))


    if 'foldit' in TEST_LIST :
        VERY_LONG_CONSTANT = [ 0X721A614B6C1C32C06F6EA721BF318B0030B29952AA7A607B8CEC23B4E423BD116E198C6DEB98C5492DDBA4B5179C72055AA3900E33EAEF01E8472171E55F19E721A614B6C1C32C06F6EA721BF318B0030B29952AA7A6F07B8CEC23B4E423BD116E198C6DEB98C5492DDBA4B5179C72055AA3900E33EAEF01E8472171E55F19EA98258446, 0XF40A8A ]

        for THE_CONSTANT in VERY_LONG_CONSTANT :
            for i in range( 32, 0, -1 ) :
                MAX_INT = ( 1 << i ) - 1
                FOLDED_VALUE = THE_FOLD.fold_it( THE_CONSTANT, i ) 
                print( hex( MAX_INT ) )
                print( hex( FOLDED_VALUE ), '\n' )


    if 'patterns' in TEST_LIST :
        PATTERNS = [ 0x1111111111111111,
                     0x2222222222222222,
                     0x4444444444444444,
                     0x8888888888888888,
                     0x3333333333333333,
                     0x6666666666666666,
                     0xcccccccccccccccc,
                     0x5555555555555555,
                     0xaaaaaaaaaaaaaaaa, 
                     0x7777777777777777,
                     0xffffffffffffffff ]

        for PATTERN in PATTERNS :
            print( hex( PATTERN ) )
            for i in range( 3, 64, 3 ) :
                print( i )
                print( 'xor0', hex( THE_FOLD.fold_xor0( PATTERN, i ) ))
                print( 'xor1', hex( THE_FOLD.fold_xor1( PATTERN, i ) ))
                print( 'xad0', hex( THE_FOLD.fold_xor_add0( PATTERN, i ) ))
                print( 'xad1', hex( THE_FOLD.fold_xor_add1( PATTERN, i ) ))

    if 'xor0' in TEST_LIST :

        THE_RNT = RNT( 4096, 2, 'desktop', 'this is a passphrase' )

        RANDINT = THE_RNT.randint( 64 )

        # ( password, integer_width, hash_depth )
        # conservative wrt entropy, only 3x the 64 bits and 11 deep
        THE_HASH = HASH0( THE_RNT, 192, 11 )

        NEW_UPDATE = THE_HASH.intdigest() & 0xFF

        while 1 :
            THE_HASH.update( str( NEW_UPDATE) )
            THE_RANDOM_NUMBER = THE_HASH.intdigest()

            FOLDED_VALUE = THE_FOLD.fold_xor0( THE_RANDOM_NUMBER, 64 ) 

            BIN_VECTOR[ 0 ] = FOLDED_VALUE
            BIN_VECTOR.tofile( SO )
#            print( hex( FOLDED_VALUE ) )

            NEW_UPDATE = THE_RANDOM_NUMBER & 0xFF

    if 'xor1' in TEST_LIST :

        THE_RNT = RNT( 4096, 2, 'desktop', 'this is a passphrase' )

        RANDINT = THE_RNT.randint( 64 )

        # ( password, integer_width, hash_depth )
        # conservative wrt entropy, only 3x the 64 bits and 11 deep
        THE_HASH = HASH0( THE_RNT, 192, 11 )

        NEW_UPDATE = THE_HASH.intdigest() & 0xFF

        while 1 :
            THE_HASH.update( str( NEW_UPDATE) )
            THE_RANDOM_NUMBER = THE_HASH.intdigest()

            FOLDED_VALUE = THE_FOLD.fold_xor1( THE_RANDOM_NUMBER, 64 ) 

            BIN_VECTOR[ 0 ] = FOLDED_VALUE
            BIN_VECTOR.tofile( SO )
#            print( hex( FOLDED_VALUE ) )

            NEW_UPDATE = THE_RANDOM_NUMBER & 0xFF

    if 'xadd0' in TEST_LIST :

        THE_RNT = RNT( 4096, 2, 'desktop', 'this is a passphrase' )

        RANDINT = THE_RNT.randint( 64 )

        # ( password, integer_width, hash_depth )
        # conservative wrt entropy, only 3x the 64 bits and 11 deep
        THE_HASH = HASH0( THE_RNT, 192, 11 )

        NEW_UPDATE = THE_HASH.intdigest() & 0xFF

        while 1 :
            THE_HASH.update( str( NEW_UPDATE) )
            THE_RANDOM_NUMBER = THE_HASH.intdigest()

            FOLDED_VALUE = THE_FOLD.fold_xor_add0( THE_RANDOM_NUMBER, 64 ) 

            BIN_VECTOR[ 0 ] = FOLDED_VALUE
            BIN_VECTOR.tofile( SO )
#            print( hex( FOLDED_VALUE ) )

            NEW_UPDATE = THE_RANDOM_NUMBER & 0xFF

    if 'xadd1' in TEST_LIST :

        THE_RNT = RNT( 4096, 2, 'desktop', 'this is a passphrase' )

        RANDINT = THE_RNT.randint( 64 )

        # ( password, integer_width, hash_depth )
        # conservative wrt entropy, only 3x the 64 bits and 11 deep
        THE_HASH = HASH0( THE_RNT, 192, 11 )

        NEW_UPDATE = THE_HASH.intdigest() & 0xFF

        while 1 :
            THE_HASH.update( str( NEW_UPDATE) )
            THE_RANDOM_NUMBER = THE_HASH.intdigest()

            FOLDED_VALUE = THE_FOLD.fold_xor_add1( THE_RANDOM_NUMBER, 64 ) 

            BIN_VECTOR[ 0 ] = FOLDED_VALUE
            BIN_VECTOR.tofile( SO )
#            print( hex( FOLDED_VALUE ) )

            NEW_UPDATE = THE_RANDOM_NUMBER & 0xFF

