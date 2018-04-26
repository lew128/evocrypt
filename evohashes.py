#!/usr/bin/python3

"""
evohashes.py

This is a set of hash functions for use with evocrypt.py.

All of these return 64-bit values, folding longer hashes with xors of
the components.

"""
__version__   = "0.1"
__revision__  = "$Id$"
__date__      = "2017-04-07"
__author__    = "nobody@nowhere.com"
__copyright__ = "None"
__license__   = "None"
__filename__  = "evohashes.py"
__history__   = """
0.1 - 20170407 - started this file.

TODO :
0) 

"""


import os
import sys
import getopt
from   array import array

#SINGLE_PROGRAM_FROM_HERE

#
# The goal is to have many hashes, not just what is in python hashlib.
#
# Add more hash functions in this section, before the list
#

class HASHES() :
    """
    This is the general hash, instantiating specific hashes from the function
    list. All have the same interface, so the user doesn't know which
    one they have.

    This scrambles the list again with each call.
    """
    #
    def __init__( self, rnt, integer_width, hash_depth ) :
        """
        This is the general hash, invoking specific hashes from the function
        list.
        """
        self.hash_functions  = [ HASH0, HASH1 ]
        self.next_hash_index = 0
#        self.entropy_bits    = rnt.password_hash
        self.rnt             = rnt
        self.integer_width   = integer_width
        self.hash_depth      = hash_depth

        self.rnt.scramble_list( self.hash_functions )


    def next( self ) :
        """
        instantiates and returns the next hash.
        """

        this_hash = self.hash_functions[ self.next_hash_index ]
        self.next_hash_index += 1
        self.next_hash_index %= len( self.hash_functions )

        return  this_hash( self.rnt, self.integer_width, self.hash_depth )


class HASH0( ) :
    """
    Another hash, which I invented. The goal for this is to pass dieharder
    for a 1-byte update taken from the low byte of the last value, with
    64-bit integers.  That is a very stringent test.

    It does pass.
    """
    def __init__( self, rnt, integer_width, hash_depth ) :
        """
        Uses an random number table accessed as bitstrings to compute
        entropy beginning with the entropy_bits.

        integer_width is the size of the integer used.
        hash_depth is the number of integers in the vector.  This should
        be a prime number to prevent any synchrony in update.
        """
        self.entropy_bits     = rnt.password_hash
        self.integer_width    = integer_width
        self.hash_depth       = hash_depth
        self.max_integer      = 1 << integer_width
        self.max_integer_mask = self.max_integer - 1
        self.next_index       = 0
        self.rnt              = rnt
        self.integer_vector   = []


        # A simple initialization.  Could get the next higher prime,
        # multiply by an index into the global 4K_RANDOM_BYTES, etc.
        # Goal is 'random' bits in the array at the start of mixing the
        # input data, and different in this version of the program than
        # any other.
        #
        # need a semi-random seed from the entropy bits

        for _ in range( hash_depth ) :
            the_integer = rnt.randint( integer_width )
            self.entropy_bits ^= the_integer

            the_integer = rnt.randint( integer_width )

            self.integer_vector.append( the_integer )

            self.entropy_bits += the_integer
            self.entropy_bits += rnt.randint( integer_width )

        self.update( self.entropy_bits )
        self.entropy_bits &= self.max_integer_mask


    def update( self, the_update ) :
        """ 
        Mixes the value into the array of bits.
        Problem of types, this handles strings and integers and arrays
        of strings and integers.

        Algorithm is to multiply the integer_vector[ next_index ] by the
        byte value, then shift the next 8 numbers left or right
        according to the bits in the byte, adding '1' or max_int
        sometimes.

        There are many possible update algorithms that will work with
        this basic structure, and thus more elements of HASH_FUNCTIONS[].
        """
        if isinstance( the_update, str ) :
            for this_byte in the_update :
                # degenerate case causes right shifts, small numbers,
                # and loss of entropy in the vector
                if ord( this_byte ) == 0 :
                    this_byte = self.rnt.randint( 8 )

                # a big change to one value
                self.integer_vector[ self.next_index ] *= ord( this_byte )

                # bigger change to the next value
                self.next_index += 1 
                self.next_index %= self.hash_depth
                self.integer_vector[ self.next_index ] *= 5 * ord( this_byte )

                # the next 8 values are shifted according to bit
                # settings in each byte
                for i in range( 8 ) :
                    self.next_index += 1 
                    self.next_index %= self.hash_depth
                    if ord( this_byte ) & ( 1 << i ) :
                        self.integer_vector[ self.next_index ] <<= 1
                        if i & 0x01 :
                            self.integer_vector[ self.next_index ] += 1
                    else :
                        self.integer_vector[ self.next_index ] >>= 1
                        if i & 0x01 :
                            self.integer_vector[ self.next_index ] += \
                                    self.max_integer

        elif isinstance( the_update, int ) :
            while the_update :
                # degenerate case causes right shifts, small numbers,
                # and loss of entropy in the vector
                this_byte = the_update & 0xFF
                the_update >>= 8
                if this_byte == 0 :
                    this_byte = self.rnt.randint( 8 )

                assert self.next_index >= 0 and \
                        self.next_index < self.hash_depth

                # a big change to one value
                self.integer_vector[ self.next_index ] *= this_byte

                # bigger change to the next value
                self.next_index += 1 
                self.next_index %= self.hash_depth
                self.integer_vector[ self.next_index ] *= 5 * this_byte

                # the next 8 values are shifted according to bit
                # settings in each byte
                for i in range( 8 ) :
                    self.next_index += 1 
                    self.next_index %= self.hash_depth
                    if this_byte & ( 1 << i ) :
                        self.integer_vector[ self.next_index ] <<= 1
                        if i & 0x01 :
                            self.integer_vector[ self.next_index ] += 1
                    else :
                        self.integer_vector[ self.next_index ] >>= 1
                        if i & 0x01 :
                            self.integer_vector[ self.next_index ] += \
                                    self.max_integer

        elif isinstance( the_update, list or dict ) :
            print( "update with a list or dict" )
            sys.exit( 1 )

        # the integers grow without bound in the basic update.
        # mask the integers back into range.
        for j in range( self.hash_depth ) :
            self.integer_vector[ j ] &= self.max_integer_mask

    def hexdigest( self ) :
        """
        returns a hexadecimal string of the xors of all integers in the vector

        This is not symmetrical with the next( int_width ) functions
        also used in encryption, but making it so breaks the concept of
        'hash'. Thus, intdigest() and a function that uses it to produce
        integer_width values.
        """
        return_value = 0
        for vector_index in range( self.hash_depth ) :
            return_value ^= self.integer_vector[ vector_index ]

        hex_string = hex( return_value )
        if 'L' in hex_string :
            return hex_string[ : -1 ]
        else :
            return hex_string

    def intdigest( self ) :
        """
        returns the integer value of the hash.  The integer is as wide
        as the integers making up the hash structure.
        """
        return_value = 0
        for i in range( self.hash_depth ) :
            return_value ^= self.integer_vector[ i ]

        return return_value

class HASH1( HASH0 ) :
    """
    This uses a more general update method.

    """
    def __init__( self, rnt, integer_width, hash_depth ) :
        """
        Uses an random number table accessed as bitstrings to compute
        entropy beginning with the entropy_bits.

        integer_width is the size of the integer used.
        hash_depth is the number of integers in the vector.  This should
        be a prime number to prevent any synchrony in update.
        """
        self.entropy_bits     = rnt.password_hash
        self.integer_width    = integer_width
        self.hash_depth       = hash_depth
        self.max_integer      = 1 << integer_width
        self.max_integer_mask = self.max_integer - 1
        self.next_index       = 0
        self.rnt              = rnt
        self.integer_vector   = []


        # A simple initialization.  Could get the next higher prime,
        # multiply by an index into the global 4K_RANDOM_BYTES, etc.
        # Goal is 'random' bits in the array at the start of mixing the
        # input data, and different in this version of the program than
        # any other.
        #
        # need a semi-random seed from the entropy bits

        for _ in range( hash_depth ) :
            integer_0 = rnt.randint( integer_width )
            self.entropy_bits ^= integer_0

            integer_1 = rnt.randint( integer_width )
            self.entropy_bits += integer_1

            integer_2  = rnt.randint( integer_width )
            self.entropy_bits += integer_2

            the_integer = self.entropy_bits ^ integer_0 ^ integer_1 ^ integer_2
            self.integer_vector.append( the_integer )

        self.update( self.entropy_bits )
        self.entropy_bits &= self.max_integer_mask


    def update( self, the_update ) :
        """ 
        Mixes the value into the array of bits.
        Problem of types, this handles strings and integers and arrays
        of strings and integers.

        Algorithm is to multiply the integer_vector[ next_index ] by the
        byte value, then shift the next 8 numbers left or right
        according to the bits in the byte, adding '1' or max_int
        sometimes.

        There are many possible update algorithms that will work with
        this basic structure, and thus more elements of HASH_FUNCTIONS[].
        """
        if isinstance( the_update, str ) :
            for this_byte in the_update :
                # degenerate case causes right shifts, small numbers,
                # and loss of entropy in the vector
                if ord( this_byte ) == 0 :
                    this_byte = self.rnt.randint( 8 )

                # a big change to one value
                self.integer_vector[ self.next_index ] *= ord( this_byte )
                # the next 8 values are shifted according to bit
                # settings in each byte
                for i in range( 8 ) :
                    self.next_index += 1 
                    self.next_index %= self.hash_depth
                    if ord( this_byte ) & ( 1 << i ) :
                        self.integer_vector[ self.next_index ] <<= 1
                        if i & 0x01 :
                            self.integer_vector[ self.next_index ] += 1
                    else :
                        self.integer_vector[ self.next_index ] >>= 1
                        if i & 0x01 :
                            self.integer_vector[ self.next_index ] += \
                                    self.max_integer

        elif isinstance( the_update, int ) :
            while the_update :
                # degenerate case causes right shifts, small numbers,
                # and loss of entropy in the vector
                this_byte = the_update & 0xFF
                the_update >>= 8
                if this_byte == 0 :
                    this_byte = self.rnt.randint( 8 )

                # a big change to one value
                self.integer_vector[ self.next_index ] *= this_byte
                # the next 8 values are shifted according to bit
                # settings in each byte
                for i in range( 8 ) :
                    self.next_index += 1 
                    self.next_index %= self.hash_depth
                    if this_byte & ( 1 << i ) :
                        # bit is 1
                        self.integer_vector[ self.next_index ] <<= 1
                        # on odd bits, skip an index
                        if i & 0x01 :
                            self.integer_vector[ self.next_index ] += 1
                    else :
                        # bit is zero
                        self.integer_vector[ self.next_index ] >>= 1
                        if i & 0x01 :
                            # odd bits, set a bit on the far left
                            self.integer_vector[ self.next_index ] += \
                                    self.max_integer

        elif isinstance( the_update, list or dict ) :
            print( "update with a list or dict" )
            sys.exit( 1 )

        # the integers grow without bound in the basic update.
        # mask the integers back into range.
        for j in range( self.hash_depth ) :
            self.integer_vector[ j ] &= self.max_integer_mask


HASH_FUNCTIONS = [ HASH0, HASH1 ]

#SINGLE_PROGRAM_TO_HERE

def usage() :
    """
    This provides 'help' and other usage information.
    """
    usage_info = """
        --help  Invokes this usage function
        -h      Invokes this usage function

    --file <file name>
        This isn't used for anything yet.

    --test  <test name>
        adds a test to the list to be executed. can be repeated.
                                    
        Current tests are:
            'md5', 'sha1', 'sha384', 'sha512' and 'all' invoke those
            hashes and print the results.
                                                                    
    """
    print( usage_info )

#
# main begins here, generally test code for the module.
#
if __name__ == "__main__" :

    import random
    from   evornt import RNT

#    print '#' + __filename__
#    print '#' + __version__
#    print '#' + str( sys.argv[ 1 : ] )

    # which ones need an '=' ?
    SHORT_ARGS = "f=ht="
    LONG_ARGS  = [  'help' , 'file=', 'test=' ]

    TEST_LIST = []      # list of tests to execute
    FILE_NAME = ''

    try :
        OPTS, ARGS = getopt.getopt( sys.argv[ 1 : ], SHORT_ARGS, LONG_ARGS )

    except getopt.GetoptError as err :
        print( "getopt.GetoptError = ", err )
        sys.exit( -2 )

    for o, a in OPTS :
        if o in ( "--help" ) or o in ( "-h" ) :
            usage()
            sys.exit( -2 )

        if o in ( "--file" ) or o in ( "-f" ) :
            FILE_NAME = a

        if o in ( "--test" ) :
            TEST_LIST.append( a )

    # need a random factor to prevent repeating random sequences
    random.seed()

    PASSPHRASE = 'this is a passphrase' + hex( random.getrandbits( 128 ) )
    THE_RNT = RNT( 4096, 2, 'desktop', PASSPHRASE )

    BIN_VECTOR = array( 'L' )
    BIN_VECTOR.append( 0 )

    if 'all' in TEST_LIST :

        for HASH_FUNCTION in HASH_FUNCTIONS :
            THE_HASH = HASH_FUNCTION( 30617646 + 11744896, THE_RNT, 64, 19 )
            print( "THE_HASH = ", THE_HASH )

            THE_HASH.update( 'more text' )
            HASH_VALUE = THE_HASH.intdigest()

            print( "The hash value returned = ", hex( HASH_VALUE ) )

    if 'hashes' in TEST_LIST :

        H0 = HASHES( THE_RNT, 128, 19 )

        for _ in range( 10 ) :
            HASH_FUNCTION = H0.next()
            HASH_FUNCTION.update( "fred" )

            HASH_VALUE = HASH_FUNCTION.intdigest()

            print( "The hash value returned = ", hex( HASH_VALUE ) )


    # latest results, with the initialization from the 4k_randoms
    # this is intentionally a small RNT
    # 5.75e04 rands/second passes most through rgb_bitdist[ 11 ], 3 are
    # weak one 'runs', one 'sts_serial', one rbg_bitdist
    # weak should be 1/100, fail 1/1000.  So this is not a serious prng,
    # in crypto terms.
    if 'new' or 'hash0' in TEST_LIST :
        FP = os.fdopen( sys.stdout.fileno(), 'wb' )

        # ( password, integer_width, hash_depth ) :
        THE_HASH = HASH0( THE_RNT, 64, 31 )

        NEW_UPDATE = int( THE_HASH.hexdigest(), 16 ) & 0xFF
        
        while 1 :
            THE_HASH.update( str( NEW_UPDATE ) )
            THE_RANDOM_NUMBER = THE_HASH.intdigest()

            BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER
            BIN_VECTOR.tofile( FP )

#            print( hex( THE_RANDOM_NUMBER ) )

            NEW_UPDATE = THE_RANDOM_NUMBER & 0xFF

    # latest results, with the initialization from the 4k_randoms
    # this is intentionally a small RNT
    # 5.92e+04 rands/second passes most through rgb_bitdist[ 11 ], 3 are
    # weak one 'runs', one 'sts_serial', one rbg_bitdist
    if 'hash1' in TEST_LIST :
        FP = os.fdopen( sys.stdout.fileno(), 'wb' )

        # ( password, integer_width, hash_depth ) :
        THE_HASH = HASH1( THE_RNT, 64, 31 )

        NEW_UPDATE = int( THE_HASH.hexdigest(), 16 ) & 0xFF
        
        while 1 :
            THE_HASH.update( str( NEW_UPDATE ) )
            THE_RANDOM_NUMBER = THE_HASH.intdigest()

            BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER
            BIN_VECTOR.tofile( FP )

#            print( hex( THE_RANDOM_NUMBER ) )

            NEW_UPDATE = THE_RANDOM_NUMBER & 0xFF

    # add another test generating a sequence of pairs of 64-bit integers
    # which differ from each other in 1 bit, check the distribution of
    # bits that differ between the two hash values produced by the two
    # used as updates. 
    

