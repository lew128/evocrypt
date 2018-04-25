#!/usr/bin/python3
# -*- coding : UTF8 -*-

"""
evoprngs.py

This contains the crypto-graphic quality classes of pseudo-random number
generators, used by secure connections, any computer-to-computer connection
however transmitted.

"""
__version__   = "0.1"
__revision__  = "$Id$"
__date__      = "2017-01-25"
__author__    = "nobody@nowhere.com"
__copyright__ = "None"
__license__   = "None"
__filename__  = "evocprngs.py"
__history__   = """
0.1 - 20170706 - started this file by splitting evoprngs.py
"""

import os
import sys
import getopt
import time
from array     import array
from evofolds  import FoldInteger
from evohashes import HASHES, HASH0
from evornt    import RNT
from evoprimes import get_next_higher_prime
from evoutils  import print_stacktrace
from evoprngs  import PRNGs, MersenneTwister, VaxC, LongPeriod5, \
                      LongPeriod256, CMWC4096, LFSR, LCG, byte_rate

#SINGLE_PROGRAM_FROM_HERE

#
# Classes of CRYPTO-QUALITY-PRNGS
#

# This implements a PseudoRandom Number Generator using a set of
# Linear Congruential # Generators.

# LCGs can be predicted, and should not be be used for cryptographic
# applications.

# This produces a cryptographic-quality PRNG by seeding multiple LCGs and
# using one LCG to select bits in the random output byte from 8 others.

# With 128-bit values, 19 values per LCG array and different prime offsets
# for each of the 9 LCGs, the cycle time, even if the individual LCDs is
# very short, because of one bit being picked from 8 of them to make up
# an output byte, the combined cycle will be far too long to allow
# predicting it.

class CRYPTO :
    """
    The general crypto-quality PRNGs.
    This returns the next PRNG in the randomized list. All have the same
    methods, so the caller doesn't need to know which one is being used.

    The list is scrambled in this initialization, of course.

    This is also the point at which policies are translated to mechanism,
    presenting a simpler interface to the higher levels.
    System_type is at least 'big', 'desktop', 'laptop', 'cellphone'
    Paranoia_level chooses levels within those, at least 1, 2, 3,
    all I implement here.

    Other uses could be standard selections for 'jim', or ... because
    both sides have to be using the same choices, or you can't
    communicate.
    """
    # this returns tuples of n_prngs, integer_width, 'vector_size'
    # This is easily changed or extended without touching the code.
    system_paranoia = { 
        'big'        : { 1 : ( 19, 256, 31 ),
                         2 : ( 31, 256, 41 ),
                         3 : ( 41, 512, 97 )
                       },
        'desktop'    : { 1 : ( 19, 128, 31 ),
                         2 : ( 29, 128, 37 ),
                         3 : ( 37, 128, 53 )
                       },
        'laptop'     : { 1 : ( 17, 128, 29 ),
                         2 : ( 19, 128, 31 ),
                         3 : ( 37, 128, 43 )
                       },
        'cellphone'  : { 1 : ( 11,  64, 17 ),
                         2 : ( 13,  64, 19 ),
                         3 : ( 23,  64, 31 )
                       }
                     }

    def __init__( self, passphrase, system_type, paranoia_level ) :
        """
        """

        self.system_type       = system_type
        self.paranoia_level    = paranoia_level
        self.n_prngs, self.integer_width, self.vector_size = \
            self.system_paranoia[ system_type ][ paranoia_level ]

        self.crypto_functions = [ LcgCrypto, HashCrypto ]
        # twister fails in crypto, haven't debugged that yet.
#        self.crypto_functions = [ LcgCrypto, TwisterCrypto, HashCrypto ]
        self.next_crypto_index = 0

        # instantiate a random number table
        # hard code desired RNT bytes and paranoia level for now
        # because it is passed everywhere, I am using it to pass the
        # paranoia_level and sysem type
        self.the_rnt           = RNT( 4096, paranoia_level, system_type,
                                        passphrase )

        self.entropy           = self.the_rnt.password_hash
        self.the_rnt.paranoia_level = paranoia_level

        self.the_rnt.scramble_list( self.crypto_functions )

    def next( self ) :
        """
        Instantiates and returns the next crypto-quality PRNG with
        parameters selected by system_type and paranoia level.
        """
        this_crypto = self.crypto_functions[ self.next_crypto_index ]
        self.next_crypto_index += 1
        self.next_crypto_index %= len( self.crypto_functions )

        return  this_crypto( self.the_rnt, self.n_prngs,
                             self.integer_width, self.vector_size )



class LcgCrypto() :
    """
    Uses a set of LCGs to produce a crypto-quality pseudo-random number.

    Algorithm is to use N LCGs, with the last LCG selecting the particular
    bits from the others.

    This uses randomly chosen primes for the two constants, and
    increasing primes for the lags to produce the longest cycles.
    """

    def __init__( self, the_rnt, n_prngs, prng_bit_width, lcg_depth ) :
        """
        Initializes N LCGs of bit_width and lcg_depth.

        The goal is to calculate and set ( seed, int_width, lcg_array_size,
        multiplier, constant, lag ) for each LCD instantiated.

            lcg_array_size is the # of prng_bit_width integers in the array.

            prng_bit_width is bits in the intgers. It must be a power of
            2 for this code to work because of the calculation of the
            bit-selection mask.
            
            The values of multiplier, constants and lag are calculated.
            Multiplier decreases from a 10% less than 'max_int' for the
            array width.  Constant increases from 10% above 0. 
            Both change by an amount making N fit into 1/3rd of the range.
            
            Discussions say they only need be relatively prime, this makes
            them a prime.
 
            The lag is prime and also different across the N arrays to prevent
            short cycles.

        """

        self.entropy_bits        = the_rnt.password_hash
        self.the_rnt             = the_rnt
        self.n_prngs             = n_prngs
        self.integer_width       = prng_bit_width
        self.lcg_depth           = lcg_depth

        self.bit_selection_mask  = prng_bit_width - 1
        self.next_prng           = 0
        self.max_integer_mask    = ( 1 << prng_bit_width ) - 1
        self.max_integer         =   1 << prng_bit_width

        self.total_cycles        = 0
        self.prng_vector         = []

        self.the_fold            = FoldInteger( )


        # hash_depth should be differently different than lcg_depth
        # good enough for now.
        hashes = HASHES( the_rnt, self.integer_width, self.lcg_depth )
        the_hash = hashes.next()

        hash_of_passphrase = the_hash.intdigest()

        # small enough it doesn't mis-order the numbers, large enough
        # it won't be close to the calculated value
        fold_width = int( prng_bit_width *.6 )
        folded_hash_of_passphrase = self.the_fold.fold_it( hash_of_passphrase,
                                                     fold_width )
            
        # multipliers and additive constants :
        # need 2 series of primes a good distance apart, say the low
        # range beginning from low at 10% to high at 40 and high range
        # beginning 60% to 90% We need N of each.
        # This is predictable from standard integer widths, so we also need the
        # entropy mixed into this.
        current_max = ( self.entropy_bits + folded_hash_of_passphrase ) % \
                        int( self.max_integer * .9 )
        current_min = ( self.entropy_bits + folded_hash_of_passphrase ) % \
                        int( self.max_integer * .1 )

        # 1/Nth of 30% of the total range
        delta        = int( ( current_max * .3 ) / self.n_prngs )

        lag = 7   # initial lag.  Even if the primes become > n_prngs, it
                # is OK because that wraps around the vector.
        for i in range( self.n_prngs ) :
            multiplier   = get_next_higher_prime( current_max )
            constant     = get_next_higher_prime( current_min )
            lag          = get_next_higher_prime( lag )

            # seed, rnt, integer_width, n_integers, multiplier, constant, lag 
            self.prng_vector.append( LCG( self.the_rnt,
                                          self.integer_width, self.lcg_depth,
                                          multiplier, constant, lag ) )

            current_max -= delta
            current_min += delta
            lag         += 2
            delta        = get_next_higher_prime( delta )

        for i in range( self.n_prngs ) :  
            self.prng_vector[ i ].next( 8, 5 ) #should be dependent on the pw

    def next( self, bit_width, steps ) :
        """
        Uses the last word in the int_vector to select bits from the
        others. Cycle last and next_lcd steps times, then select a bit
        from next_lcd using the low-order bits of the 9th LCG.

       'steps' is unnecessarily tricky, but is the kind of complexity
        that makes breaking any individual set harder.  The intent is to
        cycle the PRNG a variable number of times based on the password
        before returning a value. This can't make our
        pseudo-random-number generator weaker, at 128+ bit integers and 64
        integers deep , they are individually very likely have long cycles.
        Combined, if initialized both intelligently and differently
        and using different constants for everything, it must be effectively
        infinite.  But, this is another variable in that, another complexity.

        So not one that likely fuzzes any statistics beyond what they were,
        but certainly one that works against any other attack.
        """

        # We want an index into the bit-width bits, which must be less than
        # bit_width.  That is a power of 2, of course.
        bit_selection_mask = bit_width - 1
        return_integer = 0
        self.next_prng %= ( self.n_prngs - 1 )
        for step in range( steps ) :
            for bit_index in range( bit_width ) :
    
                # bit is selected by the last prng in the vector
                selected_bit_index = \
                            self.prng_vector[ self.n_prngs - 1 ].next(
                            bit_width, 1 ) &  bit_selection_mask 
    
                lcg_value = self.prng_vector[ self.next_prng ].next(
                                                                bit_width, 1 )
                self.next_prng += 1
                self.next_prng %= ( self.n_prngs - 1 )
    
                # shift a bit to the selected bit index
                bit_mask = 1 << selected_bit_index
    
                # mask to select the bit value
                selected_bit_value = lcg_value & bit_mask
    
                # shift the selected bit to the 0th position
                bit_value = selected_bit_value >> selected_bit_index 
    
                # put the unshifted bit into the return byte
                return_integer |= ( bit_value << bit_index )
    
        self.total_cycles += steps
        return return_integer & ( ( 1 << bit_width ) - 1 )


    def dump_state( self ) :
        """
        Debug code
        """
        for element in self.prng_vector :
            print( '\n', element )
            element.dump_state()


    def encrypt( self, plain_text, steps ) :
        """
        Encrypts a message string and returns the encrypted string.
        This only handles text, other data needs serialized.

        Plain text can be a short string or a file read.  Those are
        ascii and [], there may be other special cases for later.
        """
        assert type( plain_text ) == type( 'a' ) or \
               type( plain_text ) == type( [] )
        
        cipher_text = ''
        if type( plain_text ) == type( 'a' ) :
            for plain_byte in plain_text :
                rand_byte = self.next( 8, steps )
#                print( "encode rand_byte = ", hex( rand_byte ) )
                cipher_text += chr( rand_byte ^ ord( plain_byte ) )
#                cipher_text += chr( ( rand_byte ^ ord( plain_byte ) )
#                & 0xFF )
        elif type( plain_text ) == type( [] ) :
            for plain_line in plain_text :
                for plain_byte in plain_line :
                    assert type( plain_byte ) == type( 'a' )
                    cipher_text += chr( ( ord( self.next( 8, steps ) ) ^ \
                                          ord( plain_byte ) ) & 0xFF )

        return cipher_text

    def decrypt( self, cipher_text, steps ) :
        """
        decrypts a message string and returns the encrypted string.
        """

        plain_text = ''
        if type( cipher_text ) == type( 'a' ) :
            for ciph_byte in cipher_text :
                rand_byte = self.next( 8, steps )
#                print( "decode rand_byte = ", hex( rand_byte ) )

                plain_text += chr( rand_byte ^ ord( ciph_byte ) )

        if type( plain_text ) == type( [] ) :
            for ciph_line in cipher_text :
                for ciph_byte in ciph_line :
                    assert type( ciph_byte ) == type( 'a' )
                    plain_text += chr( ( ord( self.next( 8, steps ) ) ^ \
                                         ord( ciph_byte ) ) & 0xFF )
        
        return plain_text


class TwisterCrypto( LcgCrypto ) :
    """
    Uses a set of Mersenne Twisters to produce a crypto-quality
    pseudo-random number.

    Algorithm is to use N twisterss, one for each bit of the output byte,
    with a Nth LCG selecting the particular bit from the 8.

    This represents N * 128 * size bits of state that an adversary must
    determine in order to know the next byte of pseudo-random number.

    The larger risk is that the initial state can be found by guessing
    the seed, so each of the N the twisters are initialized with different
    hashes of the seed.
    """

    def __init__( self, the_rnt, n_prngs, integer_width, prng_depth ) :
        """
        initializes N LCGs 
        """
        # prng_depth has no meaning for this PRNG
        self.prng_vector        = []
        self.total_cycles       = 0
        self.the_rnt            = the_rnt
        self.n_prngs            = n_prngs
        self.integer_width      = integer_width
        self.prng_depth         = prng_depth

        self.bit_selection_mask = integer_width - 1 # must be a power of 2

        self.the_fold            = FoldInteger( )

        hashes = HASHES( the_rnt, self.integer_width, self.prng_depth )
        hash_function = hashes.next()

        self.next_prng          = the_rnt.password_hash % prng_depth


        # self, seed, int_width, 
        #
        # int_width is bits in the intgers.
        #
        # bigger risk is guessint the seed, so initialize with a
        # different hash for each across the N subsidiary PRNGs
        for i in range( self.n_prngs ) :
            self.prng_vector.append( MersenneTwister( the_rnt, integer_width ) )

        for i in range( self.n_prngs ) :  
            self.prng_vector[ i ].next( 8, 5 ) #should be dependent on the pw

#        self.dump_state()

    def dump_state( self ) :
        """
        Dump the vectors.
        """
        for i in range( self.n_prngs ) :  
            print( "i = ", i, "prng = ", self.prng_vector[ i ] )


class HashCrypto( LcgCrypto ) :
    """
    Uses the set of hashes to produce a crypto-quality pseudo-random number.

    Individual hash functions may be relatively weak wrt dieharder, but
    very strong when considered as an ensemble.

    Data structure is the vector of instantiated hash functions.
    
    After that, each hash's integer_vector is replaced with a single
    vector.
    
    Next() calls the hashes in order doing updates.
    """
    def __init__( self, the_rnt, n_integers, integer_width, hash_depth ) :
        """
        initializes N LCGs 
        """
        self.hash_function_vector = []
        self.total_cycles         = 0
        self.the_rnt              = the_rnt
        self.n_integers           = n_integers
        self.integer_width        = integer_width # both prng and hash
        self.hash_depth           = hash_depth # no meaning here
        self.bit_selection_mask   = integer_width - 1
        self.next_integer            = 0

        self.the_fold              = FoldInteger()

        h0 = HASHES( the_rnt, integer_width, n_integers )
        for i in range( len( h0.hash_functions ) ) :
            self.hash_function_vector.append( h0.next() )
            
        # make all of the integer_vectors the same vector
        self.the_integer_vector = self.hash_function_vector[ 0 ].integer_vector
        for i in range( len( self.hash_function_vector ) ) :
            self.hash_function_vector[ i ].integer_vector = \
                                                        self.the_integer_vector

        # update the single integer_vector with every algorithm
        for i in range( len( self.hash_function_vector ) ) :
            self.hash_function_vector[ i ].update(
                                                the_rnt.password_hash * i + i )
                                       
        # initial steps should be dependent on the password
        this_value = self.next( 64, 40 )

    def next( self, bit_width, steps ) :
        """
        Returns the xors of steps random numbers in the next_integer
        positions, masked to bit_width.
        """

        # the prng integer_width must be >= bit_width, or bad crypto
        assert bit_width <= self.integer_width

        return_value = 0
        for i in range( steps ) : 
            self.next_integer = ( self.n_integers + 1 ) % self.n_integers

            # if the application uses prime values for the depth, any
            # number will do.  Otherwise, 3 and 7 are at least relatively-prime
            v0 = ( self.next_integer + i +  3 ) % self.n_integers
            v1 = ( self.next_integer + i + 11 ) % self.n_integers

            # the hash update is the slow part. RNT is to prevent cycles
            update_value  = self.the_integer_vector[ v0 ]
            update_value += self.the_rnt.next_random_value(
                            self.the_integer_vector[ v1 ], self.integer_width )

            # fold to 32 bits, probably still overkill
            four_byte_update = 0
            while update_value != 0 :
                # another link in the code breaker's logic chains
                # costs a test and branch, nearly nothing.
                if update_value & 0x01 :
                    four_byte_update ^= update_value & 0xFFFFFFFF
                else :
                    four_byte_update += update_value & 0xFFFFFFFF
                update_value >>= 32

            self.hash_function_vector[ i % len( self.hash_function_vector ) ].\
                                                    update( four_byte_update )

            # the new hash value becomes the next element of the prng vector
            new_value = self.hash_function_vector[ i % len( 
                                self.hash_function_vector ) ].intdigest()
            self.the_integer_vector[ self.next_integer ] ^= new_value

            return_value ^= new_value
            
        return return_value & ( ( 1 << bit_width ) - 1 )

class PrngsCrypto( LcgCrypto ) :
    """
    This class uses non-crypto prngs to compose an crypto-quality prng.
    """
    pass


def generate_random_table( the_rnt, N ) :
    # generate N bytes of random data in 64-bit hexadecimal words
    # I used this to generate the first-generation evocrypt.py'
    # 4K_Constant bytes.

    random_table = ''
    lcg_crypto = LcgCrypto( the_rnt, 23, 256, 31 )

    # this is 4K bytes as lines of 8-byte words in hexadecimal
    # 4 words per line
    for this_prng in range( int( N / ( 8 * 4 ) ) ) :
        the_line = ''
        for line_count in range( 4 ) :
            the_value = lcg_crypto.next( 64, 1 )

            the_line += format( the_value,' >#18X' ) + ','

        random_table += the_line + '\n'

    return random_table

#SINGLE_PROGRAM_TO_HERE

def usage() :
    """
    This provides 'help' and other usage information.
    """
    usage_info = """
        --help  Invokes this usage function
        -h      Invokes this usage function

        --test  adds a test to be executed. Current tests are:
            'big_distribution'    prints 64M prn bytes to std out
            'medium_distribution' prints 16M prn bytes to std out
            'small_distribution'  prints 4096 prn bytes to std out
            'code'  encodes, then decodes plain text
    """
    print( usage_info )

CRYPTO_PRNG_FUNCTIONS = [ HashCrypto, LcgCrypto ]
#CRYPTO_PRNG_FUNCTIONS = [ HashCrypto, TwisterCrypto, LcgCrypto ]


# main begins here, generally test code for the module.

if __name__ == "__main__" :

    import random 

    SHORT_ARGS = "hp="
    LONG_ARGS  = [  'help' , 'password=', 'test=' ]

#    print '#' + __filename__
#    print '#' + __version__
#    print '#' + str( sys.argv[ 1 : ] )

    TEST_LIST = []      # list of tests to execute
    try :
        OPTS, ARGS = getopt.getopt( sys.argv[ 1 : ], SHORT_ARGS, LONG_ARGS )

    except getopt.GetoptError as Err :
        print( "getopt.GetoptError = ", Err )
        sys.exit( -2 )

    for o, a in OPTS :
        if o in ( "--help" ) or o in ( "-h" ) :
            usage()
            sys.exit( -2 )

        if o in ( "--test") :
            TEST_LIST.append( a )

        if o in ( "--password") or o in ( "-p" ) :
            PASSWORD = a

#    THE_RNT = RNT( 4096, 1, 'desktop', 'passXE5013C13DACA28A3DADCF4F92F4FE920' )

    if 'generate_random_table' in TEST_LIST :
        print( generate_random_table( THE_RNT.password_hash, 4096, 64 ) )

    if 'lcg_crypto' in TEST_LIST :
        # 3.41e+03 rands / second, very slow

        FP = os.fdopen( sys.stdout.fileno(), 'wb' )

        INTEGER_WIDTH = 128
        LCG_DEPTH     = 32
        DIEHARDER_MAX_INTEGER   = ( 1 << 64 ) - 1

        BIN_VECTOR = array( 'L' )
        BIN_VECTOR.append( 0 )

        # need a random factor to prevent repeating pseudo-random sequences
        random.seed()

        PASSPHRASE = 'passXE5013DACA28A3DCF4F92F4FE920' + \
                        hex( random.getrandbits( 128 ) )

        THE_RNT = RNT( 4096, 1, 'desktop', PASSPHRASE )

        THE_PRNG = LcgCrypto( THE_RNT, 19, 128, 32 ) 

        while True :
            THE_RANDOM_NUMBER = THE_PRNG.next( INTEGER_WIDTH, 1 )
            THE_RANDOM_NUMBER &= ( 1 << 64 ) - 1

            BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER
            BIN_VECTOR.tofile( FP )
#            print( hex( THE_RANDOM_NUMBER )

    if 'lcg_crypto_rate' in TEST_LIST :
        FP = os.fdopen( sys.stdout.fileno(), 'wb' )

        BIN_VECTOR = array( 'L' )
        BIN_VECTOR.append( 0 )

        # need a random factor to prevent repeating pseudo-random sequences
        random.seed()

        PASSPHRASE = 'this is a seed' + hex( random.getrandbits( 128 ) )

        THE_RNT = RNT( 4096, 1, 'desktop', PASSPHRASE )

        THE_PRNG = LcgCrypto( THE_RNT, 9, 128, 31 )

        print( 'twister crypto byte rate = ',
                byte_rate( THE_PRNG, 64, 1024*1024 ) )

    if 'mersenne_twister' in TEST_LIST :
        # 5.86e+05 rands / second Passes dieharder
        FP = os.fdopen( sys.stdout.fileno(), 'wb' )

        BIN_VECTOR = array( 'L' )
        BIN_VECTOR.append( 0 )
                         
        THE_RNT = RNT( 4096, 1, 'desktop', 'passXE5013C13DACA28A3DADCF9FFE920' )

        # need a random factor to prevent repeating pseudo-random sequences
        random.seed()

        THE_PRNG = MersenneTwister( random.getrandbits( 128 ), THE_RNT, 64 )

        while True :
            THE_RANDOM_NUMBER = THE_PRNG.next( 64, 1 )
            BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER 
            BIN_VECTOR.tofile( FP )
#            print( hex( THE_RANDOM_NUMBER ) )

    if 'twister_crypto' in TEST_LIST :
        #   2.72e+03 rands / second
        # Passes birthdays
        FP = os.fdopen( sys.stdout.fileno(), 'wb' )

        BIN_VECTOR = array( 'L' )
        BIN_VECTOR.append( 0 )

        # need a random factor to prevent repeating pseudo-random sequences
        random.seed()

        # password hash is the entropy for initialing the hash
        THE_RNT.password_hash = random.getrandbits( 128 )

#    def __init__( self, the_rnt, n_prngs, integer_width, prng_depth ) :
        THE_PRNG = TwisterCrypto( THE_RNT, 9, 128, 31 )

        while True :
            THE_RANDOM_NUMBER = THE_PRNG.next( 64, 1 )

            BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER
            BIN_VECTOR.tofile( FP )
#            print( hex( THE_RANDOM_NUMBER )

    if 'twister_crypto_rate' in TEST_LIST :
        FP = os.fdopen( sys.stdout.fileno(), 'wb' )

        BIN_VECTOR = array( 'L' )
        BIN_VECTOR.append( 0 )

        # need a random factor to prevent repeating pseudo-random sequences
        random.seed()

        PASSPHRASE = 'this is a seed' + hex( random.getrandbits( 128 ) )

        THE_RNT = RNT( 4096, 1, 'desktop', PASSPHRASE )

        THE_PRNG = TwisterCrypto( THE_RNT, 9, 128, 31 )

        print( 'twister crypto byte rate = ',
                byte_rate( THE_PRNG, 64, 1024*1024 ) )

    if 'hash_crypto' in TEST_LIST :
        FP = os.fdopen( sys.stdout.fileno(), 'wb' )

        BIN_VECTOR = array( 'L' )
        BIN_VECTOR.append( 0 )

        # need a random factor to prevent repeating pseudo-random sequences
        random.seed()

        PASSPHRASE = 'this is a seed' + hex( random.getrandbits( 128 ) )

        THE_RNT = RNT( 4096, 1, 'desktop', PASSPHRASE )

        THE_PRNG = HashCrypto( THE_RNT, 19, 64, 11 )

        while True :
            THE_RANDOM_NUMBER = THE_PRNG.next( 64, 1 )
            BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER
            BIN_VECTOR.tofile( FP )
#            print( hex( THE_RANDOM_NUMBER ) )


    if 'hash_crypto_rate' in TEST_LIST :
        FP = os.fdopen( sys.stdout.fileno(), 'wb' )

        BIN_VECTOR = array( 'L' )
        BIN_VECTOR.append( 0 )

        # need a random factor to prevent repeating pseudo-random sequences
        random.seed()

        PASSPHRASE = 'this is a seed' + hex( random.getrandbits( 128 ) )

        THE_RNT = RNT( 4096, 1, 'desktop', PASSPHRASE )

        THE_PRNG = HashCrypto( THE_RNT, 19, 64, 11 )

        print( "hash crypto byte rate = ",
                byte_rate( THE_PRNG, 64, 1024*1024 ) )

    if 'encode0' in TEST_LIST :
        # this isn't as clean as encoding entirely text files, but I
        # don't have a large source of just text.  First make it work
        # with this, then on to plainer text.
        #
        # I believe that passing dieharder with a single text
        # file repeatedly encrypted is a more stringent test than this,
        # as binary files have more values possible per byte, and that
        # would help to cover a weak pseudo-random NG.
#=============================================================================#
#            dieharder version 3.31.1 Copyright 2003 Robert G. Brown
#=============================================================================#
#   rng_name    |rands/second|   Seed   |
#stdin_input_raw|  5.80e+03  |2731372621|
#=============================================================================#
#       test_name   |ntup| tsamples |psamples|  p-value |Assessment
#=============================================================================#
#  diehard_birthdays|   0|       100| 100|0.23131660|  PASSED
# then it stopped, apparently because I didn't have enough large files.

        import glob
        import struct

        N = 1024*1024*1024*1024
#        N = 8*1024*1024
        N_COUNT = 0

        FP = os.fdopen( sys.stdout.fileno(), 'wb' )

        BIN_VECTOR = array( 'L' )
        BIN_VECTOR.append( 0 )

        THE_RNT = RNT( 4096, 1, 'desktop', 'this is  seed' )

        THIS_CRYPTO = CRYPTO( 'this is a phrase', 'desktop', 1 )
        ENCODE = THIS_CRYPTO.next()

        DIR_LIST = [
        '/home/lew/Downloads*.doc',
        '/home/lew/Downloads*.pdf',
        '/home/lew/Downloads*.sh',
        '/home/lew/Downloads*.txt',
        '/home/lew/Documents/*.doc',
        '/home/lew/Documents/*.pdf',
        '/home/lew/Documents/*.sh',
        '/home/lew/Documents/*.txt',
        '/home/lew/Desktop/Downloads*.doc'
        '/home/lew/Desktop/Downloads*.pdf'
        '/home/lew/Desktop/Downloads*.sh'
        '/home/lew/Desktop/Downloads*.txt'
        ] 
        for THIS_DIR in DIR_LIST :
            FILE_LIST = glob.glob( THIS_DIR )
            for THIS_FILE in FILE_LIST :

                THIS_FILE_DATA = open( THIS_FILE, 'rb').read()
                print( THIS_FILE, len( THIS_FILE_DATA ) , len(
                THIS_FILE_DATA ) % 8 )

                #Make the file length an exact multiple of 8
                # this saves problems below, speeds this up
                # genuine encryption would be byte-by-byte.
                # this ignores an odd # of bytes at the end of the file
                MAX_BYTE_COUNT = len( THIS_FILE_DATA ) - \
                                 len( THIS_FILE_DATA ) % 8

                print( "max = ", MAX_BYTE_COUNT )
                THIS_FILE_BYTE_COUNT = 0
                CIPH_WORD = 0
                while THIS_FILE_BYTE_COUNT < MAX_BYTE_COUNT :

                    PLAIN_BYTES = THIS_FILE_DATA[ THIS_FILE_BYTE_COUNT : 
                                                  THIS_FILE_BYTE_COUNT + 8 ]
                    THIS_FILE_BYTE_COUNT += 8

                    if len( PLAIN_BYTES) == 0 :
                        break

                    RAND_INT = ENCODE.next( 64, 1 )
                    PLAIN_INT = struct.unpack( "@Q", PLAIN_BYTES )[ 0 ]

                    CIPH_WORD = PLAIN_INT ^ RAND_INT

#                    print( "ciph_word = ", hex( CIPH_WORD ) )
                    BIN_VECTOR[ 0 ] = CIPH_WORD
                    BIN_VECTOR.tofile( FP )
                    CIPH_WORD = 0
                    N_COUNT += 1
 
                    if N_COUNT > N :
                        sys.exit( 0 )

    if 'encode1' in TEST_LIST :
        # this repeatedly encodes a single large text file.
        # If dieharder can't detect regularities in the encoded message,
        # the prng is OK. Because I already knew that from other tests,
        # this merely proves that I didn't do xor wrong ;)
        #
        # 1 failed and 3 weak out of 19 tests is far too lousy, so
        # either the xor is wrong (silly to consider, it is hardware)
        # or there are regularities in encrypted files that are
        # imposed by the regularites of the text.  OK, empirically
        # true, or ?? Can't be, really can't be, and 2 moments thought
        # proides a couple of other ideas.  But first, retest.
        #
        # HAve to run that test again, different passphrase.
        # 
        # very slow, 6.23K 64-bit values / second according to dieharder
        """
lew@Lew-amd-x6 ~/EvoCrypt $ ./evoprngs.py --test encode1 | dieharder -a -g 200
#=============================================================================#
#            dieharder version 3.31.1 Copyright 2003 Robert G. Brown          #
#=============================================================================#
   rng_name    |rands/second|   Seed   |
stdin_input_raw|  6.23e+03  |3017691726|
#=============================================================================#
        test_name   |ntup| tsamples |psamples|  p-value |Assessment
#=============================================================================#
   diehard_birthdays|   0|       100|     100|0.18537547|  PASSED  
      diehard_operm5|   0|   1000000|     100|0.64316840|  PASSED  
  diehard_rank_32x32|   0|     40000|     100|0.07200933|  PASSED  
    diehard_rank_6x8|   0|    100000|     100|0.00064433|   WEAK   
   diehard_bitstream|   0|   2097152|     100|0.88380248|  PASSED  
        diehard_opso|   0|   2097152|     100|0.00017506|   WEAK   
        diehard_oqso|   0|   2097152|     100|0.01536041|  PASSED  
         diehard_dna|   0|   2097152|     100|0.15532173|  PASSED  
diehard_count_1s_str|   0|    256000|     100|0.98957588|  PASSED  
diehard_count_1s_byt|   0|    256000|     100|0.18894573|  PASSED  
 diehard_parking_lot|   0|     12000|     100|0.35741380|  PASSED  
    diehard_2dsphere|   2|      8000|     100|0.30090914|  PASSED  
    diehard_3dsphere|   3|      4000|     100|0.93053164|  PASSED  
     diehard_squeeze|   0|    100000|     100|0.00000000|  FAILED  
        diehard_sums|   0|       100|     100|0.05330236|  PASSED  
        diehard_runs|   0|    100000|     100|0.41932238|  PASSED  
        diehard_runs|   0|    100000|     100|0.40481210|  PASSED  
       diehard_craps|   0|    200000|     100|0.00029863|   WEAK   
       diehard_craps|   0|    200000|     100|0.06962231|  PASSED 

This is the 2nd run. I had the random with local entropy in all of them
today and later.
lew@Lew-amd-x6 ~/EvoCrypt $ tail evornt_encode1_20June2017.dieharder
      rng_name    |rands/second|   Seed   |
   stdin_input_raw|  5.83e+03  | 711436871|
#=============================================================================#
      test_name   |ntup| tsamples |psamples|  p-value |Assessment
#=============================================================================#
 diehard_birthdays|   0|       100|     100|0.80550140|  PASSED  
    diehard_operm5|   0|   1000000|     100|0.47661623|  PASSED  
diehard_rank_32x32|   0|     40000|     100|0.72298278|  PASSED  
  diehard_rank_6x8|   0|    100000|     100|0.47543395|  PASSED  
 diehard_bitstream|   0|   2097152|     100|0.49024940|  PASSED  

lew@Lew-amd-x6 ~/EvoCrypt $ ./evoprngs.py --test encode1 | dieharder -a
-g 200
#=============================================================================#
#            dieharder version 3.31.1 Copyright 2003 Robert G. Brown
#            #
#=============================================================================#
   rng_name    |rands/second|   Seed   |
stdin_input_raw|  6.35e+03  | 700496571|
#=============================================================================#
        test_name   |ntup| tsamples |psamples|  p-value |Assessment
#=============================================================================#
   diehard_birthdays|   0|       100|     100|0.84651717|  PASSED  
      diehard_operm5|   0|   1000000|     100|0.40706187|  PASSED  
  diehard_rank_32x32|   0|     40000|     100|0.26665833|  PASSED  
    diehard_rank_6x8|   0|    100000|     100|0.82319031|  PASSED  
   diehard_bitstream|   0|   2097152|     100|0.94650258|  PASSED  
        diehard_opso|   0|   2097152|     100|0.00000001|  FAILED  
        diehard_oqso|   0|   2097152|     100|0.55687162|  PASSED  

Has to be judged to fail.  I assume it is hashcrypto failing?  rand rae
is 10X for pure hash0 compared to CRYPTO. Need to try Hash1 again, then
work through CRYPTO code and also make sure HashCrypto works, which it
does not just now.
        """
        import glob
        import struct

#        N = 1024*1024*1024*1024
        N = 8*1024*1024
        N_COUNT = 0

        FP = os.fdopen( sys.stdout.fileno(), 'wb' )

        BIN_VECTOR = array( 'L' )
        BIN_VECTOR.append( 0 )

        # need a random factor to prevent repeating pseudo-random sequences
        random.seed()       # includes local entropy, so this doesn't repeat

        # Don't need to decode this, just defeat dieharder.
        # Password hash is the entropy for initializing the hash.
        # Decoding is not a goal, so incorporate local entropy
        # to get fair test via dieharder.
        PASSPHRASE = "this is a brand new phrase" + \
                        hex( random.getrandbits( 128 ) )
        THIS_CRYPTO = CRYPTO( PASSPHRASE, 'desktop', 1 )
        ENCODE = THIS_CRYPTO.next()

        # I constructed this 11MB file from text files in a linux kernel
        # directory.  I won't include it with the code because it might
        # contain something owned by a client.
        THE_FILE = "./TestText.txt"

        THIS_FILE_DATA = open( THE_FILE, 'rb').read()

        # Make the file length a multiple of 8
        # This saves problems below, speeds this up
        # genuine encryption would be byte-by-byte.
        # This ignores an odd # of bytes at the end of the file
        MAX_BYTE_COUNT = len( THIS_FILE_DATA ) - len( THIS_FILE_DATA ) % 8

        while True :
            THIS_FILE_BYTE_COUNT = 0
            CIPH_WORD = 0
            while THIS_FILE_BYTE_COUNT < MAX_BYTE_COUNT :

                PLAIN_BYTES = THIS_FILE_DATA[ THIS_FILE_BYTE_COUNT : 
                                              THIS_FILE_BYTE_COUNT + 8 ]
                THIS_FILE_BYTE_COUNT += 8

                if len( PLAIN_BYTES) == 0 :
                    break

                RAND_INT = ENCODE.next( 64, 1 )
                PLAIN_INT = struct.unpack( "@Q", PLAIN_BYTES )[ 0 ]

                CIPH_WORD = PLAIN_INT ^ RAND_INT

#                    print( "ciph_word = ", hex( CIPH_WORD ) )
                BIN_VECTOR[ 0 ] = CIPH_WORD
                BIN_VECTOR.tofile( FP )
                CIPH_WORD = 0
                N_COUNT  += 1
 


