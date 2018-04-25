#!/usr/bin/python3
# -*- coding : UTF8 -*-

"""
evoprngs.py

This contains ordinary pseudo-random number generators useful for scientific
and statistical work.

"""
__version__   = "0.1"
__revision__  = "$Id$"
__date__      = "2017-01-25"
__author__    = "nobody@nowhere.com"
__copyright__ = "None"
__license__   = "None"
__filename__  = "evoprngs.py"
__history__   = """
0.1 - 20170125 - started this file
"""

import os
import sys
import getopt
import time
import random
from array     import array
from evofolds  import FoldInteger
from evohashes import HASHES, HASH0
from evornt    import RNT
from evoprimes import get_next_higher_prime
from evoutils  import print_stacktrace

#SINGLE_PROGRAM_FROM_HERE

#
# PRNGs that are not crypto quality, but which can be used to compose the
# crypto versions. 
#
# Timing tests say the LCG with 128-bit integers and 32 ints in the array
# runs as fast as the Mersenne Twister, 18 seconds for 1M bytes.
# However, the crypto version of LCG takes 226 seconds vs 101 for Twister.

class PRNGs() :
    """
    This hides what particular PRNG is being used by being a universal
    superset call, each is instantiated as necessary.

    The goal is to allow mixing different lower-quality PRNGs in
    crypto-quality PRNGs.

    It applies the usual scrambling to the list during initialization.
    """

    def __init__( self, the_rnt, integer_width, prng_depth, paranoia_level ) :
        """
        store all the needed variables, calcualte anything that is
        common to the subsidiary PRNGs.
        """
        self.prng_functions       = [ LCG, MersenneTwister, VacC,
                                      LongPeriod5, LongPeriod256,
                                      CMWC4096,
                                    ]
        self.the_rnt              = the_rnt
        self.paranoia_level       = paranoia_level
        self.integer_vector       = []
#        self.multiplier           = multiplier
#        self.constant             = constant
#        self.lag                  = lag
        self.next_prng_index      = 0
        # integer_vector_size
        self.prng_depth           = prng_depth
        # width of the integers in the lcg_array
        self.width_in_bits        = integer_width
        self.width_in_bytes       = integer_width / 8 
        self.width_in_hexits      = self.width_in_bytes * 2
        self.total_cycles         = 0
        self.max_integer_mask     = ( 1 << integer_width ) - 1
        self.max_integer          =   1 << integer_width 

    def next( self ) :
        """
        Instantiates and returns the next PRNG.
        """
        this_prng = self.prng_functions[ self.next_prng_index ]
        self.next_prng_index += 1
        self.next_prng_index %= len( self.prng_functions )

        return  this_prng( self.the_rnt, self.width_in_bits, self.prng_depth )


class MersenneTwister() :
    """
    An example of a class of a non-crypto-quality PRNG.
    """
    def __init__( self, the_rnt, result_width ) :
        """
        This uses the seed to initialize the particular PRNG.

        Returned value is converted to a 128-bit integer by magic
        related to the type of the value and its size
        """
        # crypto functions depend upon the RNT having been fully initialized
        assert the_rnt.password_hash != 0
        self.the_rnt                  = the_rnt
        self.result_width             = result_width
        self.max_integer_mask         = ( 1 << result_width ) - 1 

        hashes   = HASHES( the_rnt, self.result_width, 17 )
        the_hash = hashes.next()
        the_hash.update( self.the_rnt.password_hash )
        the_hash.update( 'mersenne twister' )

        self.the_fold  = FoldInteger( )

        xor_result = \
                  self.the_fold.fold_it( the_hash.intdigest(),
                                     self.result_width )

        # need more entropy, get that from the random numbers
        new_seed = the_rnt.next_random_value( xor_result, result_width  )
        random.seed( new_seed )

    def next( self, bit_width, cycles ) :
        """
        Returns the next random value
        """
        last_value = 0
        for no_use_x in range( cycles ) :
            last_value = random.randint( 0, self.max_integer_mask )

        return last_value & ( ( 1 << bit_width ) - 1 )


class VaxC() :
    """
    Linear congruential used on the VAX.
    http://school.anhb.uwa.edu.au/personalpages/kwessen/shared/Marsaglia03.html
    """

    def __init__( self, the_rnt, integer_width, prng_depth, paranoia_level ) :
        """
        """
        # crypto functions depend upon the RNT having been fully initialized
        assert the_rnt.password_hash != 0
        self.the_rnt        = the_rnt
        self.integer_width  = integer_width
        self.integer_mask   = ( 1 << integer_width ) - 1
        self.paranoia_level = paranoia_level

        self.seed = the_rnt.next_random_value( self.the_rnt.password_hash,
                                            integer_width )
        self.next( integer_width, 40 )

    def next( self, bit_width, cycles ) :
        """
        returns a bit-width integer
        """
        for no_use_i in range( cycles * self.paranoia_level ) :
            self.seed = 69069 * self.seed + 362437
            self.seed &= self.integer_mask

        print( hex( self.seed ) )
        return self.seed & ( ( 1 << bit_width ) - 1 )

class LongPeriod5() :
    """
    http://school.anhb.uwa.edu.au/personalpages/kwessen/shared/Marsaglia03.html
    Here is an example with k=5, period about 2^160, one of the fastest long
    period RNGs, returns more than 120 million random 32-bit integers/second
    (1.8MHz CPU), seems to pass all tests:
    """

    def __init__( self, the_rnt, integer_width, prng_depth, paranoia_level ) :
        """
        """
        # crypto functions depend upon the RNT having been fully initialized
        assert the_rnt.password_hash != 0

        self.the_rnt        = the_rnt
        self.integer_width  = integer_width
        self.integer_mask   = ( 1 << integer_width ) - 1
        self.paranoia_level = paranoia_level

        # replace defaults with five random seed values in calling * program */
        self.x = the_rnt.next_random_value( the_rnt.password_hash,
                                            integer_width  )
        self.y = the_rnt.next_random_value( ( the_rnt.password_hash >> 7 )
                    & 0xFFFFFFFF, integer_width )
        self.z = the_rnt.next_random_value( ( the_rnt.password_hash >> 13 )
                    & 0xFFFFFFFF, integer_width )
        self.w = the_rnt.next_random_value( ( the_rnt.password_hash >> 23 )
                    & 0xFFFFFFFF, integer_width )
        self.v = the_rnt.next_random_value( ( the_rnt.password_hash >> 31 )
                    & 0xFFFFFFFF, integer_width )

    def next( self, bit_width, cycles ) :
        """
        returns a bit-width integer
        """
        for nouse_i in range( cycles * self.paranoia_level ) :
            t = (self.x ^ ( self.x >> 7))
            self.x  = self.y
            self.y  = self.z
            self.z  = self.w
            self.w  = self.v
            self.v  = ( self.v ^ ( self.v << 6 ) ) ^ ( t ^ ( t << 13 ) )
            self.v &= self.integer_mask

        return ( self.y + self.y + 1 ) * self.v & ( ( 1 << bit_width ) - 1 )

class LongPeriod256() :
    """
    Another example has k=257, period about 2^8222. Uses a static array
    Q[256] and an initial carry 'c', the Q array filled with 256 random
    32-bit integers in the calling program and an initial carry c<809430660
    for the multiply-with-carry operation. It is very fast and seems to pass
    all tests.
    http://school.anhb.uwa.edu.au/personalpages/kwessen/shared/Marsaglia03.html
    """
    def __init__( self, the_rnt, integer_width, prng_depth, paranoia_level ) :
        """
        Choose random initial c < 809430660 and 256 random 32-bit integers for
        Q[]

        static unsigned long Q[256],c=362436; 

        unsigned long MWC256(void){
            unsigned long long t,a=809430660LL;
            static unsigned char i=255;
            t=a*Q[++i]+c; c=(t>>32);
            return(Q[i]=t);      }
        """
        assert the_rnt.password_hash != 0
        assert integer_width == 32

        self.the_rnt        = the_rnt
        self.integer_width  = 32
        self.integer_mask   = ( 1 << 32 ) - 1
        self.paranoia_level = paranoia_level
        self.next_index     = 255
        self.Q = []

        entropy = self.the_rnt.password_hash
        for nouse_i in range( 256 ) :
            entropy  = the_rnt.next_random_value( entropy, 32 )
            entropy ^= the_rnt.next_random_value( entropy, 32 )
            self.Q.append( entropy )

        # subtracted 660 to make sure the prime is always lower than 809430660
        self.c = get_next_higher_prime( self.the_rnt.password_hash % 809430000 )

    def next( self, bit_width, cycles ) :
        """
        returns a bit_width integer
        """
        a = 809430660
        for unused_i in range( cycles * self.paranoia_level ) :
            # point to the next element of the vector
            self.next_index = ( self.next_index + 1 ) % 256

            t  = a * self.Q[ self.next_index ] + self.c
            self.c = ( t >> 32 )

            t &= self.integer_mask
            self.Q[ self.next_index ] = t 

        return t

class CMWC4096() :
    """
    Here is a complimentary-multiply-with-carry RNG with k=4097 and a
    near-record period, more than 10^33000 times as long as that of the
    Twister. (2^131104 vs. 2^19937)
    http://school.anhb.uwa.edu.au/personalpages/kwessen/shared/Marsaglia03.html
    """

    def __init__( self, the_rnt, integer_width, prng_depth, paranoia_level ) :
        """
        """
        self.the_rnt        = the_rnt
        self.integer_width  = integer_width
        self.integer_mask   = ( 1 << integer_width ) - 1
        self.paranoia_level = paranoia_level
        self.next_index = 4095
        self.Q = []
        self.c = get_next_higher_prime( self.the_rnt.password_hash % 809430000 )

        entropy = self.the_rnt.password_hash
        for nouse_i in range( 4096 ) :
            entropy += the_rnt.next_random_value( entropy, integer_width )
            self.Q.append( entropy & self.integer_mask )

        # subtracted 660 to make sure the prime is always lower than 809430660
        self.c = get_next_higher_prime( self.the_rnt.password_hash % 809430000 )

    def next( self, bit_width, cycles ) :
        """
        returns a bit_width integer
        """
        a = 18782
        r = 0xfffffffe

        for nouse_j in range( cycles * self.paranoia_level ) :
            self.next_index = ( self.next_index + 1 ) & 4095
            t = a * self.Q[ self.next_index ] + self.c
            self.c = ( t >> 32 )
            x = t + self.c
            if x < self.c :
                x += 1
                self.c += 1
            self.Q[ self.next_index ] = r - x
            self.Q[ self.next_index ] &= self.integer_mask

        return self.Q[ self.next_index ]

# http://citeseerx.ist.psu.edu/viewdoc/download?doi=10.1.1.43.3639&rep=rep1&type=pdf

lfsr_taps_32  = [
 ( 18,  2,  7, 13 ), ( 13,  3,  4,  9 ), ( 24,  3, 11, 12 ), ( 10,  4,  2,  6 ),
 ( 16,  4,  2, 12 ), ( 11,  5,  4,  3 ), ( 17,  5,  4,  6 ), ( 12,  5, 11,  9 ),
 ( 23,  5, 11, 12 ), ( 23,  6,  7,  8 ), ( 14,  8,  2,  9 ), ( 22,  8,  7,  4 ),
 ( 21,  8, 11,  4 ), ( 10,  9,  8,  2 ), ( 22,  9, 11,  9 ), (  3, 10,  4, 15 ),
 ( 24, 10,  7,  8 ), ( 21, 10,  8,  4 ), ( 12, 10,  8, 15 ), ( 17, 10, 11,  6 ),
 (  3, 11,  4, 12 ), (  9, 11,  4, 13 ), (  9, 11,  7,  4 ), ( 11, 12,  4, 10 ),
 ( 20, 12,  7, 15 ), ( 17, 12, 11, 11 ), ( 21, 13,  4, 14 ), ( 11, 14,  8,  7 ),
 (  6, 14,  8, 13 ), ( 20, 15,  7, 13 ), ( 12, 16,  2, 10 ), (  4, 16,  8,  3 ),
 ( 22, 17,  4,  6 ), ( 21, 17,  4, 13 ), ( 20, 17,  7,  8 ), ( 19, 17, 11,  6 ),
 (  4, 17, 11,  7 ), ( 12, 17, 11, 15 ), ( 15, 18,  4,  9 ), ( 17, 18,  4, 15 ),
 ( 12, 18,  7,  4 ), ( 15, 18,  8, 11 ), (  6, 18, 11, 13 ), (  8, 19,  2,  9 ),
 ( 13, 19,  4,  2 ), (  5, 19,  8,  3 ), (  6, 19,  8, 11 ), ( 24, 19, 11,  5 ),
 (  6, 20,  2, 10 ), ( 13, 20,  4, 10 ), ( 24, 21,  2,  7 ), ( 14, 21,  8, 13 ),
 ( 10, 22,  8, 13 ), (  7, 22,  8, 14 ), ( 15, 23,  8,  5 ), (  9, 23, 11,  4 ),
 ( 20, 24,  4,  8 ), ( 16, 24,  4, 14 ), ( 20, 24,  4, 14 ), ( 23, 24,  7,  3 ),
 ( 14, 24,  8, 10 ), ( 16, 24, 11, 12 )
 ]

lfsr_taps_64 = [ ( 18, 28,  7,  8 ), ( 26, 20, 11,  7 ), ( 19, 25, 12,  9 ),
                 ( 18, 22, 16,  6 ), ( 18, 22, 16,  6 ), ( 30, 28, 17,  9 ),
                 ( 17, 28, 18,  6 ), ( 12,  8, 22,  9 ) ]

class LFSR() :
    """
    Galois version because it is faster.  This does not yet work they
    way the literatue describes, or I don't understand what the
    liberature is describing.

    ./evoprngs.py --test lfsr_periods
    !!!!cycle detected !!!! 11927370
    351 million 64-bit cycles after that initial cycle
    When run 20 times with different seeds, usually none or all failed.
    If they cycled, the cycles had common divsors, but weird, like 19.5,
    93, ... Tho 2 was common also.
    
    In 20 random seeds, ?? of the 62 32-bit tap patterns above had periods
    shorter than 102K x 64-bit cycles in a program I found online. Some
    had very short cycles, many of them multiple cycles in the 1M or
    102K 64-bit cycles.

    In this implementation, 30 of the 62 had cycles shorter than 1M x
    64-bit cycles. In total, there were 720 trials out of 62 * 20 total
    that had no period in 64M cycles, 58%. 

    This is not supposed to happen, 32-bit or 64-bit, so there is a
    problem with this code.

    However,  I tested some other code with the above taps, and can't
    make them work any better, whether starting with random seeds or
    with '1'.

    However, it doesn't matter, this passes dieharder.  Crypto-quality
    prngs need to be better, but these are the basis of those. Obviously,
    it is trivial to xor the bit outputs of N of these and thus produce
    crypto-quality unpredictability in a pseudorandom number stream.
   
    After I have the application working I will do that.

    Even better, every time there is a cycle, switch to a different set
    of taps, and continue with the existing state.  Change taps, not
    state. So we begin with a random order of taps in the set, randomly
    select one of them, and continue to the next in the list, wrapping
    as necessary. That design means we don't need to care about cycles.

    I do care, would rather understand the problem in this.  But I don't
    need to, it is half way to crypto-quality with that change. Two of
    those xorded are all that is needed, so that will be one of the
    faster algorithms, 40K bytes a second.
    """
    def __init__( self, the_rnt, integer_width, prng_depth,
                    paranoia_level, a_specified_tap=None ) :
        """ seed is entropy. taps is one set
            prng_depth has no use here.
        """
        self.the_rnt        = the_rnt
        self.integer_width  = integer_width
        self.integer_mask   = ( 1 << integer_width ) - 1
        self.paranoia_level = paranoia_level
        self.this_tap = 0
        if   integer_width == 32 :
            if a_specified_tap :
                self.taps = a_specified_tap
            else :
                self.this_tap = the_rnt.password_hash % len( lfsr_taps_32 )
                self.taps = lfsr_taps_32[ self.this_tap ]

        elif integer_width == 64 :
            if a_specified_tap :
                self.taps = a_specified_tap
            else :
                self.this_tap = the_rnt.password_hash % len( lfsr_taps_64 )
                self.taps     = lfsr_taps_64[ self.this_tap ]

        else :
            sys.stderr.write(
                        "LFSR : Only 32 or 64 bit integer_width are supported" )
            sys.exit( -1 )

        self.seed_count = 2 # to modify the seed if it cycles
        self.seed = the_rnt.password_hash & self.integer_mask
        self.lfsr = self.seed

        self.period = 0
        self.periods = []

        self.tap_mask = self.integer_taps( self.taps )

#        sys.stdout.write( "tap_mask = " + hex( self.tap_mask ) )
#        sys.stdout.write( " self.lfsr = " + hex( self.lfsr ) + '\n' )
#        sys.stdout.flush()

    def integer_taps( self, the_taps ) :
        """
        Returns an integer mask for use in next_bit.
        """
        tap_mask = 0
        for this_tap in the_taps :
            tap_mask |= 1 << ( this_tap - 1 )
        # include the top bit
        tap_mask |= 1 << ( self.integer_width - 1 )

        return tap_mask

    def next_bit( self, cycles ) :
        """
        lfsr cannot have a shorter cycle, from the theory, so this
        implementation is wrong.
        """
        for nouse_x in range( 1 + cycles * self.paranoia_level ) :
            self.period += 1
            bit = self.lfsr & 0x01
            self.lfsr >>= 1
            if bit :
                self.lfsr  ^= self.tap_mask

            # this may cover up a problem, so did tests for how long
            # the period was. 32-bit period is sometimes only a few 10s
            # of millions, but not after the first cycle.  64-bit also.
            # Both pass dieharder.
            if self.lfsr == self.seed :
                sys.stdout.write( "!!!cycle detected!!! " + str( self.period ) )
                self.periods.append( ( self.period, hex( self.lfsr ) ) )
                self.period = 0
                self.seed_count += 1 # need to modify the seed if it cycles

                if self.integer_width == 32 :
                    self.this_tap = ( self.this_tap + 1 ) % len( lfsr_taps_32 )
                    self.taps = lfsr_taps_32[ self.this_tap ]
                else :
                    self.this_tap = ( self.this_tap + 1 ) % len( lfsr_taps_64 )
                    self.taps = lfsr_taps_64[ self.this_tap ]

                self.tap_mask = self.integer_taps( self.taps )
                # no need to change the seed?
#                self.seed = ( self.the_rnt.password_hash * \
#                            ( self.the_rnt.password_hash * self.seed_count )) \
#                             & self.integer_mask
#                self.lfsr = self.seed
                sys.stdout.write( " passwd_hash = " +
                                            hex( self.the_rnt.password_hash ) )
                sys.stdout.write( " new lfsr state = " + hex( self.lfsr ) +'\n')
                sys.stdout.flush()

#        eprint( "bit = ", bit )
        return bit

    def next( self, bit_width, cycles ) :
        """
        Standard next function adapted to this PRNG.
        """
        return_value = 0
        for nouse_i in range( bit_width ) :
            return_value <<= 1 
            return_value  += self.next_bit( cycles )

#        eprint( hex( return_value ) )
        return return_value
            


class LCG():
    """
    Class for a Linear Congruential Generator with parameters
    controlling space/time of running.
    """

    def __init__( self, rnt, integer_width, n_integers,
                        multiplier, constant, lag ) :
        """
        This uses the seed to initialize the m values in the lcg_array.
        The goal of the code is to prevent knowing anything about the
        seed, given the initial output values.

        It also stores a, c, lag for use in the next and next_byte functions.

        LCG as is passes dieharder, with only 2 'weak' scores, the rest
        passes. Approx 100 total, so acceptable?  Twister had weak
        scores, also.
        """
        self.integer_vector       = []
        self.entropy              = rnt.password_hash
        self.the_rnt              = rnt
        self.integer_width        = integer_width
        self.integer_vector_size  = n_integers
        self.multiplier           = multiplier
        self.constant             = constant
        self.lag                  = lag
        self.index                = 0

        # width of the integers in the lcg_array
        self.width_in_bits        = integer_width
        self.width_in_bytes       = integer_width / 8 
        self.width_in_hexits      = self.width_in_bytes * 2
        self.total_cycles         = 0
        self.max_integer_mask     = ( 1 << integer_width ) - 1
        self.max_integer          =   1 << integer_width 

        self.integer_vector = [ 0 for i in range( self.integer_vector_size ) ]

        #
        # initialize the lcg array beginning with a hash of the seed
        #

        # Each successive value in the lcg_array is the xor of the hash
        # of the set of the prior values.
        # xor to further obfuscate the result by preventing guessing
        # which hash was used, a fact that could be used to work back
        # to obtain the password, given the code.
        # The fold operation does this, but not reliably because all
        # hashes are not longer than 64 bits

        # Perilously close to security by obscurity, but I think solid
        # math.  If the hash input changing in a single bit, on average
        # changes 50% of the bits in the hash, changing more bits via
        # xor can't hurt unless the number of bits changed in the input
        # predicts some statistic about the relationship of cyphertext to
        # plaintext.  Statistically, it can't happen.

        hashes = HASHES( rnt, self.integer_width, self.integer_vector_size )
        the_hash = hashes.next()


        # each LCD will be unique in these, so uniquely initialized
        the_hash.update( self.entropy )
        the_hash.update( str( self.multiplier ) + str( self.constant ) + \
                         str( self.lag ) )

        self.the_fold  = FoldInteger( )
        xor_result = \
                  self.the_fold.fold_it( the_hash.intdigest(),
                                     self.width_in_bits )

        the_hash.update( xor_result )

        for vector_index in range( self.integer_vector_size ) :

            # the hash of the previous part of the array
            for j in range( vector_index ) :
                the_hash.update( str( self.integer_vector[ j ] ) )

            integer_hash = the_hash.intdigest()
            integer_hash = self.the_fold.fold_it( integer_hash,
                                                  self.width_in_bits )

            xor_result ^= integer_hash
            self.integer_vector[ vector_index ] = xor_result


        # Cycle it a random number of times
        cycles = ( xor_result & 
                   self.the_rnt.randint( self.width_in_bits ) ) % 1024
        self.next( 1, cycles )


    def next( self, bit_width, cycles ) :
        """
        Returns the next pseudo-random bit_width value after cycles of
        operation.

        This produces far too many leading digits of 0 in the 128-bit
        numbers, so we return the middle 64 bits.
        """

        for this_cycle in range( cycles ) :

            lagged_index = ( self.index + self.lag ) % self.integer_vector_size

            # mask to the max_value to prevent wild growth of the integer
            vector_value = self.max_integer_mask
            vector_value &= self.integer_vector[ lagged_index ]
            vector_value *= self.multiplier
            vector_value += self.constant

            self.integer_vector[ self.index ] = vector_value

            self.index = ( self.index + 1 ) % self.integer_vector_size
            self.total_cycles += 1

        return self.integer_vector[ self.index ] & ( ( 1 << bit_width ) - 1 )

    def dump_state( self ) :
        """
        Debug code
        """
        for element in self.integer_vector :
            print( hex( element ) )



def byte_rate( the_function, result_width, N ) :
    """
    The_function is one of the crypto or PRNG functions with a 'next'.
    Result_width is the desired width of the result of that function in bits.
    N is the number of results to compute before returning bytes/second.
    """
    beginning_time = int( time.time() )
    for I in range( N ) :
        this_result = the_function.next( result_width , 1 )
    ending_time = int( time.time() )

    return ( N * ( result_width / 8 ) ) / ( ending_time - beginning_time )

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


# main begins here, generally test code for the module.

if __name__ == "__main__" :

    import random 

    SHORT_ARGS = "hp="
    LONG_ARGS  = [  'help' , 'int_width=', 'password=', 'test=' ]

#    print '#' + __filename__
#    print '#' + __version__
#    print '#' + str( sys.argv[ 1 : ] )

    PASSWORD  = ''
    INT_WIDTH = None
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

        if o in ( "--int_width") :
            INT_WIDTH = int( a )

        if o in ( "--password") or o in ( "-p" ) :
            PASSWORD = a

    if 'lcg' in TEST_LIST :
        #  7.97e+05 rands/second Passes dieharder
        # passes birthdays, operm5, rank 32x32, weak or fails rank
        # 6x8 weak nd beyond
        # this was not improved by the twister-produced rng.

        FP = os.fdopen( sys.stdout.fileno(), 'wb' )

        INTEGER_WIDTH = 128
        LCG_DEPTH     = 32
        MAX_INTEGER = (1 << INTEGER_WIDTH ) - 1

        # 
        #  128 bit widths = 7.54e+05 rands/second

        BIN_VECTOR = array( 'L' )
        BIN_VECTOR.append( 0 )

        # need a random factor to prevent repeating pseudo-random sequences
        random.seed()

        PASSWORD += hex( random.getrandbits( 128 ) )
        THE_RNT = RNT( 4096, 1, 'desktop', PASSWORD )


        MAX_INTEGER = ( 1 << INTEGER_WIDTH ) - random.getrandbits( 36 )

        BIG_PRIME   = get_next_higher_prime( int( ( MAX_INTEGER * 4 ) / 5 ) )
        SMALL_PRIME = get_next_higher_prime( int( ( MAX_INTEGER * 2 ) / 5 ) )

            #( seed, INTEGER_WIDTH, n_integers, multiplier, constant, lag ):
        THE_PRNG = LCG( THE_RNT, INTEGER_WIDTH, LCG_DEPTH, BIG_PRIME,
                                                           SMALL_PRIME, 19 ) 
        while True :
            THE_RANDOM_NUMBER = THE_PRNG.next( 64, 1 )

            BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER 
            BIN_VECTOR.tofile( FP )
#            print( hex( THE_RANDOM_NUMBER )

    if 'vax_c' in TEST_LIST :
        # 8.17e+05 rands / second, very slow
        FP = os.fdopen( sys.stdout.fileno(), 'wb' )

        INTEGER_WIDTH = 32
        LCG_DEPTH     = 32
        DIEHARDER_MAX_INTEGER   = ( 1 << 64 ) - 1

        BIN_VECTOR = array( 'L' )
        BIN_VECTOR.append( 0 )

        # need a random factor to prevent repeating pseudo-random sequences
        random.seed()

        PASSWORD += hex( random.getrandbits( 128 ) )
        THE_RNT = RNT( 4096, 1, 'desktop', PASSWORD )


        # ( self, the_rnt, integer_width, prng_depth, paranoia_level )
        THE_PRNG = VaxC( THE_RNT, 32, 32, 2 ) 

        while True :
            RN0 = THE_PRNG.next( 32, 1 )
            RN1 = THE_PRNG.next( 32, 1 )
            THE_RANDOM_NUMBER  = RN0 << 32
            THE_RANDOM_NUMBER += RN1
#            THE_RANDOM_NUMBER = RN0 << 32 + RN1
            THE_RANDOM_NUMBER &= ( 1 << 64 ) - 1

            BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER
            BIN_VECTOR.tofile( FP )
#            print( hex( THE_RANDOM_NUMBER ) )

    if 'lp5' in TEST_LIST :
        # 8.17e+05 rands / second, very slow
        FP = os.fdopen( sys.stdout.fileno(), 'wb' )

        INTEGER_WIDTH = 32
        LCG_DEPTH     = 32
        DIEHARDER_MAX_INTEGER   = ( 1 << 64 ) - 1

        BIN_VECTOR = array( 'L' )
        BIN_VECTOR.append( 0 )

        # need a random factor to prevent repeating pseudo-random sequences
        random.seed()

        PASSWORD += hex( random.getrandbits( 128 ) )

        THE_RNT = RNT( 4096, 1, 'desktop', PASSWORD )

        # ( self, the_rnt, integer_width, prng_depth, paranoia_level )
        THE_PRNG = LongPeriod5( THE_RNT, 32, 32, 2 ) 

        while True :
            RN0 = THE_PRNG.next( 32, 1 )
            RN1 = THE_PRNG.next( 32, 1 )
            THE_RANDOM_NUMBER  = RN0 << 32
            THE_RANDOM_NUMBER += RN1
            THE_RANDOM_NUMBER &= ( 1 << 64 ) - 1

            BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER
            BIN_VECTOR.tofile( FP )
#            print( hex( THE_RANDOM_NUMBER ) )

    if 'lp256' in TEST_LIST :
        # 8.17e+05 rands / second, very slow
        FP = os.fdopen( sys.stdout.fileno(), 'wb' )

        INTEGER_WIDTH = 32
        LCG_DEPTH     = 32
        DIEHARDER_MAX_INTEGER   = ( 1 << 64 ) - 1

        BIN_VECTOR = array( 'L' )
        BIN_VECTOR.append( 0 )

        # need a random factor to prevent repeating pseudo-random sequences
        random.seed()

        PASSWORD += hex( random.getrandbits( 128 ) )

        THE_RNT = RNT( 4096, 1, 'desktop', PASSWORD )

        # ( self, the_rnt, integer_width, prng_depth, paranoia_level )
        THE_PRNG = LongPeriod256( THE_RNT, 32, 32, 2 ) 

        while True :
            RN0 = THE_PRNG.next( 32, 1 )
            RN1 = THE_PRNG.next( 32, 1 )
            THE_RANDOM_NUMBER  = RN0 << 32
            THE_RANDOM_NUMBER += RN1
            THE_RANDOM_NUMBER &= ( 1 << 64 ) - 1

            BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER
            BIN_VECTOR.tofile( FP )
#            print( hex( THE_RANDOM_NUMBER ) )

    if 'cmwc4096' in TEST_LIST :
        # 8.17e+05 rands / second, very slow
        FP = os.fdopen( sys.stdout.fileno(), 'wb' )

        INTEGER_WIDTH = 32
        LCG_DEPTH     = 32
        DIEHARDER_MAX_INTEGER   = ( 1 << 64 ) - 1

        BIN_VECTOR = array( 'L' )
        BIN_VECTOR.append( 0 )

        # need a random factor to prevent repeating pseudo-random sequences
        random.seed()

        PASSWORD += hex( random.getrandbits( 128 ) )

        THE_RNT = RNT( 4096, 1, 'desktop', PASSWORD )

        # ( self, the_rnt, integer_width, prng_depth, paranoia_level )
        THE_PRNG = CMWC4096( THE_RNT, 32, 32, 2 ) 

        while True :
            RN0 = THE_PRNG.next( 32, 1 )
            RN1 = THE_PRNG.next( 32, 1 )
            THE_RANDOM_NUMBER  = RN0 << 32
            THE_RANDOM_NUMBER += RN1
            THE_RANDOM_NUMBER &= ( 1 << 64 ) - 1

            BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER
            BIN_VECTOR.tofile( FP )
#            print( hex( THE_RANDOM_NUMBER ) )

    if 'lfsr_periods' in TEST_LIST :
        # tests 20 samples to see if they have a period less than 64B
        # this is random selection of the taps and initial condition
        # I proofed the tap list carefully, so it is OK.
        for j in range( 20 ) :
            # need a random factor to prevent repeating pseudo-random sequences
            random.seed()       # includes local entropy, so this doesn't repeat

            PASSWORD += hex( random.getrandbits( 128 ) )

            THE_RNT = RNT( 4096, 1, 'desktop', PASSWORD )

            #    ( the_rnt, integer_width, prng_depth, paranoia_level )
            lfsr = LFSR( THE_RNT, INT_WIDTH, 20, 1 )
  
            beginning_time = int( time.time() )

            N = 1024 * 1024 * 1024
            for i in range( 1024 ):
                for j in range( 1024 * 1024 ) :
                    lfsr.next( 64, 1 )
                print( i, " million ", INT_WIDTH, "bit cycles" )

            ending_time = int( time.time() )

            print( "byte_rate = ", ( N * 8 ) / ( ending_time - beginning_time) )
            print( lfsr.periods )

    if 'lfsr_periods0' in TEST_LIST :
        # tests 20 samples of seeds for each individual LFSR tap setting
        # to see if they have a period less than 1M. Another check on
        # the implementation.

        for this_tap in lfsr_taps_32 : # don't screw up 32/64 and int_width
            INT_WIDTH = 32
            print( this_tap )
            for j in range( 20 ) :
                # need a random factor to prevent repeating pseudo-random
                # sequences
                random.seed() # includes local entropy, so this doesn't repeat

                PASSWORD += hex( random.getrandbits( 128 ) )

                THE_RNT = RNT( 4096, 1, 'desktop', PASSWORD )

                #    ( the_rnt, integer_width, prng_depth, paranoia_level )
                lfsr = LFSR( THE_RNT, INT_WIDTH, 20, 1, this_tap )
  
                beginning_time = int( time.time() )

                N = 1024 * 1024
                for i in range( N ) :
                    lfsr.next( 64, 1 )

                ending_time = int( time.time() )

                print( '\t', hex( THE_RNT.password_hash ), lfsr.periods, 
                        "byte_rate = ",
                            int(( N * 8 ) / ( ending_time - beginning_time) ) )

    if 'lfsr_periods1' in TEST_LIST :
        for this_tap in [ ( 16, 4, 2, 12 ), ( 11, 5, 4, 3 ) ] :
            sys.stdout.write( '\n' + str( this_tap ) + '\n' )
            sys.stdout.flush()
            INT_WIDTH = 32
            for j in range( 20 ) :
                # need a random factor to prevent repeating pseudo-random
                # sequences
                random.seed() # includes local entropy, so this doesn't repeat

                PASSWORD += hex( random.getrandbits( 128 ) )

                THE_RNT = RNT( 4096, 1, 'desktop', PASSWORD )

                #    ( the_rnt, integer_width, prng_depth, paranoia_level )
                lfsr = LFSR( THE_RNT, INT_WIDTH, 20, 1, this_tap )
  
                beginning_time = int( time.time() )

                N = 1024 * 102
                for i in range( N ) :
                    lfsr.next( 64, 1 )

                ending_time = int( time.time() )

                sys.stdout.write( '\t')
                sys.stdout.write( hex( lfsr.tap_mask ) + ' ' )
                sys.stdout.write( hex( THE_RNT.password_hash ) + ' ' )
                sys.stdout.write( str( lfsr.periods ) + ' ' )
                sys.stdout.write( "byte_rate = " )
                sys.stdout.write( str(
                                ( N * 8 ) / ( ending_time - beginning_time) ) )
                sys.stdout.write( '\n' )
                sys.stdout.flush()

    if 'lfsr' in TEST_LIST :
        FP = os.fdopen( sys.stdout.fileno(), 'wb' )

        BIN_VECTOR = array( 'L' )
        BIN_VECTOR.append( 0 )

        THE_RNT = RNT( 4096, 1, 'desktop', 'passXE5013C13DACA2ADCF4F92F4FE920' )
        # need a random factor to prevent repeating pseudo-random sequences
        random.seed()       # includes local entropy, so this doesn't repeat

        PASSWORD += hex( random.getrandbits( 128 ) )

        print( "instantiating the RNT" )
        THE_RNT = RNT( 4096, 1, 'desktop', PASSWORD )

        print( "instantiating the LFSR" )
        #    ( the_rnt, integer_width, prng_depth, paranoia_level )
        lfsr = LFSR( THE_RNT, INT_WIDTH, 64, 1 )

        while True :
            BIN_VECTOR[ 0 ] = lfsr.next( 64, 1 )
            BIN_VECTOR.tofile( FP )


