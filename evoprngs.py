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
0.2 - 20180516 - started the versioning again so I can keep track of the
small changes in the 'search' dieharder series of experiments on
MultAdd02.
02.1.1 20180516 -- added the 03 version of MultiplyAdd
02.1.2 20180516 -- added the 04 version of MultiplyAdd to test
                   dieharder's ability to detect non-randomness
02.1.3 20180517 -- fixed the 04 version of MultiplyAdd. The fold
eliminated the effect of the intentional flaw, a good experimental
result in itself.
02.1.4 20180517 -- increased the number of working biases to 4 in the
04 version of MultiplyAdd. Run 3 only had one working, was identical to
2. And, in fact, it didn't fail.
"""

import os
import sys
import getopt
import time
import random
import traceback
import evoutils
from array        import array
from evofolds     import FoldInteger
from evohashes    import HASHES
from evoprngutils import generate_constants
from evornt       import RNT
from evoprimes    import get_next_higher_prime

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

    It is the responsibility of the caller of this general PRNG
    interface to have organized these values to allow a reliable
    CryptoPRNG to be formed.
    
    This level just hides the details of each instantiated PRNG behind
    an call to a function, another list to scramble and another layer of
    logic that is difficult to move into hardware. (understated, that.)

    This is one of the layers where components can be evaluated by
    Dieharder tests, so we know all these are individually excellent
    PRNGs.

    Solid mechanisms connecting solid components and solid process, all
    built on solid theory, in handling your secrets produce secrecy,
    nothing less will do.

    I believe that password attacks were the last hurrah of modern
    cryptography. I mean, just thinking about it, from what I think I
    have learned, writing solid crypto systems is falling-off-a-log
    easy, tho doing it as a secure piece of software needs special skills
    (and this program does NOT have those characteristics, I have given
    no thought to dealing with passwords in a way to preserve their
    secrecy while in use, for example).
 
    But performance seems to me the limiting factor. Absolutely not an
    issue even for a simple smartphone these days, tho it may take
    a few 10s of seconds..
    """

    def __init__( self ) :
        """
        Only the index is necessary, all the other stuff is passthrough.

        Thus function only knows enough to call the next PRNG in the
        list, in round-robin order.
        
        """
        self.prng_functions       = [ LCG, KnuthMMIX, KnuthNewLib,
                                      LongPeriod5, LongPeriod256,
                                      CMWC4096, MultiplyAdd00,
                                      MultiplyAdd01, MultiplyAdd03
                                    ]
        self.next_prng_index      = 0

        # not useless, calculated entropy can only be known to an opponent
        # if they also have the random number table
        the_rnt = RNT( 4096, "internal password", "desktop", 1 )

        the_rnt.scramble_list( self.prng_functions )

    def name( self ) :
        """
        Returns the string name, debugging.
        """
        return "PRNGs\n"

    def next( self, the_rnt, integer_width, prng_depth, paranoia_level,
              multiplier, constant, lag ) :
        """
        Instantiates and returns the next PRNG.
        """
        this_prng = self.prng_functions[ self.next_prng_index ]
        self.next_prng_index += 1
        self.next_prng_index %= len( self.prng_functions )

        return  this_prng( the_rnt, integer_width, prng_depth, paranoia_level,
                            multiplier, constant, lag )

#
# These first few 'classical' PRNGs pass Dieharder 'out of the box'
# The goal of my versions is not just to pass Dieharder, but to do so
# while hiding the internal mechanism.
# I wouldn't need to do this, as none of the functions here are directy
# used in encrypting or decrypting, but the goal is to have every
# element at every level hide its internal workings, it's state, so as
# to not allow any leakage of any internal state.
#
class KnuthMMIX() :
    """
    Linear congruential specified by Knuth in his MMIX.
    """

    def __init__( self, the_rnt, integer_width, prng_depth, paranoia_level,
                  multiplier, constant, lag ) :
        """
        """
        # crypto functions depend upon the RNT having been fully initialized
        assert the_rnt.password_hash != 0
        self.the_rnt        = the_rnt
        self.integer_width  = integer_width
        self.integer_mask   = ( 1 << integer_width ) - 1
        self.paranoia_level = paranoia_level
        self.the_fold       = FoldInteger( )

        self.seed = the_rnt.next_random_value( self.the_rnt.password_hash,
                                            integer_width )

    def name( self ) :
        """
        Returns the string name, debugging.
        """
        return "KnuthMMIX\n"

    def next( self, bit_width, steps ) :
        """
        returns a bit-width integer
        """
        return_value = 0
        return_limit = 1 << bit_width * 2
        shift_width    = int( bit_width / ( 4 *  steps * self.paranoia_level))+1
        for _ in range( steps * self.paranoia_level ) :
            while return_value < return_limit :
                return_value <<= shift_width
                self.seed = 6364136223846793005 * \
                    self.seed + 1442695040888963407
                return_value ^= self.seed
                self.seed &= self.integer_mask

            return_value ^= ( self.seed << 16 ) 

        return self.the_fold.fold_it( return_value, bit_width )

class KnuthNewLib() :
    """
    Linear congruential specified by Knuth in his MMIX + NewLibMusl
    """

    def __init__( self, the_rnt, integer_width, prng_depth, paranoia_level,
                  multiplier, constant, lag ) :
        """
        """
        # crypto functions depend upon the RNT having been fully initialized
        assert the_rnt.password_hash != 0
        self.the_rnt        = the_rnt
        self.integer_width  = integer_width
        self.integer_mask   = ( 1 << integer_width ) - 1
        self.paranoia_level = paranoia_level
        self.the_fold       = FoldInteger( )

        self.seed0 = the_rnt.next_random_value( self.the_rnt.password_hash,
                                            integer_width )
        self.seed1 = the_rnt.next_random_value( self.the_rnt.password_hash,
                                            integer_width )
        self.next( integer_width, 40 )  # initial spin of the wheel

    def name( self ) :
        """
        Returns the string name, debugging.
        """
        return "KnuthNewLib\n"

    def next( self, bit_width, steps ) :
        """
        returns a bit-width integer
        """
        return_value = 0
        # left shift produces very large #s if paranoid and initial spins
        shift_width    = int( bit_width / ( 4 *  steps * self.paranoia_level))+1
        return_limit = 1 << bit_width * 2
        for _ in range( steps * self.paranoia_level ) :
            while return_value < return_limit :
                # seed0 is stepped 1/2 rate of seed2, same progression.
                # That makes weird sense, the cycle will be very long,
                # and if one is random, so is the other. Assumes both
                # halves of the word are equally random.
                self.seed0 = 6364136223846793005 * \
                    self.seed0 + 1442695040888963407
                self.seed1 = 6364136223846793005 * self.seed1 + 1
                return_value ^= self.seed0

                return_value ^= \
                         ( self.seed1 & 0x0000FFFFFFFF0000 ) >> shift_width
                return_value <<= shift_width
                self.seed1 = 6364136223846793005 * self.seed1 + 1
                return_value += ( self.seed1 & 0xFFFFFFFF00000000 ) >> 32

                self.seed0 &= self.integer_mask
                self.seed1 &= self.integer_mask
            # the usual masking to bit_width would leave nothing to be
            # folded
            return_value &= return_limit >> shift_width * 4 

        return self.the_fold.fold_it( self.seed0 ^ return_value, bit_width )

class LongPeriod5() :
    """
    http://school.anhb.uwa.edu.au/personalpages/kwessen/shared/Marsaglia03.html
    Here is an example with k=5, period about 2^160, one of the fastest long
    period RNGs, returns more than 120 million random 32-bit integers/second
    (1.8MHz CPU), seems to pass all tests:
    """

    def __init__( self, the_rnt, integer_width, prng_depth, paranoia_level,
                  multiplier, constant, lag ) :
        """
        """
        # crypto functions depend upon the RNT having been fully initialized
        assert the_rnt.password_hash != 0

        self.the_rnt        = the_rnt
        self.integer_width  = integer_width
        self.integer_mask   = ( 1 << integer_width ) - 1
        self.paranoia_level = paranoia_level
        self.the_fold       = FoldInteger( )

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

    def name( self ) :
        """
        Returns the string name, debugging.
        """
        return "LongPeriod5\n"

    def next( self, bit_width, steps ) :
        """
        steps the algorithm to compute new prngs, returns a bit-width integer
        """
        return_value = 0
        return_limit = 1 << bit_width * 2
        shift_width    = int( bit_width / ( 4 *  steps * self.paranoia_level))+1
        for _ in range( steps * self.paranoia_level ) :
            while return_value < return_limit :
                return_value <<= shift_width
                t = (self.x ^ ( self.x >> 7 ) )
                self.x  = self.y
                self.y  = self.z
                self.z  = self.w
                self.w  = self.v
                self.v  = ( self.v ^ ( self.v << 6 ) ) ^ ( t ^ ( t << 13 ) )
                self.v &= self.integer_mask

                return_value ^= ( self.y + self.y + 1 ) * self.v 

            return_value = self.the_fold.fold_it( return_value, bit_width )

        return return_value

class LongPeriod256() :
    """
    Another example has k=257, period about 2^8222. Uses a static array
    Q[256] and an initial carry 'c', the Q array filled with 256 random
    32-bit integers in the calling program and an initial carry c<809430660
    for the multiply-with-carry operation. It is very fast and seems to pass
    all tests.
    http://school.anhb.uwa.edu.au/personalpages/kwessen/shared/Marsaglia03.html
    """
    def __init__( self, the_rnt, integer_width, prng_depth, paranoia_level,
                  multiplier, constant, lag ) :
        """
        Choose random initial c < 809430660 and 256 random 32-bit integers for
        Q[]

        static unsigned long Q[256],c=362436; 

        unsigned long MWC256(void){
            unsigned long long t,a=809430660LL;
            static unsigned char i=255;
            t=a*Q[++i]+c; c=(t>>32);
            return(Q[i]=t);      }

        Decision is whether to keep this 32-bit, ignoring the bit-width,
        or test it with 64, 128, etc. widths. I will go with the
        general, retest.
        """
        assert the_rnt.password_hash != 0

        self.the_rnt        = the_rnt
        self.integer_width  = integer_width
        self.integer_mask   = ( 1 << integer_width ) - 1
        self.paranoia_level = paranoia_level
        self.the_fold       = FoldInteger( )
        self.next_index     = 255
        self.Q = []

        entropy = self.the_rnt.password_hash
        for _ in range( 256 ) :
            entropy  = the_rnt.next_random_value( entropy, integer_width )
            entropy ^= the_rnt.next_random_value( entropy, integer_width )
            self.Q.append( entropy )

        # subtracted 660 to make sure the prime is always lower than 809430660
        self.c = get_next_higher_prime( self.the_rnt.password_hash % 809430000 )

    def name( self ) :
        """
        Returns the string name, debugging.
        """
        return "LongPeriod256\n"

    def next( self, bit_width, steps ) :
        """
        returns a bit_width integer
        """
        a_constant = 809430660

        return_value = 0
        return_limit = 1 << bit_width * 2
        shift_width    = int( bit_width / ( 4 *  steps * self.paranoia_level))+1
        for _ in range( steps * self.paranoia_level ) :
            while return_value < return_limit :
                return_value <<= shift_width
                for _ in range( steps * self.paranoia_level ) :
                    # point to the next element of the vector
                    self.next_index = ( self.next_index + 1 ) % 256

                    t  = a_constant * self.Q[ self.next_index ] + self.c
                    self.c = ( t >> 32 )

                    t &= self.integer_mask
                    self.Q[ self.next_index ] = t 

                    return_value += t

            return_value = self.the_fold.fold_it( return_value, bit_width )

        return return_value

class CMWC4096() :
    """
    Here is a complimentary-multiply-with-carry RNG with k=4097 and a
    near-record period, more than 10^33000 times as long as that of the
    Twister. (2^131104 vs. 2^19937)
    http://school.anhb.uwa.edu.au/personalpages/kwessen/shared/Marsaglia03.html

    This is closer to what I called LGC. 
    """

    def __init__( self, the_rnt, integer_width, prng_depth, paranoia_level,
                  multiplier, constant, lag ) :
        """
        """
        self.the_rnt        = the_rnt
        self.integer_width  = integer_width
        self.integer_mask   = ( 1 << integer_width ) - 1
        self.paranoia_level = paranoia_level
        self.next_index     = 4095
        self.integer_array  = []
        self.the_fold       = FoldInteger( )
        self.c = get_next_higher_prime( self.the_rnt.password_hash % 809430000 )

        entropy = self.the_rnt.password_hash
        for _ in range( 4096 ) :
            entropy += the_rnt.next_random_value( entropy, integer_width )
            self.integer_array.append( entropy & self.integer_mask )

        # subtracted 660 to make sure the prime is always lower than 809430660
        self.c = get_next_higher_prime( self.the_rnt.password_hash % 809430000 )

    def name( self ) :
        """
        Returns the string name, debugging.
        """
        return "CMWC4096\n"

    def next( self, bit_width, steps ) :
        """
        returns a bit_width integer
        """
        a_constant = 18782
        r_constant = 0xfffffffe

        return_value = 0
        return_limit = 1 << bit_width * 2
        shift_width    = int( bit_width / ( 4 * steps * self.paranoia_level)) +1
        for _ in range( steps * self.paranoia_level ) :
            while return_value < return_limit :
                return_value <<= shift_width
                self.next_index = ( self.next_index + 1 ) & 4095
                t = a_constant * self.integer_array[ self.next_index ] + \
                                                         self.c
                self.c = ( t >> 32 )
                x = t + self.c
                if x < self.c :
                    x += 1
                    self.c += 1
                self.integer_array[ self.next_index ] = r_constant - x
                self.integer_array[ self.next_index ] &= self.integer_mask

                return_value += self.integer_array[ self.next_index ]

            return_value = self.the_fold.fold_it( return_value, bit_width )

        return return_value

class LCG():
    """
    Class for a Linear Congruential Generator with parameters
    controlling space/time of running.
    """

    def __init__( self, rnt, integer_width, n_integers, paranoia_level,
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
        self.paranoia_level       = paranoia_level
        self.multiplier           = multiplier
        self.constant             = constant
        self.lag                  = lag
        self.index                = 0

        if integer_width < 64 :    # bad, so apply paranoia
            print( "integer widths less than 64 bits are prohibited!" )
            sys.exit( 0 )
                                                
        # width of the integers in the lcg_array
        self.width_in_bits        = integer_width
        self.width_in_bytes       = integer_width / 8 
        self.width_in_hexits      = self.width_in_bytes * 2
        self.total_steps          = 0
        self.max_integer_mask     = ( 1 << integer_width ) - 1

        self.integer_vector = [ 0 for _ in range( self.integer_vector_size ) ]

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

        # each LCG will be unique in these, so uniquely initialized
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
            for int_index in range( vector_index ) :
                the_hash.update( str( self.integer_vector[ int_index ] ) )

            integer_hash = the_hash.intdigest()
            integer_hash = self.the_fold.fold_it( integer_hash,
                                                  self.width_in_bits )

            xor_result ^= integer_hash
            self.integer_vector[ vector_index ] = xor_result


        # Cycle it a random number of times
        steps = self.the_rnt.next_random_value( xor_result, 
                                           self.width_in_bits ) % 32

# this complains about not being initialized properly for MA03
# because 'self.next()' calls the MA03 next, not the LCG next.
# ?? how to fix that ???
#        self.next( self.integer_width, steps )


    def name( self ) :
        """
        Returns the string name, debugging.
        """
        return "LCG\n"

    def next( self, bit_width, steps ) :
        """
        Returns the next pseudo-random bit_width value after steps of
        operation.

        lower-bit return values produce an occassional zero. I am not sure
        that is bad, but I fixed it.
        """

        return_value = 0
        all_ffs = ( 1 << bit_width ) - 1
        before_the_fold = 0 # debug
        n_steps      = steps * self.paranoia_level
        return_limit = 1 << bit_width * 2
        for _ in range( n_steps ) :
            # this algorithm has a subtle bias to '1' in the hi bit.
            while return_value < return_limit :
                return_value <<= int( self.integer_width / 4 )

                # update the next integer this cycle through
                self.index = ( self.index + 1 ) % self.integer_vector_size
                self.total_steps += 1

                # this is a step of the state machine
                lagged0_index = ( self.index + self.lag ) % \
                                  self.integer_vector_size

                new_vector_value = self.integer_vector[ lagged0_index ] * \
                                   self.multiplier + self.constant

                # the shift is crucial to prevent duplicates
                self.integer_vector[ self.index ] ^= ( new_vector_value >> 5 )\
                                                     & self.max_integer_mask

                # mask for middle bits
                return_value +=  ( new_vector_value >> \
                                   int( self.integer_width / 4 ) )

                # this is a step of the state machine
#                lagged1_index = ( self.index + self.lag + 1 ) % \
#                               self.integer_vector_size

                new_vector_value  = self.integer_vector[ lagged0_index ] * \
                                   self.multiplier + self.constant
                # overkill
#                new_vector_value ^= self.integer_vector[ lagged1_index ] * \
#                                   self.multiplier + self.constant

                # the shift is crucial to prevent duplicates
                self.integer_vector[ self.index ] ^= ( new_vector_value >> 3 )\
                                                     & self.max_integer_mask

                # mask for middle bits
                return_value +=  ( new_vector_value >> \
                                   int( self.integer_width / 4 ) )
                before_the_fold = return_value # debug
                # once in a very great while, it returns a zero.

        return_value = self.the_fold.fold_it( return_value, bit_width )

        if return_value == 0 or return_value == all_ffs :
        
            # debug from here
            # this happens for 128-bit values? and the vector does not
            # have any zeros? WTF?
            self.dump_state()
            print( "Zero or all_ffs return value" )
            print( "before_the_fold  = ", hex( before_the_fold ) )
            print( "the return_value = ", hex( return_value ) )
            print( "the_fold = ", self.the_fold )
            print( traceback.extract_stack() )
            sys.stdout.flush()
            # debug to here
            return_value = self.next( bit_width, steps )


        return return_value

    def dump_state( self ) :
        """
        Debug code
        """
        for element in self.integer_vector :
            print( hex( element ) + '\n' )

class MultiplyAdd00( LCG ) :
    """
    So I asked myself how REALLY easy it is to make a PRNG that passes
    dieharder. This works, experimentally.

    A generalization of a simple multiply-add used for testing.

    If you made the # of additional updates with different lags
    dependent upon the paranoia level, a whole new level of cycle.
    """

    def name( self ) :
        """
        Returns the string name, debugging.
        """
        return "MA00\n"

    def next( self, bit_width, steps ) :
        """
        returns a bit_width integer
        """

        return_value = 0
        return_limit = 1 << bit_width * 2
        while return_value < return_limit :
            return_value <<= 16
            for _ in range( steps * self.paranoia_level ) :
                self.index = ( self.index + 1 ) % self.integer_vector_size
                lag_index  = ( self.index - self.lag ) % \
                             self.integer_vector_size

                self.integer_vector[ self.index ] *= self.multiplier + \
                                                     self.constant
                self.integer_vector[ self.index ] += \
                                           self.integer_vector[ lag_index ] * \
                                           self.multiplier + self.constant

                self.integer_vector[ self.index ] &= self.max_integer_mask

                return_value += self.integer_vector[ self.index ]
#                print( hex( return_value ) )

        return self.the_fold.fold_it( return_value, bit_width )

class MultiplyAdd01( LCG ) :
    """
    A generalization of a simple multiply-add used for testing.

    This makes additional updates with different lags dependent upon the
    paranoia level.

    I like that, meaningfully scalable in paranoia.
    """

    def __init__( self, rnt, integer_width, n_integers, paranoia_level,
                        multiplier, constant, lag ) :

        self.lag_set = [ 1, 3, 5 ]

        LCG.__init__( self, rnt, integer_width, n_integers, paranoia_level,
                                multiplier, constant, lag )

        # Additionally need 2 more lags. The set should be primes the maximal
        # differences apart to maximize the length of any cycle.
        # So the largest that fit into 4 individual indexes
        # That means we select on the number of vector elements and
        # paranoia level.

        # these lags handle the case up to 220 integers
        
        lag_sets = [ [  1,  3,  5,  7 ], [  3,  5,  7, 11 ], [  5,  7, 11, 13 ],
                     [  7, 11, 13, 17 ], [ 11, 13, 17, 19 ], [ 13, 17, 19, 23 ],
                     [ 17, 19, 23, 29 ], [ 19, 23, 29, 31 ], [ 23, 29, 31, 41 ],
                     [ 29, 31, 41, 43 ], [ 31, 41, 43, 47 ], [ 41, 43, 47, 53 ],
                     [ 43, 47, 53, 59 ], [ 47, 53, 59, 61 ] ]

        for lag_set in lag_sets :
            if sum( lag_set ) < self.integer_vector_size :
                self.lag_set = lag_set

#        sys.stderr.write( 'lag_set = ' + str( self.lag_set ) + '\n' )
        
    def name( self ) :
        """
        Returns the string name, debugging.
        """
        return "MA01\n"

    def next( self, bit_width, steps ) :
        """
        returns a bit_width integer
        """

        return_value = 0
        return_limit = 1 << bit_width * 2
        while return_value < return_limit :
            return_value <<= 16
            for _ in range( steps * self.paranoia_level ) :
                self.index = ( self.index + 1 ) % self.integer_vector_size
                self.integer_vector[ self.index ] *= self.multiplier + \
                                                     self.constant

                for lag in self.lag_set :
                    lag_index  = ( self.index - lag ) % self.integer_vector_size
                    self.integer_vector[ self.index ] += \
                                           self.integer_vector[ lag_index ] * \
                                           self.multiplier + self.constant

                self.integer_vector[ self.index ] &= self.max_integer_mask

                return_value += self.integer_vector[ self.index ]

        return self.the_fold.fold_it( return_value, bit_width )

class MultiplyAdd02( MultiplyAdd01 ) :
    """
    A generalization of a simple multiply-add used for testing.

    This makes additional updates with different lags dependent upon the
    paranoia level. This version adds a different shift to each update.

    Also, I have been skimpy on the vector size. Memory costs nil until
    we overflow the cache, which is in MBs in all current cores, even
    smartphones. Large vectors don't cost processing time.

    So, the rule is to assume large vectors with more lags, more variations
    on the next() function, and keep all lesser versions?

    Now, I need to test at least 100 times against dieharder to be sure
    nothing comes up as a short cycle or non-random cycle.  At that point,
    we have a 'good enough' probability such that the chances of a non-random
    Crypto PRNG using 5 or more such 'good enough' PRNGs is seriously
    small, as they should be random because randomness is produced by
    their addition and also have a cycle that is an exponential of the
    number in the CryptoPRNG set of lesser PRNGs.

    Abstracting this, variables are the left-shift of return_value, how
    many integers in vector, how many constants are used, how many
    constants and variables are used to update a value, how
    those are combined and how many updates are done per random value
    returned.

    Below is a test I ran through dieharder. 722 separate separate pairs
    of big-small primes were tested through 481 dieharder tests. Every
    test checked every new value to see if it was the first value
    produced by the multiply-add of that random pair, a test of whether
    they loop. I need to add keep and test the values at
    10K, etc points also, but that will slow things down.
    
    12 produced 'weak', none failed, the rested PASSED. This is 2.5% 'WEAK'
    rate. Not good, really, 2+X the 1% that is expected in these random
    variables. OTOH, not that large a sample, either.

    But still significant experimental results : this version of the
    code comes close, probably acceptably close, to random and uses a
    very simple mechanism to do so. It is a design that lets you trade
    off the usual CS resources, computation and memory and measure the
    result.

    Those counts were for overnight. Knowing this I can do experiments
    with vector sizes, bits in integers, paranoia levels. The ultimate
    measure would be the amount of randomness per watt of expended
    energy 8). 'Amount of randomness' has no meaning, so 'passes
    dieharder producing 64-bit pseudorandom integers at the highest rate
    / watt' is a meaningful measure.

    BTW: another version of initialization would develop other pairs of
    multiply-add constants. There are another infinitude of ways to use
    those to make cycles very long. But, I think cycles are not
    something to worry about in this crypto design. Any that might
    happen in a PRNG will be very long and Crypto PRNGs are inherently
    immune to such flaws.
    
    8.94e+04 - slow. 
    So the experiments should be on paranoia level vs randomness, how
    much that left shift of the return value is, etc.

    I put the max count of 64-bit values at 1M, so every dieharder test
    'sees' 30 or so different sets of multiplier and addition values.
    """

    def name( self ) :
        """
        Returns the string name, debugging.
        """
        return "MA02\n"

    def next( self, bit_width, steps ) :
        """
        returns a bit_width integer
        """

        return_value = 0
        return_limit = 1 << bit_width * 2
        for _ in range( steps ) :
            while return_value < return_limit :
                return_value <<= 16
                self.index = ( self.index + 1 ) % self.integer_vector_size
                self.integer_vector[ self.index ] *= self.multiplier + \
                                                     self.constant
                # paranoia level controls the loop
                for lag in self.lag_set[ 0 : self.paranoia_level ] :
                    lag_index  = ( self.index + lag ) % self.integer_vector_size
                    a_temp = self.integer_vector[ lag_index ] * \
                                           self.multiplier + self.constant
                    # shifting by the lag is desirable complexity
                    self.integer_vector[ self.index ] += a_temp >> lag

                self.integer_vector[ self.index ] &= self.max_integer_mask

                return_value += self.integer_vector[ self.index ]

        return self.the_fold.fold_it( return_value, bit_width )

class MultiplyAdd03( MultiplyAdd02 ) :
    """
    A generalization of a simple multiply-add used for testing.

    This makes additional updates with different lags dependent upon the
    paranoia levels and also use separate multiplier-add combinations.

    I like that, meaningfully scalable in paranoia. Note there is no
    reason for the multiplier and addition values to be paired, they
    only need be relatively prime, and are in fact prime in this code.
    So how to make that evolve and have the largest possible primes do that?
    There need only be 2, so ...

    This design has the multiplier and addition indexes incremented with
    different prime numbers, so permanently out of step with each other
    and the 'main' index and the lags. No cycles! (Except in the case of
    the vector of integers being too small, where there will be an overlap,
    there not being enough primes down at the bottom for separation.
    So don't use vector sizes less than 301.

    I put the max count of 64-bit values at 1M, so every dieharder test
    'sees' 30 or so different sets of multiplier and addition values.
    For MA03, that is sets for multiplier addition the same size as the
    integer array. I expect that the dieharder tests are sensitive
    enough to detect any serious problems in 1 million out of 30 million
    random numbers. I should test that.

    I have been testing to be sure all these pairs of prime numbers
    produce randomness. Turns out, dieharder isn't sensitive enough to
    be sure, but out of 1.8M pairs, only 14 were not unique, so the
    basic mechanism is OK and produces PRNs acceptable to dieharder.

    $ wc lew.sorted           8284438   8284438 169830979 lew.sorted
    $ wc lew.sorted_unique    8284370   8284370 169829571 lew.sorted_unique

    68 / 8,284,438 random integers is 8 in a million collisions 

    The range 0 1 << 48 bits is 256*1024*1024*1024*1024
    of which I used only 40%. Now I am stuck on how to figure lottery odds.
    .4 * 256T / 8,284,438 = 13,590,540

    """

    def __init__( self, rnt, integer_width, n_integers, paranoia_level,
                        multiplier, addition, lag ) :

        # Wow, who could have guessed at the interactions in these
        # initializations?
        # Easier to copy the code?
        # indexes should be different small prime values, doesn't matter
        self.n_integers = n_integers
        self.mult_index = 1
        self.add_index  = 1
        self.counter    = 0

        MultiplyAdd02.__init__( self, rnt, integer_width, n_integers,
                                paranoia_level, multiplier, addition, lag )

        # from the integer width, develop the appropriate series of
        # prime numbers, one multiplier and one addition for each of
        # n_integers
        self.multipliers = []
        self.additions   = []

        # copied this code from evocprngs.py, PrngCrypto. Should common
        # it out in a function. Pass in the vector 
        # get back the two filled lists.
        # initialized, but no update is sort of OK
#        hashes = HASHES( rnt, self.integer_width, self.n_integers )
#        the_hash = hashes.next()
#        hash_of_state = the_hash.intdigest()

        # an additional bit of randomness
#        folded_hash_of_state = self.the_fold.fold_it( hash_of_state,
#                                            integer_width )
#        entropy_bits = folded_hash_of_state ^ rnt.password_hash

        constant_generator = generate_constants( rnt, self.integer_width, 
                                                 self.n_integers )
        for _ in range( n_integers ) :
            multiplier, addition, lag, delta = next( constant_generator )
            self.multipliers.append( multiplier )
            self.additions.append(   addition )


    def name( self ) :
        """
        Returns the string name, debugging.
        """
        return "MA03\n"


    def next( self, bit_width, steps ) :
        """
        returns a bit_width integer
        """

        return_value = 0
        return_limit = 1 << bit_width * 2
        for _ in range( steps ) :
            while return_value < return_limit :
                return_value = return_value << int( bit_width / 4 )
                self.index      = ( self.index      + 1 ) % \
                                    self.integer_vector_size
                self.mult_index = ( self.mult_index + 3 ) % \
                                    self.n_integers
                self.add_index  = ( self.add_index  + 5 ) % \
                                    self.n_integers

                self.integer_vector[ self.index ] *= \
                                            self.multipliers[ self.mult_index ]
                self.integer_vector[ self.index ] += \
                                               self.additions[ self.add_index ]

                # paranoia level controls the loop
                for lag in self.lag_set[ 0 : self.paranoia_level ] :
                    lag_index  = ( self.index + lag ) % self.integer_vector_size
                    self.mult_index = ( self.mult_index + 3 ) % \
                                        self.n_integers
                    self.add_index  = ( self.add_index  + 5 ) % \
                                        self.n_integers

                    a_temp = self.integer_vector[ lag_index ] * \
                             self.multipliers[ self.mult_index ] + \
                             self.additions[   self.add_index ]

                    # shifting by the lag is desirable complexity
                    self.integer_vector[ self.index ] += a_temp >> lag

                self.integer_vector[ self.index ] &= self.max_integer_mask

                return_value += self.integer_vector[ self.index ]

        return self.the_fold.fold_it( return_value, bit_width )

class MultiplyAdd04( MultiplyAdd03 ) :
    """
    This is MA03 with a regularity to see what dieharder can catch.
    """

    def name( self ) :
        """
        Returns the string name, debugging.
        """
        return "MA04\n"

    def next( self, bit_width, steps ) :
        """
        returns a biased bit_width integer intended to fail dieharder.

        First attempt was modifying a_temp inside the lag loop. The flaw
        was 16X more 0xFF values in the low byte than a random stream of
        64-bit integers would have had. That had no effect in the first 25
        or so dieharder tests, so the important effect is that the fold
        eliminated the excessive regularity. Maybe the bit tests later
        would have caught it? Important to put them all through all the
        tests, it seems, there are so many ways to be non-random, to
        impose signal on noise. Literally, some Cantor infinity of them,
        the reason NSA cracks no more ciphers when someone gets this
        right.  Seems like they already have, why don't we all know
        that?

        Second attempt modified the return integer, same change.  That
        is picked up by birthdays, none of the others. Dieharder is not
        universally sensitive, as I certainly should have expected.
        So next overdo the proportion of 0x00 in the bottom byte same as
        I did for the 0xFF. The pattern should catch some stat's
        attention.
        """


        return_value = 0
        return_limit = 1 << bit_width * 2
        while return_value < return_limit :
            for _ in range( steps ) :
                return_value    <<= 32
                self.index      = ( self.index      + 1 ) % \
                                    self.integer_vector_size
                self.mult_index = ( self.mult_index + 3 ) % \
                                    self.integer_vector_size
                self.add_index  = ( self.add_index  + 5 ) % \
                                    self.integer_vector_size

                self.integer_vector[ self.index ] *= \
                                            self.multipliers[ self.mult_index ]
                self.integer_vector[ self.index ] += \
                                               self.additions[ self.add_index ]

                # paranoia level controls the loop
                for lag in self.lag_set[ 0 : self.paranoia_level ] :
                    lag_index  = ( self.index + lag ) % self.integer_vector_size
                    self.mult_index = ( self.mult_index + 3 ) % \
                                        self.integer_vector_size
                    self.add_index  = ( self.add_index  + 5 ) % \
                                        self.integer_vector_size

                    a_temp = self.integer_vector[ lag_index ] * \
                             self.multipliers[ self.mult_index ] + \
                             self.additions[   self.add_index ]

                    # shifting by the lag is desirable complexity
                    self.integer_vector[ self.index ] += a_temp >> lag

                self.integer_vector[ self.index ] &= self.max_integer_mask

                return_value += self.integer_vector[ self.index ]

        # modifying a_temp above did not make it non-random!
        return_value = self.the_fold.fold_it( return_value, bit_width )

        self.counter += 1
        if self.counter % 4 == 0 :
            return_value = return_value & 0xffffffffffffff00 # too many
                                                             # 0s in low byte
        return return_value

        
def byte_rate( the_function, result_width, n_values ) :
    """
    The_function is one of the crypto or PRNG functions with a 'next'.
    Result_width is the desired width of the result of that function in bits.
    N is the number of results to compute before returning bytes/second.
    """
    print( "the_function = ", the_function )
    beginning_time = int( time.time() )
    steps = 1
    for _ in range( n_values ) :
        the_function.next( result_width, steps )

    elapsed_time = int( time.time() ) - beginning_time
    if elapsed_time == 0 :
        elapsed_time = 1

    return ( n_values * ( result_width / 8 ) ) / elapsed_time

#SINGLE_PROGRAM_TO_HERE

def usage() :
    """
    This provides 'help' and other usage information.
    """
    usage_info = """
        --help  Invokes this usage function
        -h      Invokes this usage function

        --int_width < the_width >
        -i specifies width of integers used in the PRNGs

        --test  < the test > adds a test to be executed. Current tests are:
            'big_distribution'    prints 64M prn bytes to std out
            'medium_distribution' prints 16M prn bytes to std out
            'small_distribution'  prints 4096 prn bytes to std out
            'code'  encodes, then decodes plain text
    """
    print( usage_info )


# main begins here, generally test code for the module.

if __name__ == "__main__" :

    SHORT_ARGS = "hi=p=l=t=v="
    LONG_ARGS  = [  'help' , 'int_width=', 'password=', 'paranoia=', 'test=',
                 'vec_depth=' ]

# to track the dieharder tests
    sys.stderr.write( '# ' + __filename__ + ' : ' + __version__ + ' : ' +
                      str( sys.argv[ 1 : ] ) + '\n' )

    PASSWORD  = ''
    INT_WIDTH = None
    VEC_DEPTH = None
    PARANOIA  = None
    TEST_LIST = []      # list of tests to execute
    try :
        OPTS, ARGS = getopt.getopt( sys.argv[ 1 : ], SHORT_ARGS, LONG_ARGS )

    except getopt.GetoptError as err :
        print( "getopt.GetoptError = ", err )
        sys.exit( -2 )

    for o, a in OPTS :
        print( o, a )
        if o in ( "--help" ) or o in ( "-h" ) :
            usage()
            sys.exit( -2 )

        if o in ( "--test") or o in ( "-t" ) :
            TEST_LIST.append( a )

        if o in ( "--int_width" ) or o in ( "-i" ) :
            INT_WIDTH = int( a )

        if o in ( "--paranoia" ) or o in ( "-l" ) :
            PARANOIA = int( a )

        if o in ( "--vec_depth" ) or o in ( "-v" ) :
            VEC_DEPTH = int( a )

        if o in ( "--password") or o in ( "-p" ) :
            PASSWORD = a

    # over-ride these in the individual test if necessary
    if INT_WIDTH :
        INTEGER_WIDTH = INT_WIDTH
    else :
        INTEGER_WIDTH = 64  #default

    if VEC_DEPTH :
        VECTOR_DEPTH = VEC_DEPTH
    else :
        VECTOR_DEPTH = 31   # default

    if PARANOIA :
        PARANOIA_LEVEL = PARANOIA
    else :
        PARANOIA_LEVEL = 1  # default


    MAX_INTEGER   = ( 1 << INTEGER_WIDTH ) - random.getrandbits( 50 )
    MULTIPLIER    = get_next_higher_prime( int( ( MAX_INTEGER * 4 ) / 5 ) )
    ADDITION      = get_next_higher_prime( int( ( MAX_INTEGER * 1 ) / 5 ) )
    LAG           = 19

    DIEHARDER_MAX_INTEGER   = ( 1 << 64 ) - 1

    # need a random factor to prevent repeating pseudo-random sequences
    random.seed()

    PASSWORD += hex( random.getrandbits( 128 ) )
    THE_RNT = RNT( 4096, PASSWORD, 'desktop', 1 )
    BIN_VECTOR = array( 'L' )
    BIN_VECTOR.append( 0 )
    SO = os.fdopen( sys.stdout.fileno(), 'wb' )

    if 'PRNGs' in TEST_LIST :
        # it is the responsibility of the caller of a general PRNG to
        # have organized these values to allow a reliable CryptoPRNG to
        # be formed. This level just hides the details of each one
        # behind a function indirect call.

        THE_PRNGS = PRNGs()

        random.seed()       # includes local entropy, so this doesn't repeat

        PASSPHRASE = PASSWORD + hex( random.getrandbits( 128 ) )

        # the_rnt, integer_width, prng_depth, paranoia_level,
        # multiplier, constant, lag

        for INTEGER_WIDTH in [ 64, 128, 256 ] :
            for INT_VECTOR_DEPTH in [ 7, 17, 29, 43 ] :
                for PARANOIA_LEVEL in [ 1, 2, 3 ] :
                    for _ in range( 20 ) :

                        MAX_INTEGER = ( 1 << INTEGER_WIDTH ) - \
                                        random.getrandbits( 36 )

                        BIG_PRIME   = get_next_higher_prime(
                                                        int((MAX_INTEGER*4)/5))
                        SMALL_PRIME = get_next_higher_prime(
                                                        int((MAX_INTEGER*1)/5))

                        LAG = INT_VECTOR_DEPTH >> 1

                        
                        THIS_PRNG = THE_PRNGS.next( THE_RNT, INTEGER_WIDTH,
                                        INT_VECTOR_DEPTH, PARANOIA_LEVEL,
                                        BIG_PRIME, SMALL_PRIME, LAG )

                        # byte_rate( the_function, result_width, n_values )
                        print( str( INTEGER_WIDTH ) + ' : ' +
                               str( INT_VECTOR_DEPTH ) + ' : ' +
                               str( PARANOIA_LEVEL ) + ' : ' +
                         str( byte_rate( THIS_PRNG, INTEGER_WIDTH, 1000000 ) ) )


    if 'lcg' in TEST_LIST :
        MAX_INTEGER   = ( 1 << INTEGER_WIDTH ) - 1

        MAX_INTEGER   = ( 1 << INTEGER_WIDTH ) - random.getrandbits( 36 )

        BIG_PRIME     = get_next_higher_prime( int( ( MAX_INTEGER * 4 ) / 5 ) )
        SMALL_PRIME   = get_next_higher_prime( int( ( MAX_INTEGER * 1 ) / 5 ) )

            #( seed, INTEGER_WIDTH, n_integers, multiplier, constant, lag ):
        THE_PRNG = LCG( THE_RNT, INTEGER_WIDTH, VECTOR_DEPTH, 
                        PARANOIA_LEVEL, BIG_PRIME, SMALL_PRIME, LAG ) 
        while True :
            THE_RANDOM_NUMBER = THE_PRNG.next( 64, 1 )

            BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER 
            BIN_VECTOR.tofile( SO )
#            print( hex( THE_RANDOM_NUMBER ) )

    if 'newlib' in TEST_LIST :
        # 8.17e+05 rands / second, very slow

        # ( self, the_rnt, integer_width, prng_depth, paranoia_level )
        THE_PRNG = KnuthNewLib( THE_RNT, INTEGER_WIDTH, VECTOR_DEPTH,
                                PARANOIA_LEVEL, None, None, None ) 

        while True :

            THE_RANDOM_NUMBER = THE_PRNG.next( 64, 1 )
            BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER
            BIN_VECTOR.tofile( SO )
#            print( hex( THE_RANDOM_NUMBER ) )

    if 'knuth' in TEST_LIST :
        # 8.17e+05 rands / second, very slow
        INTEGER_WIDTH = 64
        VECTOR_DEPTH  = 31

        # ( self, the_rnt, integer_width, prng_depth, paranoia_level )
        THE_PRNG = KnuthMMIX( THE_RNT, INTEGER_WIDTH, VECTOR_DEPTH,
                              PARANOIA_LEVEL, None, None, None ) 

        while True :

            THE_RANDOM_NUMBER = THE_PRNG.next( 64, 1 )
            BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER
            BIN_VECTOR.tofile( SO )
#            print( hex( THE_RANDOM_NUMBER ) )

    if 'lp5' in TEST_LIST :
        # I have generalized these, need to test as 64- and 128-bit widths
        # 8.17e+05 rands / second, very slow

        # ( self, the_rnt, integer_width, prng_depth, paranoia_level )
        THE_PRNG = LongPeriod5( THE_RNT, INTEGER_WIDTH, VECTOR_DEPTH,
                                PARANOIA_LEVEL, None, None, None ) 

        while True :
            if INTEGER_WIDTH == 32 :
                RN0 = THE_PRNG.next( 32, 1 )
                RN1 = THE_PRNG.next( 32, 1 )
                THE_RANDOM_NUMBER  = RN0 << 32
                THE_RANDOM_NUMBER += RN1
                THE_RANDOM_NUMBER &= ( 1 << 64 ) - 1
            else :
                THE_RANDOM_NUMBER = THE_PRNG.next( 64, PARANOIA_LEVEL )

            BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER
            BIN_VECTOR.tofile( SO )
#            print( hex( THE_RANDOM_NUMBER ) )

    if 'lp256' in TEST_LIST :
        # I have generalized these, need to test as 64- and 128-bit widths
        # 8.17e+05 rands / second, very slow

        # ( self, the_rnt, integer_width, prng_depth, paranoia_level )
        THE_PRNG = LongPeriod256( THE_RNT, INTEGER_WIDTH, VECTOR_DEPTH,
                                  PARANOIA_LEVEL, MULTIPLIER, ADDITION,
                                  LAG ) 

        while True :
            if INTEGER_WIDTH == 32 :
                RN0 = THE_PRNG.next( 32, PARANOIA_LEVEL )
                RN1 = THE_PRNG.next( 32, PARANOIA_LEVEL )
                THE_RANDOM_NUMBER  = RN0 << 32
                THE_RANDOM_NUMBER += RN1
                THE_RANDOM_NUMBER &= ( 1 << 64 ) - 1
            else :
                THE_RANDOM_NUMBER = THE_PRNG.next( 64, PARANOIA_LEVEL )

            BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER
            BIN_VECTOR.tofile( SO )
#            print( hex( THE_RANDOM_NUMBER ) )

    if 'cmwc4096' in TEST_LIST :
        # 8.17e+05 rands / second, very slow

        # ( self, the_rnt, integer_width, prng_depth, paranoia_level )
        THE_PRNG = CMWC4096( THE_RNT, INTEGER_WIDTH, VECTOR_DEPTH,
                             PARANOIA_LEVEL, MULTIPLIER, ADDITION, LAG ) 

        while True :
            if INTEGER_WIDTH == 32 :
                RN0 = THE_PRNG.next( 32, PARANOIA_LEVEL )
                RN1 = THE_PRNG.next( 32, PARANOIA_LEVEL )
                THE_RANDOM_NUMBER  = RN0 << 32
                THE_RANDOM_NUMBER += RN1
                THE_RANDOM_NUMBER &= ( 1 << 64 ) - 1
            else :
                THE_RANDOM_NUMBER = THE_PRNG.next( 64, PARANOIA_LEVEL )

            BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER
            BIN_VECTOR.tofile( SO )
#            print( hex( THE_RANDOM_NUMBER ) )

    if 'search' in TEST_LIST :
        # Test random pairs of multiplier/constants in a simple
        # multiply-add PRNG, all primes. check to see if they pass
        # birthdays.

        # this is the python side of a test of what proportion of pairs
        # big/small primes produce random number strings according to
        # dieharder. I need to test at least 100 pairs to be sure the
        # failure rate is low enough.
        INTEGER_WIDTH  = 64
        VECTOR_DEPTH   = 373    # a prime bigger than any sum of lags
        LAG            = 19
        PARANOIA_LEVEL = 3

        sys.stderr.write( "Search : int width = " + str( INTEGER_WIDTH ) + '\n')
        sys.stderr.write( "Search : vec depth = " + str( VECTOR_DEPTH  ) + '\n')
        sys.stderr.write( "Search : lag       = " + str( LAG           ) + '\n')
        sys.stderr.write( "Search : paranoia  = " + str( PARANOIA_LEVEL) + '\n')

        
        SWITCH = 0
        while True :

            MAX_INTEGER   = ( 1 << INTEGER_WIDTH ) - random.getrandbits( 48 )

            BIG_PRIME     = get_next_higher_prime(
                                                int( ( MAX_INTEGER * 4 ) / 5 ) )
            SMALL_PRIME   = get_next_higher_prime(
                                                int( ( MAX_INTEGER * 1 ) / 5 ) )

            sys.stderr.write( 'search : ' + hex( BIG_PRIME ) + ' : ' +
                                            hex( SMALL_PRIME ) + '\n' )

            # 1/16 with 4X the number of FFs in the low byte of the
            # integer produced a weak birthdays, passed operm5
            if SWITCH & 0x0F :      # one of 16 produces flawed ints
                THE_PRNG = MultiplyAdd03( THE_RNT, INTEGER_WIDTH, VECTOR_DEPTH,
                                 PARANOIA_LEVEL, BIG_PRIME, SMALL_PRIME, LAG ) 
            else :
                sys.stderr.write( "MA04" )
                THE_PRNG = MultiplyAdd04( THE_RNT, INTEGER_WIDTH, VECTOR_DEPTH,
                                 PARANOIA_LEVEL, BIG_PRIME, SMALL_PRIME, LAG ) 

            FIRST_RANDOM_NUMBER = THE_PRNG.next( INTEGER_WIDTH, 1 )

            CYCLE_COUNT = 0
            SWITCH      += 1
            while CYCLE_COUNT < 10000000 :
                THE_RANDOM_NUMBER = THE_PRNG.next( INTEGER_WIDTH, 1 )

                if THE_RANDOM_NUMBER == FIRST_RANDOM_NUMBER :
                    sys.stderr.write ( "!!!FAIL !!! Cycle at : ", CYCLE_COUNT,
                                        THE_RANDOM_NUMBER )
                    sys.exit( 0 )

                BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER
                BIN_VECTOR.tofile( SO )
                CYCLE_COUNT += 1
#            print( hex( THE_RANDOM_NUMBER ) )
