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
0.2 - 20180517 - Began working through these again, writing the
next-more general ensemble.

TODO :
    write the CPRNG that uses a randomly-selected ensemble of PRNGs.
"""

import os
import sys
import getopt
import random
import struct
import array
import evoutils
from evofolds     import FoldInteger
from evohashes    import HASHES
from evoprngutils import generate_constants
from evornt       import RNT
from evoprimes    import get_next_higher_prime
from evoprngs     import PRNGs, LCG, byte_rate
from evoutils     import VERBOSITY_LEVEL, DEBUG_FD, debug, \
                         close_files_and_exit, print_stacktrace, \
                         print_stacktrace_exit


#from evochat   import LOG_FD

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

    All lists are scrambled in the evocrypt initialization, of course.

    This is also the point at which policies are translated to mechanism,
    presenting a simpler interface to the higher levels.
    System_type is at least 'big', 'desktop', 'laptop', 'cellphone'
    Paranoia_level chooses levels within those, at least 1, 2, 3, and 4,
    all I implement here.

    Other uses could be standard selections for 'jim', or ... because
    both sides have to be using the same choices, or you can't
    communicate.
    """
    # this returns tuples of n_prngs, integer_width, 'vector_size'
    # This is easily changed or extended without touching the code.
    # But this is vast overkill.

    # The basics of information processing mandates that folding such
    # large integers down to 64-bits hides the mechanism producing the
    # PRNG extremely well. That is in addition to the opacifying mechanism
    # of one PRNG choosing bits from an ensemble of others to make up the
    # CryptoPRNG. After the # of subsidiary PRNGs is > than 1 + the
    # number of bits in the required output (normally a byte), the
    # excess are just a larger state to be determined by an attacker.

    system_paranoia = { 
        'big'        : { 1 : ( 19, 256, 31 ),
                         2 : ( 31, 256, 41 ),
                         3 : ( 41, 512, 97 ),
                         4 : ( 79, 512, 97 )
                       },
        'desktop'    : { 1 : ( 19, 128, 31 ),
                         2 : ( 29, 128, 37 ),
                         3 : ( 37, 128, 53 ),
                         4 : ( 53, 128, 79 )
                       },
        'laptop'     : { 1 : ( 17, 128, 29 ),
                         2 : ( 19, 128, 31 ),
                         3 : ( 37, 128, 43 ),
                         4 : ( 47, 128, 67 )
                       },
        'cellphone'  : { 1 : ( 11,  64, 17 ),
                         2 : ( 13,  64, 19 ),
                         3 : ( 23,  64, 31 ),
                         4 : ( 31,  64, 37 )
                       }
                     }

    def __init__( self, passphrase, system_type, paranoia_level ) :
        """
        """

        self.system_type       = system_type
        self.paranoia_level    = paranoia_level
        self.n_prngs, self.integer_width, self.vector_depth = \
            self.system_paranoia[ system_type ][ paranoia_level ]

        self.crypto_functions = [ LcgCrypto, HashCrypto, PrngCrypto ]
        self.next_crypto_index = 0

        # instantiate a random number table
        # hard code desired RNT bytes and paranoia level for now
        # because it is passed everywhere, I am using it to pass the
        # paranoia_level and sysem type
        self.the_rnt           = RNT( 4096, passphrase, system_type,
                                      paranoia_level )

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
                             self.integer_width, self.vector_depth,
                             self.paranoia_level )

class LcgCrypto() :
    """
    Uses a set of LCGs to produce a crypto-quality pseudo-random number.

    Algorithm is to use N LCGs, with the last LCG selecting the particular
    bits from the others.

    This uses randomly chosen primes for the two constants, and
    increasing primes for the lags to produce the longest cycles.

    I don't know where I got this algorithm, and I can't find a ref.
    It seems a genealization of the idea behind the LCG, but ...
    """

    def __init__( self, the_rnt, n_prngs, prng_bit_width, vector_depth,
                  paranoia_level ) :
        """
        Initializes N LCGs of bit_width and vector_depth.

        The goal is to calculate and set the tuple ( seed, int_width,
        lcg_array_size, multiplier, constant, lag ) for each LCD instantiated.

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

        15738.476547842401 bytes/second.  Slow, but how many of your
        messages are 15K bytes?
        """

        self.the_rnt             = the_rnt
        self.integer_width       = prng_bit_width
        # 64 bits is the least I think is reliably random, are now prohibited
        if self.integer_width < 64 :
            print( "integer widths less than 64 bits are prohibited!" )
            sys.exit( 0 )
        self.n_prngs             = n_prngs
        self.vector_depth        = vector_depth
        self.paranoia_level      = paranoia_level

        self.next_prng           = 0
        self.max_integer_mask    = ( 1 << prng_bit_width ) - 1
        self.max_integer         =   1 << prng_bit_width

        self.total_cycles        = 0
        self.prng_vector         = []

        self.the_fold            = FoldInteger( )
        self.entropy_bits        = the_rnt.password_hash


        # hash_depth should be differently different than vector_depth
        # good enough for now.
#        hashes = HASHES( the_rnt, self.integer_width, self.vector_depth )
#        the_hash = hashes.next()

#        the_hash.update( str( n_prngs ) + str( prng_bit_width ) + 
#                         str( vector_depth ) + str( paranoia_level ) )
#        hash_of_state = the_hash.intdigest()

        # small enough it doesn't mis-order the numbers, large enough
        # it won't be close to the calculated value
#        folded_hash_of_state = \
#            self.the_fold.fold_it( hash_of_state, self.integer_width )
            
        # multipliers and additive constants :
        # need 2 series of primes a good distance apart, say the low
        # range beginning from low at 10% to high at 40 and high range
        # beginning 60% to 90% We need N of each.
        # This is predictable from standard integer widths, so we also need the
        # entropy mixed into this.
        # return multiplier, constant, lag, increment
        
#        entropy_bits = folded_hash_of_state ^ self.entropy_bits
        constant_generator = generate_constants( self.the_rnt,
                                                 self.integer_width,
                                                 self.n_prngs )
        for i in range( self.n_prngs ) :
            multiplier, constant, lag, _ = next( constant_generator )

            # seed, rnt, integer_width, n_integers, multiplier, constant, lag 
            self.prng_vector.append( LCG( self.the_rnt,
                                          self.integer_width, self.vector_depth,
                                          self.paranoia_level,
                                          multiplier, constant, lag ) )

        for i in range( self.n_prngs ) :  
            # steps should be dependent on pw
            steps = self.the_rnt.password_hash & 0x2F
            self.prng_vector[ i ].next( 8, steps )

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
#        bit_selection_mask = bit_width - 1
        return_integer = 0
        self.next_prng %= ( self.n_prngs - 1 )
        for _ in range( steps ) :
            for bit_index in range( bit_width ) :
                # bit is selected by the last prng in the vector
                # this makes this a crypto-prng
                selected_bit_index = \
                                self.prng_vector[ self.n_prngs - 1 ].next(
                                    bit_width, 1 ) %  bit_width
                                    # bit_selection_mask 
        
                lcg_value = \
                        self.prng_vector[ self.next_prng ].next( bit_width,
                                                                 steps )
                self.next_prng += 1
                self.next_prng %= ( self.n_prngs - 1 )
    
                # shift a bit to the selected bit index
                bit_mask = 1 << selected_bit_index
    
                # mask to select the bit value
                selected_bit_value = lcg_value & bit_mask
    
                shift_distance = selected_bit_index - bit_index
                if shift_distance > 0 :
                    return_integer ^= selected_bit_value >> shift_distance
                else :
                    return_integer ^= selected_bit_value << -shift_distance
    
#                print( "i : ", hex( return_integer ) )

        self.total_cycles += steps

        # At this point, the return integer is bit_width * steps wide
        return ( self.the_fold.fold_it( return_integer, bit_width ) )


    def dump_state( self ) :
        """
        Debug code
        """
        for element in self.prng_vector :
            sys.stderr.write( '\n' + str( element ) )
            element.dump_state()


    def encrypt( self, plain_text, steps ) :
        """
        Encrypts a message string and returns the encrypted string.
        This only handles text, other data needs serialized.

        Plain text can be a short string or a file read.  Those are
        ascii and [], there may be other special cases for later.

        returns bytes
        """
        assert isinstance( plain_text, type( 'a' ) ) or \
               isinstance( plain_text, type( [] ) )
        
        cipher_text = bytearray( b'' )
        if   isinstance( plain_text, type( b'' ) )  or \
             isinstance( plain_text, bytearray ) :
            for plain_byte in plain_text :
                rand_byte = self.next( 8, steps )

                cipher_byte  = rand_byte ^ ord( plain_byte )
                cipher_text.append( cipher_byte & 0xff )

        elif isinstance( plain_text, type( 'a' ) ) :
            for plain_byte in plain_text :
                rand_byte = self.next( 8, steps )

                cipher_byte  = rand_byte ^ ord( plain_byte )
                cipher_text.append( cipher_byte & 0xff )

        elif isinstance( plain_text, type( [] ) ) :
            for plain_line in plain_text :
                for plain_byte in plain_line :
                    assert isinstance( plain_byte, type( 'a' ) )
                    cipher_text.append( ord( self.next( 8, steps ) ) ^ \
                                          ord( plain_byte ) & 0xFF )

        return cipher_text

    def decrypt( self, cipher_text, steps ) :
        """
        decrypts a message string and returns the encrypted string.
        """

        plain_text = ''
        if   isinstance( cipher_text, type( b'' ) )  or \
             isinstance( cipher_text, bytearray ) :
            for ciph_byte in cipher_text :
                rand_byte = self.next( 8, steps )

                plain_byte = chr( rand_byte ^ ciph_byte )
                plain_text += plain_byte

        elif isinstance( cipher_text, type( 'a' ) ) :
            for ciph_byte in cipher_text :
                rand_byte = self.next( 8, steps )

                plain_byte = chr( rand_byte ^ ord( ciph_byte ) )
                plain_text += plain_byte

        elif isinstance( plain_text, type( [] ) ) :
            for ciph_line in cipher_text :
                for ciph_byte in ciph_line :
                    assert isinstance( ciph_byte,  type( 'a' ) )
                    plain_text += chr( ( ord( self.next( 8, steps ) ) ^ \
                                         ord( ciph_byte ) ) & 0xFF )
        
        return plain_text


class HashCrypto( LcgCrypto ) :
    """
    Uses the set of hashes to produce a crypto-quality pseudo-random number.

    The data structure is a vector of hash instantiations.

    Individual hash functions may be relatively weak wrt dieharder (but
    not the functions I provide), but very strong when considered as an
    ensemble.

    Data structure is the vector of instantiated hash functions.
    
    After that, each hash's integer_vector is replaced with a single
    vector.
    
    Next() calls the hashes in order doing updates.

    54827.50326797386 bytes / second, 5x faster than PrngCrypto
    """
    def __init__( self, the_rnt, n_prngs, integer_width, vector_depth,
                  paranoia_level ) :
        """
        initializes n_prngs with integers, then another n_prngs with
        hashes?
        """
        LcgCrypto.__init__( self, the_rnt, n_prngs, integer_width,
                            vector_depth, paranoia_level )
        self.bit_selection_mask   = integer_width - 1
        self.next_hash            = 0

        self.total_cycles         = 0
        self.hash_function_vector = []

        self.the_fold             = FoldInteger()

        # used in next() to begin the update cycle
        self.rnt_index            = 0

        # fill the hash_function_vector with instantiated hash functions
        the_hashes = HASHES( the_rnt, integer_width, vector_depth )
        for i in range( self.n_prngs ) :
            self.hash_function_vector.append( the_hashes.next() )
            
        # update the integer_vector for every function
        for i in range( len( self.hash_function_vector ) ) :
            self.hash_function_vector[ i ].update(
                the_rnt.password_hash * i + i )
            # accumulate some more entropy
            self.rnt_index ^= the_rnt.password_hash * i + i

        self.rnt_index %= the_rnt.rnt_bit_size

        # initial steps should be dependent on the password
        self.next( 64, self.the_rnt.password_hash % 64 )


    def next( self, bit_width, steps ) :
        """
        The previous next() produced lousy random streams by my tests,
        this will use a different approach, better use of the total
        state of the set of hashes.

        Algorithm :
            Get an initial 64 bits from the RNT, maintain an index
            incremented by a small prime wrapping around.
            Use that to begin the cycle of updating successive hash and
            extracting an intdigest.
        """
        return_limit = 1 << ( bit_width * 2 )
        return_value = self.the_rnt.bit_string_from_randoms(
                                                    self.rnt_index, bit_width )
        self.rnt_index = ( self.rnt_index + self.n_prngs ) % \
                           self.the_rnt.rnt_bit_size
        # initial return_value is smaller than the return_limit
        for i in range( steps ) : 
            while return_value < return_limit :
                self.next_hash = ( self.n_prngs + 1 ) % self.n_prngs
                this_hash = self.hash_function_vector[ self.next_hash ]
                this_hash.update( return_value )

                return_value += this_hash.intdigest()

            # return_value is reset to < return limit with a fold, so
            # accumulates entropy
            return_value = self.the_fold.fold_it( return_value, bit_width )

        # final fold for the generated return value
        return self.the_fold.fold_it( return_value, bit_width )

#    def next1( self, bit_width, steps ) :
#        """
#        Returns the xors of steps random numbers in the next_integer
#        positions, masked to bit_width.
#
#        This consistently has one duplicate at 32-bits.
#
#        So I started the 'hash32' dieharder test about 9AM WEd 27 June
#        and also the mods to test_evoprngs.py's checkfunction routine so
#        the sample size is 16 * 1024 * 1024. That got through generating
#        16 M randoms about 10AM, and has been working on checking
#        duplicates ever since. No dups yet.
#        
#        Will let that run indefinitely, every hour gives me more info about
#        the quality of hash32 as a prng. I nearly always let the
#        dieharder tests run to completion, I currently have ultra-slow tests
#        from 21 May and 9 June.
#
#        Checking program shows this to degenerate into cycles because of
#        all zeros in the low-order bits, e.g. 
#        dup at  8388482 0xfffc5c0000000000
#        dup at  8388487 0xfffc740000000000
#        dup at  8388497 0xfffca70000000000
#        dup at  8388500 0xfffcae0000000000
#        dup at  8388507 0xfffcc60000000000
#        dup at  8388512 0xfffcd80000000000
#        dup at  8388517 0xfffce30000000000
#        dup at  8388519 0xfffcea0000000000
#        dup at  8388522 0xfffcf40000000000
#        dup at  8388525 0xfffd000000000000
#        dup at  8388531 0xfffd110000000000
#        dup at  8388546 0xfffd560000000000
#        dup at  8388556 0xfffd750000000000
#        dup at  8388564 0xfffd970000000000
#        dup at  8388566 0xfffd9a0000000000
#        dup at  8388587 0xfffe040000000000
#        dup at  8388590 0xfffe110000000000
#        dup at  8388598 0xfffe400000000000
#        dup at  8388603 0xfffe5d0000000000
#        dup at  8388607 0xfffe6a0000000000
#        dup at  8388619 0xfffe8c0000000000
#        dup at  8388644 0xfffee40000000000
#        dup at  8388677 0xffff9b0000000000
#        dup at  8388685 0xffffbc0000000000
#        dup at  8388694 0xffffe80000000000
#
#        OK, maybe good hashes are more difficult than I thought, tho the
#        amount of time I have invested in them is not great.
#
#        So, the first thing to do is to be sure I haven't been fooling
#        myself about the rest of these Crypto functions, and to check to
#        be sure that dieharder detects this.  Will be fairly
#        disappointed if it does not. I have the hash output in a file,
#        try that first.
#
#        Well, well, well. Revelations everywhere today.  First, running
#        from file input is very fast, a few minutes for -a tests.
#        Second, it doesn't take that many randoms, 67MB is more than
#        enough. Slow the generation of those files are, it is much
#        faster than running directly to diharder. That means that the
#        overhead of piping from generator stdout to dieharder stdin is
#        quite large. Big disk are easy and cheap, so we save time
#        generating files, even if only used once for dieharder.
#
#        Third, dieharder is shit if it doesn't see the non-randoms my
#        simple checks show. Does NSA control dieharder? Or does dieharder
#        only see things from the pov of 'adequately random for models
#        and Newtonian integrations', not the NSA-resistant
#        'adequtely random to resist cryptology'? Or both?
#
#        A year ago or so, I did a lot of code for checking randoms, need
#        to resurrect that, I can't trust dieharder any longer.
#
#        Marvey, the project just turned in a different direction, I made
#        assumptions which are very wrong. Now months ahead of me, not
#        weeks. Resurrect my statistics courses.
#
#        I need to get this into github, just in case anyone wants to
#        begin using it, it is not anyplace close to secure crypto yet.
#
#        Your assumptions get you every time, it is so hard to overcome
#        your own understandings. I have said many times that  isn't
#        possible to be paranoid enough, but you should damn well try.
#
#        Again, I failed to be paranoid enough. I hate that. There is a
#        Lebowski Enlightenment in here somewhere.
#
#        CryptoPrng also has lots of dups, tho these don't look like
#        cycles, rather too-few bits changing, degenerate cases of values
#        it can't recover from, e.g.
#        dup at  14981665 0x78300a6666653966
#        dup at  14981674 0x78300a6666656237
#        dup at  14981679 0x78300a6666656332
#        dup at  14981684 0x78300a6666656339
#        dup at  14981685 0x78300a6666656339
#        dup at  14981693 0x78300a6666656532
#        dup at  14981700 0x78300a6666656663
#        dup at  14981701 0x78300a6666656663
#        dup at  14981705 0x78300a6666663062
#        dup at  14981715 0x78300a6666663232
#        dup at  14981718 0x78300a6666663237
#        dup at  14981721 0x78300a6666663265
#        dup at  14981739 0x78300a6666663661
#        dup at  14981740 0x78300a6666663661
#        dup at  14981743 0x78300a6666663664
#        dup at  14981745 0x78300a6666663731
#        dup at  14981747 0x78300a6666663732
#        dup at  14981748 0x78300a6666663732
#        dup at  14981756 0x78300a6666663836
#        dup at  14981761 0x78300a6666663864
#        dup at  14981768 0x78300a6666666133
#        dup at  14981789 0x78300a6666666461
#        dup at  14981801 0x78300a6666666636
#
#        LcgCrypto is OK, both by my tests and dieharder.
#
#        the 1hex version
#        """
#
#        return_value = 0
#        return_limit = 1 << ( bit_width * 2 )
#        for i in range( steps ) : 
#            while return_value < return_limit :
#                sys.stdout.flush()
#                return_value = return_value << int( bit_width / 4 )
#                self.next_hash = ( self.n_prngs + 1 ) % self.n_prngs
#
#                # if the application uses prime values for the depth, any
#                # number will do.  Otherwise, 3 and 7 are at least rel-prime
#                rnt_addr0 = ( self.next_hash + i + 3 ) % self.vector_depth
#                rnt_addr1 = ( self.next_hash + i + 7 ) % self.vector_depth
#                sys.stdout.flush()
#
#                this_hash = self.hash_function_vector[ self.next_hash ]
#
#                # I don't like reaching into the hash's data structures
#                update_value  = this_hash.integer_vector[ rnt_addr0 ]
#                entropy_bits  = this_hash.integer_vector[ rnt_addr1 ]
#                # the hash update is the slow part. RNT is to prevent cycles
#                # but it doesn't, I just found.
#                update_value += self.the_rnt.next_random_value( entropy_bits,
#                                                            self.integer_width )
#
#                # fold to 32 bits, probably still overkill
#                four_byte_update = 0
#                while update_value != 0 :
#                    # another link in the code breaker's logic chains
#                    # costs a test and branch, nearly nothing.
#                    if update_value & 0x01 :
#                        four_byte_update ^= update_value & 0xFFFFFFFF
#                    else :
#                        four_byte_update += update_value & 0xFFFFFFFF
#                    update_value >>= 32
#
#                # update this_hash function. Simple attempt to fix the
#                # cycles, added hex(). Test our way to success,
#                # understand later, tried and true tactics for sw engineers
#                # since the beginning of the profession. Everything
#                # Brooke's Mythical Man-Month taught us to avoid.
#                # the additon of the hex() makes the random numbers in
#                # the generated file terrible, many zeros, ... 48MB of
#                # output, but dieharder thinks it passes everything.
#                # So it seems likely I am mis-using dieharder, but 
#                # the man page does not reveal how, seems straightforward.
#                this_hash.update( four_byte_update )
#
#                # this could take a while for a wide request vs narrow
#                # hashes, but that would be a misuse, so this is OK.
#                return_value += this_hash.intdigest()
#
#        return self.the_fold.fold_it( return_value, bit_width )


class PrngCrypto( LcgCrypto ) :
    """
    Uses a set of PRNGs to produce a crypto-quality pseudo-random number
    generator.

    Algorithm is to use N PRNGs, with the last PRNG selecting the particular
    bits from the others.

    All of the PRNGs have a uniform interface, whether they use all the
    arguments or not.

    This uses randomly chosen primes for the two constants, and
    increasing primes for the lags, thus to produce the longest cycles.

    This is very slow even on my serious system : 11088 bytes/ second.

    This should use the hashes, also, but those will require a different
    interface and the next function.
    """

    def __init__( self, the_rnt, n_prngs, integer_width, vector_depth,
                  paranoia_level ) :
        """
        Initializes N PRNGs of bit_width and vector_depth.

        The goal is to calculate and set the tuple ( RNT, int_width,
        lcg_array_size, multiplier, constant, lag ) for each PRNG instantiated.
        All PRNG algorithms may not use all of them, but the interfaces
        are uniform.

            lcg_array_size is the # of prng_bit_width integers in the array.

            prng_bit_width is bits in the intgers. This integer must be a power
            of 2 for this code to work because of the calculation of the
            bit-selection mask.
            
            The values of multiplier, constants and lag are calculated.
            Multiplier decreases from a 10% less than 'max_int' for the
            array width.  Constant increases from 10% above 0. 
            Both change by an amount making N fit into 1/3rd of the range.
            
            Discussions say they only need be relatively prime, this makes
            them a prime.
 
            The lag is prime and also different across the N arrays as
            yet another mechanism to prevent short cycles.

        """

        LcgCrypto.__init__( self, the_rnt, n_prngs, integer_width,
                            vector_depth, paranoia_level )

        self.vector_depth        = vector_depth

        self.entropy_bits        = the_rnt.password_hash

        self.bit_selection_mask  = integer_width - 1
        self.next_prng           = 0
        self.max_integer_mask    = ( 1 << integer_width ) - 1
        self.max_integer         =   1 << integer_width

        self.total_cycles        = 0
        self.prng_set            = [] # will be n_prngs in the set

        self.the_fold            = FoldInteger( )

        # n_prngs should be differently different than vector_depth
#        hashes = HASHES( the_rnt, self.integer_width, self.vector_depth )
#        the_hash = hashes.next()

        # initialized, but no update is sort of OK
#        hash_of_state = the_hash.intdigest()

        # an additional bit of randomness
#        folded_hash_of_state = \
#            self.the_fold.fold_it( hash_of_state,  integer_width )
            
        # multipliers and additive constants :
        # need 2 series of primes a good distance apart, say the low
        # range beginning from low at 10% to high at 40 and high range
        # beginning 60% to 90% We need N of each.
        # This is predictable from standard integer widths, so we also need the
        # entropy mixed into this.
        # the square of entropy_bits is necessary for it to always be large
        # enough for the mod to do something.
        # current_max steps from high to low, current_min the reverse
#        entropy_bits = folded_hash_of_state ^ self.entropy_bits
        constant_generator = generate_constants( self.the_rnt,
                                                 self.integer_width,
                                                 self.n_prngs )
        prngs = PRNGs()
        for i in range( self.n_prngs ) :
            multiplier, addition, lag, _ = next( constant_generator )
            # this loop instantiates the prngs
            # seed, rnt, integer_width, hash_depth, multiplier, constant, lag 
            # prng_set size, vector_depth,  should be differently different than
            # vector_depth
#            print( "n_prngs = ", self.n_prngs, vector_depth,
#                   hex( multiplier ), hex( addition ), hex( delta ), lag, )
            sys.stdout.flush()
            the_prng = prngs.next( the_rnt, int( self.integer_width ),
                        int( self.vector_depth ), int( paranoia_level ),
                        int( multiplier ), int( addition ), int( lag ) )

            self.prng_set.append( the_prng )

        # steps should be dependent on the pw
        steps = self.the_rnt.password_hash % 64
        for i in range( n_prngs ) :  
            self.prng_set[ i ].next( 8, steps )

#            sys.stderr.write( "init finished\n" )

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

        This got very slow with my last fix.
        """

        # We want an index into the bit-width bits, which must be less than
        # bit_width.
        return_value = 0
        self.next_prng %= ( self.n_prngs - 1 )
        for _ in range( steps ) :
            for bit_index in range( bit_width ) :
    
                # bit is selected by the last prng in the vector
                selected_bit_index = \
                            self.prng_set[ self.n_prngs - 1 ].next(
                                bit_width, 1 ) % bit_width
    
                random_value = \
                    self.prng_set[ self.next_prng ].next( bit_width, 1 )
                self.next_prng += 1
                self.next_prng %= ( self.n_prngs - 1 )
    
                # shift a mask bit to the selected bit index
                bit_mask = 1 << selected_bit_index

                # mask to select the bit value
                selected_bit_value = random_value & bit_mask

                # shift the bit and xor it into the random number
                shift_distance = selected_bit_index - bit_index
                if shift_distance > 0 :
                    return_value ^= selected_bit_value >>  shift_distance
                # first experiment, take this out. Testing to success,
                # etc.
#                else :
#                    return_value ^= selected_bit_value << -shift_distance

        self.total_cycles += steps

        return self.the_fold.fold_it( return_value, bit_width )

def dump_state( self ) :
    """ Debug code """
    for element in self.prng_vector :
        sys.stderr.write( str( element ) + '\n' )
        element.dump_state()

def generate_random_table( the_rnt, n_bytes, bitwidth ) :
    """ generate N bytes of random data in 64-bit hexadecimal words
    I use this to generate the first-generation evocrypt.py'
    4K_Constant bytes when the program is fissioned.
    """ 
    random_table = ''
    the_crypto = PrngCrypto( the_rnt, 23, 256, 31, 1 )

    # this is 4K bytes as lines of 8-byte words in hexadecimal
    # 4 words per line.  The +64*16 is to provide a 16 word margin
    # that eliminates some checks for accessing information past the
    # nominal end of the table
    for _ in range( int( n_bytes / ( 8 * 4 ) ) + 4 ) :
        the_line = ''
        for _ in range( 4 ) :
            the_value = the_crypto.next( bitwidth, 1 )

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

#CRYPTO_PRNG_FUNCTIONS = [ HashCrypto, LcgCrypto ]
#CRYPTO_PRNG_FUNCTIONS = [ HashCrypto, TwisterCrypto, LcgCrypto ]


# main begins here, test code for the module, it does nothing useful by
# itself.

if __name__ == "__main__" :

    SHORT_ARGS = "hn=p=t="
    LONG_ARGS  = [ 'help', 'n_randoms=', 'password=', 'test=' ]

    sys.stderr.write( '#' + __filename__ + '\n' )
    sys.stderr.write( '#' + __version__ + '\n' )
    sys.stderr.write( '#' + str( sys.argv[ 1 : ] ) + '\n' )

    TEST_LIST                 = []      # list of tests to execute
    PASSWORD                  = ''
    DESIRED_NUMBER_OF_RANDOMS = 1024*1024*1024*1024 # default for dieharder

    try :
        OPTS, ARGS = getopt.getopt( sys.argv[ 1 : ], SHORT_ARGS, LONG_ARGS )

    except getopt.GetoptError as err :
        print( "except on OPTS" )
        sys.stderr.write( "getopt.GetoptError = " + str( err ) )
        sys.exit( -2 )

    print( "begin OPTS" )
    for o, a in OPTS :
        print( o, a )
        if o in ( "--help" ) or o in ( "-h" ) :
            usage()
            sys.exit( -2 )

        if o in ( "--n_randoms" ) or o in ( "-n" ) :
            print( a )
            DESIRED_NUMBER_OF_RANDOMS = int( a )

        if o in ( "--password" ) or o in ( "-p" ) :
            PASSWORD = a

        if o in ( "--test" ) or o in ( "-t" ):
            TEST_LIST.append( a )

    print( "DESIRED_NUMBER_OF_RANDOMS = ", DESIRED_NUMBER_OF_RANDOMS )
    print( "PASSWORD                  = ", PASSWORD )
    print( "TEST_LIST                 = ", TEST_LIST )
    sys.stdout.flush()

    # need a random factor to prevent repeating pseudo-random sequences
    random.seed()
    PASSPHRASE = PASSWORD + hex( random.getrandbits( 128 ) )
    THE_RNT = RNT( 4096, PASSPHRASE, 'desktop', 1 )

    BIN_VECTOR = array.array( 'Q' )     # now emits long long
    BIN_VECTOR.append( 0 )

    SO = os.fdopen( sys.stdout.fileno(), 'wb' )

    # all the rest is testing
    if 'generate_random_table' in TEST_LIST :
        print( generate_random_table( THE_RNT.password_hash, 4096, 64 ) )

    if 'lcg_crypto' in TEST_LIST :
        # 3.41e+03 rands / second, very slow

        N_LCGS         = 19
        INTEGER_WIDTH  = 128
        LCG_DEPTH      = 32
        PARANOIA_LEVEL = 1
        DIEHARDER_MAX_INTEGER   = ( 1 << 64 ) - 1

        THE_LCG = LcgCrypto( THE_RNT, N_LCGS, INTEGER_WIDTH, LCG_DEPTH,
                              PARANOIA_LEVEL ) 

        LO_MASK_64_BITS = ( 1 << 64 ) - 1 
        HI_MASK_64_BITS = LO_MASK_64_BITS << 64

        COUNTER = 0
        while True :
            
            THE_RANDOM_NUMBER = THE_LCG.next( INTEGER_WIDTH, 1 )

            # the strategy here is to put out the entire 128-bit 
            # integer to be sure both halves are OK. 
            # I would do the entire thing at once, but don't see how to
            # make the array.array handle those. This approach does not 
            # preserve little-endian, but the goal is checking 64 bits
            # segments so I don't care.
            THE_EMITTED_NUMBER = THE_RANDOM_NUMBER & LO_MASK_64_BITS
            BIN_VECTOR[ 0 ] = THE_EMITTED_NUMBER
            BIN_VECTOR.tofile( SO )

            THE_EMITTED_NUMBER = ( THE_RANDOM_NUMBER & HI_MASK_64_BITS ) >> 64
            BIN_VECTOR[ 0 ] = THE_EMITTED_NUMBER
            BIN_VECTOR.tofile( SO )

            COUNTER += 2 # count 64-bit randoms
            if COUNTER >= DESIRED_NUMBER_OF_RANDOMS :
                break

#            print( hex( THE_RANDOM_NUMBER )

    if 'lcg_crypto_rate' in TEST_LIST :
        THE_LCG = LcgCrypto( THE_RNT, 9, 128, 31, 1 )

        print( 'lcg crypto byte rate = ',
                byte_rate( THE_LCG, 64, 1024*1024 ) )

    if 'prng_crypto' in TEST_LIST :
        # 3.41e+03 rands / second, very slow

        VECTOR_DEPTH   = 19
        INTEGER_WIDTH  = 128
        PRNG_DEPTH     = 31
        PARANOIA_LEVEL = 1
        DIEHARDER_MAX_INTEGER   = ( 1 << 64 ) - 1

        #( the_rnt, vector_depth, integer_width, vector_depth, paranoia_level )
        THE_PRNG = PrngCrypto( THE_RNT, VECTOR_DEPTH, INTEGER_WIDTH, PRNG_DEPTH,
                               PARANOIA_LEVEL ) 
        sys.stderr.write( "THE_PRNG = " + str( THE_PRNG ) + '\n'  )

        LO_MASK_64_BITS = ( 1 << 64 ) - 1 
        HI_MASK_64_BITS = LO_MASK_64_BITS << 64

        COUNTER = 0
        while True :
#            sys.stderr.write( "calling next " + '\n' )
            THE_RANDOM_NUMBER = THE_PRNG.next( INTEGER_WIDTH, 1 )
            print( hex( THE_RANDOM_NUMBER ) )
            sys.stdout.flush()

            THE_EMITTED_NUMBER = THE_RANDOM_NUMBER & LO_MASK_64_BITS
            BIN_VECTOR[ 0 ] = THE_EMITTED_NUMBER
            BIN_VECTOR.tofile( SO )

            THE_EMITTED_NUMBER = ( THE_RANDOM_NUMBER & HI_MASK_64_BITS ) >> 64
            BIN_VECTOR[ 0 ] = THE_EMITTED_NUMBER
            BIN_VECTOR.tofile( SO )

            COUNTER += 2
            if COUNTER >= DESIRED_NUMBER_OF_RANDOMS :
                break

#            sys.stdout.write( hex( THE_RANDOM_NUMBER ) + '\n'  )

    if 'prng_crypto_rate' in TEST_LIST :
        N_HASHES       = 19
        INTEGER_WIDTH  = 128
        PRNG_DEPTH     = 31
        PARANOIA_LEVEL = 1
        DIEHARDER_MAX_INTEGER   = ( 1 << 64 ) - 1
        THE_PRNG = PrngCrypto( THE_RNT, N_HASHES, INTEGER_WIDTH, PRNG_DEPTH,
                               PARANOIA_LEVEL ) 

        print( 'prng crypto byte rate = ',
                byte_rate( THE_PRNG, 64, 10*1024*1024 ) )

    if 'hash_crypto' in TEST_LIST :
        N_HASHES       = 19
        INTEGER_WIDTH  = 128
        HASH_DEPTH     = 31
        PARANOIA_LEVEL = 1
        THE_HASH_CRYPTO = HashCrypto( THE_RNT, N_HASHES, INTEGER_WIDTH,
                                      HASH_DEPTH, PARANOIA_LEVEL )

        LO_MASK_64_BITS = ( 1 << 64 ) - 1 
        HI_MASK_64_BITS = LO_MASK_64_BITS << 64

        COUNTER = 0
        while True :
            THE_RANDOM_NUMBER = THE_HASH_CRYPTO.next( 64, 1 )

            THE_EMITTED_NUMBER = THE_RANDOM_NUMBER & LO_MASK_64_BITS
            BIN_VECTOR[ 0 ] = THE_EMITTED_NUMBER
            BIN_VECTOR.tofile( SO )

            THE_EMITTED_NUMBER = ( THE_RANDOM_NUMBER & HI_MASK_64_BITS ) >> 64
            BIN_VECTOR[ 0 ] = THE_EMITTED_NUMBER
            BIN_VECTOR.tofile( SO )

            COUNTER += 2
            if COUNTER >= DESIRED_NUMBER_OF_RANDOMS :
                break

#            print( hex( THE_RANDOM_NUMBER ) )


    if 'hash_crypto_rate' in TEST_LIST :
        N_HASHES       = 19
        INTEGER_WIDTH  = 128
        HASH_DEPTH     = 31
        PARANOIA_LEVEL = 1
        THE_HASH_CRYPTO = HashCrypto( THE_RNT, N_HASHES, INTEGER_WIDTH,
                                      HASH_DEPTH, PARANOIA_LEVEL )

        print( "hash crypto byte rate = ",
                byte_rate( THE_HASH_CRYPTO, 64, 1024*1024 ) )

    # more conservative tests would be to encrypt the same phrase again
    # and again.
    # I eliminated encode 0 and 1 test, they were less stringent than encode2

    if 'encode2' in TEST_LIST :
        # encrypt the same phrase repeatedly, test result for randomness
        # Theoretically, this should be identical in result to a random test
        # of a CRYPTO PRNGenerator.
        # MUST BE the same, this is simply making sure.
        THIS_CRYPTO = CRYPTO( PASSPHRASE, 'desktop', 1 )
        ENCODE = THIS_CRYPTO.next()

        THE_TEXT = "this is a test0"
        while True :
            THIS_TEXT_BYTE_COUNT = 0
            while THIS_TEXT_BYTE_COUNT < len( THE_TEXT ) :
                CIPH_WORD = 0

                # embarassing bug found and removed from right here forever!
                # Dumb!
                PLAIN_BYTES = THE_TEXT[ THIS_TEXT_BYTE_COUNT : 
                                        THIS_TEXT_BYTE_COUNT + 8 ]
                THIS_TEXT_BYTE_COUNT += 8

                if len( PLAIN_BYTES) == 0 :
                    break

                RAND_INT = ENCODE.next( 64, 1 )
                PLAIN_INT = struct.unpack( "@Q", PLAIN_BYTES )[ 0 ]

                CIPH_WORD = PLAIN_INT ^ RAND_INT

#                    print( "ciph_word = ", hex( CIPH_WORD ) )
                BIN_VECTOR[ 0 ] = CIPH_WORD
                BIN_VECTOR.tofile( SO )
 


    if 'encode3' in TEST_LIST :

        try :
            LOG_FD   = open( 'Encode3.log', 'w' )

        except IOError as the_error :
            STRERROR = the_error.args
            print( " error '" + STRERROR + "'" )
            sys.exit( -2 )

        evoutils.DEBUG_FD = open( 'Encode3_debug.log', 'w' )

        # this matches the chat setup.
        PASSPHRASE   = 'Fred'
        SYSTEM_TYPE  = 'desktop'
        SEND_CRYPTOS = CRYPTO( PASSPHRASE + 'serversend', SYSTEM_TYPE, 1 )
        SEND_CRYPTO  = SEND_CRYPTOS.next()

        LOG_FD.write( "\n" )
        LOG_FD.write( str( SEND_CRYPTO ) )
        LOG_FD.write( "\n" )


        # TEST CODE TO FIGURE OUT THE encode/decode PROBLEM
        TEST_MESSAGE = "from server\n"
        LOG_FD.write( TEST_MESSAGE )

        CIPHER_TEST_MESSAGE = SEND_CRYPTO.encrypt( TEST_MESSAGE, 1 )
        print( 'cipher_test_message type = ', type( CIPHER_TEST_MESSAGE) )
        LOG_FD.write( str( bytes( CIPHER_TEST_MESSAGE ) ) + '\n' )

        # need to begin again to have the same state
        SEND_CRYPTOS = CRYPTO( PASSPHRASE + 'serversend', SYSTEM_TYPE, 1 )
        SEND_CRYPTO  = SEND_CRYPTOS.next()

        CIPHER_TEST_MESSAGE = SEND_CRYPTO.decrypt( CIPHER_TEST_MESSAGE, 1 )
        print( 'cipher_test_message type = ', type( CIPHER_TEST_MESSAGE) )
        LOG_FD.write( CIPHER_TEST_MESSAGE + '\n' )

        LOG_FD.flush()
        # TEST CODE TO HERE


    if 'hash32' in TEST_LIST :
    # a test of 32-bit hash randomness, it is failing.
        MAX_INT_MASK = ( 1 << 64 ) - 1
        print( hex( MAX_INT_MASK ) )
        HASH = HashCrypto( THE_RNT, 11, 32, 17, 2 )
        for _ in range( 16 * 1024 * 1024 ) :
            RANDOM0 = HASH.next( 32, 2 )
            RANDOM1 = HASH.next( 32, 2 )
            THE_RANDOM = ( ( RANDOM0 << 32 ) + RANDOM1 ) & MAX_INT_MASK
            BIN_VECTOR[ 0 ] = THE_RANDOM
            BIN_VECTOR.tofile( SO )

    if 'constants' in TEST_LIST :
        # a test of generate_constants
        N_PRNGS = 19 
        for INTEGER_WIDTH in [ 64, 128, 256 ] :

            for N_PRNGS in [ 7, 19, 31 ] :
                CONSTANT_GENERATOR = generate_constants( THE_RNT, INTEGER_WIDTH,
                                                         N_PRNGS ) 

                for I in range( N_PRNGS ) :
                    MULTIPLIER, ADDITION, LAG, DELTA = next( CONSTANT_GENERATOR)
                    print( I, MULTIPLIER, ADDITION, LAG, DELTA )

                # should return an error
                try :
                    MULTIPLIER, ADDITION, LAG, DELTA = next( CONSTANT_GENERATOR)
                except StopIteration :
                    print( "StopIteration -- proper result" )
