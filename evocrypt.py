#!/usr/bin/python3

"""
evocrypt.py

This program is designed to foil NSA's password attacks onff standard
unbreakable ciphers such as AES. It does so by making passwords only one
component of the encryption system, the particular version of this
program is the other part of a 2-factor authentication. Additionally,
the program is easily changed and can change itself, it evolves, thereby
presenting attackers with a different problem for every version.

Small fixed mechanism and standard hashes are what allow NSA's
brute-force attacks on AES and other modern crypto systems.

This system is designed to make automated cryptoanalysis much more
difficult, and hardware acceleration impossibly expensive.  It does so
by using many different possible PRNGs and hash functions to compose
provably-strong encryptions, but with enough diffent functions
and functions with large states so that the opponent has a large
combinatorial problem in the mechanism that translates key and text into
cypher text.

This program both implements such a crypto system, and writes new ones,
each a unique combination of functions and constants.  Passwords both
protect data and direct the evolution of programs generating programs.

This is NOT the dreaded security by obscurity.  Every program component will
be solid cryptographically.  But even solid systems can be attacked, as we
have learned from all of the standards.  The many side-channel attacks
are only possible because those have regularity and small mechanisms.
Evocrypt intentionally does not have easily-exploited regularity, and
the mechanisms are too large to be accelerated with FPGAs or ASICS.

The goal is to allow encryption of an encyclopedia, a known plain text,
with no additional probability of breaking the encryption, and to
present a different problem of decryption for the opponent for every
version of program.

XOR with a PRNG is cryptographically secure, except for the PRNG.  Many
of those are predictable, given a long enough sequence of bytes, but one
PRNG choosing bits from the output of others is secure.  So long as each
one passes dieharder, the standard test of random number sequences, the
result will be cryptographically secure.

An aspect of that design is that every pair of programs will evolve
differently, so the same password will produce different encryptions
and different programs in each generation.  Even without programmers
changing anything about the program, the number of functions in every
list and the 4K bytes of random numbers guarantee that every program
can generate a new, different, program, indefinitely.

Additionally, it is easy to change or add to this program to begin a unique
lineage of programs by adding to the lists of fold, PRNG or hash functions,
or changing the mechanisms by which the password is used to select
values for the various uses throughout the program.

Each program can generate new versions of itself, so other lineages
can begin their independent evolution. Every new version will be unique,
only able to work with copies of itself or generated from the same
parent program using the same password.


Current limitations of the code :

"""
__version__   = "0.1"
__revision__  = "$Id$"
__date__      = "2017-04-02"
__author__    = "nobody@nowhere.com"
__copyright__ = "None"
__license__   = "None"
__filename__  = "evocrypt.py"
__history__   = """
0.1 - 20170402 - started this file.

TODO :
0) 

"""

import sys
import os
import getopt
import hashlib
import shutil
from array     import array
from evocprngs import LcgCrypto, CRYPTO, PrngCrypto, HashCrypto
from evohashes import HASHES
from evornt    import RNT
from evofolds  import FoldInteger
from binascii  import unhexlify


def assemble_program_from_dev_files() :
    """
    All development should be done from the half dozen module files.
    For normal use, those must be in one program so that users don't have
    a version problem.

    This composes a user's program from the development files, and
    returns the text.

    I have built in the file names and order. That is rigid, but also
    robust, mixing this code in a different project won't screw it up.

    This worked, the resulting program executes.
    """
    dev_files = [ 'evoutils.py', 'evofolds.py', 'evoprimes.py', 'evohashes.py',
                  'evornt.py',   'evoprngs.py', 'evocprngs.py', 'evocrypt.py' ]

    the_program = \
"""#!/usr/bin/python3

import pdb
import sys
import os
import time
import datetime
import socket
import select
import threading
import queue
import signal
import curses
import traceback
import math
import hashlib
import random
import binascii
import struct
import base64
import time
import copy
import getopt
from contextlib import contextmanager
from array import array
import shutil
from binascii  import unhexlify

\n
    """

    for dev_file_name in dev_files :
        found_begin = False

#        print( sys.stderr, "dev_file_name = ", dev_file_name )
        
        program_file  = open( dev_file_name, 'r' )

        for this_line in program_file :

            # this implements a primitive macro pre-processor-like
            # function to separate multi-file development code from delivered
            # single-file program that is a new lineage. Single-file
            # Python programs can be modified, as can any copy of this
            # program's git archive.

            # this separation enables wide-spread parallel development
            # and easy ways to make everyone's code different than all
            # other versions.

            # make it simple, "#SINGLE_PROGRAM_FROM_HERE" to
            # "#SINGLE_PROGRAM_TO_HERE" in non-overlapping pairs
            # and with multiple pairs

            if this_line == "#SINGLE_PROGRAM_FROM_HERE\n" :
                found_begin = True
                continue

            if found_begin :    # until found end

                if this_line == "#SINGLE_PROGRAM_TO_HERE\n" :
                    found_begin = False
                    continue

                the_program += str( this_line )

        program_file.close()

    return the_program


#SINGLE_PROGRAM_FROM_HERE

def generate_new_program( password, this_file_name, new_file_name,
                          array_size ) :
    """
    This uses the current single file program text to produce a new program.

    Scrambles everything scramblable in the text and writes the program
        to new_file_name.
    """

#    sys.stderr.write( "generate_new_program : password = '" + password + "'\n" )
#    sys.stderr.write( "generate_new_program : new_file_name = '" + \
#            new_file_name + "'\n" )

    # need a check for this being a single program

    # read the program into a buffer

    program_file = open( this_file_name, 'r' )

    # substitute the new n_K random numbers
    new_randoms_program = replace_random_table( program_file, password,
                                                array_size )

    # get a 128-bit hash of the program, used to make the new file name
    # this is both a part of decoding files and a self-check for the
    # program's integrity ?
    folded_hash = hash_text( new_randoms_program )[ 3 ]

    # Generate the new name
    if '.py' in new_file_name[ -3 : ] :
        new_file_name = new_file_name[ 0 : -3 ]
    new_name = new_file_name + '_' + folded_hash + '.py'

    # write the new program
    new_file = open( new_name, 'w' )
    new_file.write( new_randoms_program )
    new_file.close()

    return new_name

def xor_fold( the_value, bit_width ) :
    """
    This should handle both ints and bytes
    """
    mask = ( 1 << bit_width ) - 1
    short_value = 0
    for i in range( 8 ) :
        short_value ^= the_value >> ( i * bit_width ) & mask

    return hex( short_value )

def hash_text( the_text ) :
    """
    Same as file_hash, but inmemory array

    Returns 64-bits as a hexadecimal
    """
#    print( "type of the_text is ", type( the_text ) )

    the_hash = hashlib.sha512()
    if isinstance( the_text, str ):
        the_hash.update( the_text.encode( 'utf8' ) )
    else :
        the_hash.update( the_text )

    # fold the 512-bit digest to 128 bits
    byte_digest = the_hash.digest()
    int_digest = int( the_hash.hexdigest(), 16 )
    hex_digest = the_hash.hexdigest()

    short_digest = xor_fold( int_digest, 64 )

    # return all 4 hashes, different programs need them all
    return ( byte_digest, int_digest, hex_digest, short_digest )


def hash_file( filename ):
    """
    Uses sha512 to compute a 64-bit hash. 64-bits should be large enough
    to prevent collisions. if it gets so popular as for collisions to be
    an issue, make it larger.

    Returns 64-bits as a hexadecimal
    """
    the_hash = hashlib.sha512()
    with open(filename, 'rb', buffering=0) as the_file:
        for the_byte in iter( lambda : the_file.read(128*1024), b'' ) :
            the_hash.update( the_byte )

    byte_digest = the_hash.digest()
    int_digest = int( the_hash.hexdigest(), 16 )
    hex_digest = the_hash.hexdigest()

    short_digest = xor_fold( int_digest, 64 )
    
    # return all 4 hashes, different programs need them all
    return ( byte_digest, int_digest, hex_digest, short_digest )

def check_name_against_hash( this_file_name ) :
    """
    Self-check for whether the program has been modified.
    """

    folded_hash = hash_file( this_file_name )[ 3 ]

    hash_in_hex        = folded_hash

    if hash_in_hex not in this_file_name :
        print( "!!!Warning, your program has been modified!!!" )

def generate_random_array( passphrase, array_size ) :
    """
    size_of_array in bytes.

    Returns a string that is the contents of an array of random numbers.
    String is 64-bit unsigned integers in hexadecimal, with line breaks
    to allow fitting on an 60-character line.

    This operates the random generation in ultra-paranoid mode.
    """
    the_rnt       = RNT( 4096, 1, 'desktop', passphrase )

    the_fold = FoldInteger()

    hashes = HASHES( the_rnt, 256, 31 )
    the_hash = hashes.next()

    # instantiate a new PRNG, maximum paranoia here
    lcg  = LcgCrypto(  the_rnt, 19, 256, 31, 1 )
    prng = PrngCrypto( the_rnt, 19, 128, 31, 1 )

    # use it to produce a new array_size array of random numbers 
    # having a line for each 4 0x0123456789ABCDEF number
    # I add 32 numbers so I don't have to check for numbers off the end of
    # the array in using the array to generate pseudo random numbers.
    # that handles 64x32 bits, so random number widths up to 2048 bits.
    # Way more than we are using so far, but this should be a parameter.
    out_line = ''
    for one_line in range( int( array_size / ( 8 * 4 ) ) + 32 ) :
#        sys.stderr.write( "this_line = " + str( one_line ) )
        for one_number in range( 4 ) :
            lcg_rand = the_fold.fold_it( lcg.next( 256, one_number ), 64 )
            prng_rand = prng.next( 64, one_number )

            the_hash.update( lcg_rand + prng_rand)
            hash_rand = the_fold.fold_it( the_hash.intdigest(), 64 )

            this_random = hex( lcg_rand ^ prng_rand ^ hash_rand )

            # all because repr() puts '' around strings
            len_this_random = len( this_random )
            if len_this_random == 18 :
                out_line +=           this_random + ', '
            elif len_this_random == 17 :
                out_line += ' '     + this_random + ', '
            elif len_this_random == 16 :
                out_line += '  '    + this_random + ', '
            elif len_this_random == 15 :
                out_line += '   '   + this_random + ', '
            elif len_this_random == 14 :
                out_line += '    '  + this_random + ', '
            elif len_this_random == 13 :
                out_line += '     ' + this_random + ', '

        out_line += '\n'

#    out_line += '\n\n'

    return out_line


def replace_random_table( the_program_file, the_password, the_size ) :
    """
    Searches for the string 'N_K_RANDOM_BYTES = [' and replaces all of
    the text up to the next ']'
    """

    output_text         = ''
    n_k_found_flag      = False

    this_line  = ''
    for this_line in the_program_file :

#        print(  "the program line = '" + this_line + "'" )

        if this_line == 'N_K_RANDOM_BYTES = [\n' :

            n_k_found_flag = True
            output_text += this_line
            output_text += generate_random_array( the_password, the_size )
            continue

        if this_line == '    ] #END N_K_RANDOM_BYTES\n' :
            output_text += this_line
            n_k_found_flag = False
            continue

        if n_k_found_flag :
            continue

        output_text += this_line

    return output_text


def bytes_to_int( byte_sequence ) :
    """
    I think the struct module does this?
    """
    the_integer = 0
    for this_byte in byte_sequence :
        the_integer <<= 8
        the_integer += this_byte

    return the_integer


def encrypt_file( to_be_encrypted_file_name, password, system_type,
                  paranoia_level ) :
    """
    Uses the standard hash sha512 to produce a check for the
    decode. The hash is always the first 64 bits in the file to be decoded.

    Format of the file name : < original name >  + '_" +
                              < paranoia level > + '_' +
                              < 64-bit folded sha512 hash in hex > +
                              ".evocrypt"

    Format of the file : 64-bytes of hash of the plaintext file,
                         the encrypted file data
                         64-bytes of hash of the cryptotext file,
                         including the plaintext file hash, but
                         necessairly excluding the encrypted text hash itself.

    There are 2 stages of encryption : the first is with the password
    as the only key.
    The 2nd is a new RNT with the integer value of the 512-bit hash
    added to the password.

    23May 2018 encrypt-decrypt tested via ./crypt_test.bash works again.
    Now to take all the debug stuff back out, 2 steps.

    """
    # sha512 is used to test whether the encryption worked or not
    byte_plain_text_digest, int_plain_text_digest, hex_plain_text_digest, \
        short_plain_text_digest = hash_file( to_be_encrypted_file_name )

    # the file needs connected with the hash of the encrypting program,
    # contained in its file name. That is another thing to check before
    # encrypting, of course.

    # get a 512-bit hash of the program, used to make the new file name
    # this is both a part of decoding files and a self-check for the
    # program's integrity ?
    this_file_folded_hash = hash_file( sys.argv[ 0 ] )[ 3 ]
#    print( "this_file_folded_hash = ", this_file_folded_hash )

    # Generate the new name
    if sys.argv[ 0 ][ -3 : ] != '.py' :
        print( "Program name = ", sys.argv[ 0 ] )
        print( "Not a python program? Dangerous to rename your program" )
        sys.exit( 0 )

    this_file_name_hash = sys.argv[ 0 ]
    hash_index = this_file_name_hash.index( '_0x' )
    this_file_name_hash = this_file_name_hash[ hash_index + 1 : -3 ]

    if this_file_name_hash != this_file_folded_hash :
        print( "program hash does not match the name" )
        print( "this_file_name_hash = ", this_file_name_hash )
        print( "this_file_folded_hash = ", this_file_folded_hash )
        sys.exit( 0 )

    encrypted_file_name  = to_be_encrypted_file_name
    encrypted_file_name  += '_' + str( paranoia_level ) 
    encrypted_file_name  += '_' + this_file_folded_hash + ".evocrypt"

    encrypted_fd = open( encrypted_file_name, 'wb')

    # first 64 bytes in the file are the sha512 hash of the original file
    encrypted_fd.write( byte_plain_text_digest )

    # This is what makes every different file have a different
    # encryption key despite using the same password.
    total_password = password + hex_plain_text_digest

    the_rnt        = RNT( 4096, paranoia_level, system_type, total_password )

    the_crypto     = CRYPTO( password, system_type, paranoia_level )
    encode         = the_crypto.next()

    # read the to-be-encrypted file
    plain_file_data = open( to_be_encrypted_file_name, 'rb').read()

    encrypted_bytes = bytearray( len( plain_file_data ) )
    for i in range( len( plain_file_data ) ) :
        # horribly inefficient, but avoids the byte problem
        encrypted_bytes[ i ] = plain_file_data[ i ] ^ encode.next( 8, 1 )

    encrypted_fd.write( encrypted_bytes )
    encrypted_fd.close()

    # To ensure file integrity, the contents are hashed and added to the
    # end of the file.
    byte_cipher_text_digest, int_cipher_text_digest, hex_cipher_text_digest, \
        short_cipher_text_digest = hash_file( encrypted_file_name )

    encrypted_fd = open( encrypted_file_name, 'ab')
    encrypted_fd.write( byte_cipher_text_digest )
    encrypted_fd.close()

    # a test
    cipher_file_data = open( encrypted_file_name, 'rb').read()
    bytes_cipher_text_digest, int_cipher_text_digest, hex_cipher_text_digest, \
        short_cipher_text_digest = hash_text( cipher_file_data[ 0 : 64 ] )

    return encrypted_file_name

def verify_evocrypt_file_name( to_be_decrypted_file_name ) :
    """
    verify it is an evocrypt file
    """

    if '.evocrypt' not in to_be_decrypted_file_name or \
       '_0x'       not in to_be_decrypted_file_name :
        print( "this is not a valid evocrypt encrypted file name" )
        sys.exit( 0 )

    # extract the paranoia level
    paranoia_index = to_be_decrypted_file_name.index( '_0x' )
    paranoia_level = int( to_be_decrypted_file_name[ paranoia_index - 1 ] )

    original_file_name = to_be_decrypted_file_name[ 0 : paranoia_index - 2]

    # verify it has the proper ID for this version of the file 
    evocrypt_index = to_be_decrypted_file_name.index( '.evocrypt' )

    evocrypt_version = \
        to_be_decrypted_file_name[ paranoia_index + 1 : evocrypt_index ]

    return original_file_name

def verify_cipher_text_digest( cipher_file_data ) :
    """
    Checks the digest.
    """
    # As a check on file integrity, hash the initial plain_text hash and
    # the encrypted data, but not the trailing cipher_text hash
    bytes_cipher_text_digest, int_cipher_text_digest, hex_cipher_text_digest, \
        short_cipher_text_digest = hash_text( cipher_file_data[ 0 : -64 ] )

    # compare it to the value in the file
    file_bytes_cipher_text_digest = cipher_file_data[ -64 : ]

    if file_bytes_cipher_text_digest != bytes_cipher_text_digest :
        print( "calculated bytes_cipher_text_digest = ",
               bytes_cipher_text_digest, '\n' )
        print( "file_bytes_cipher_text_digest = ",
               file_bytes_cipher_text_digest, '\n' )
        print( "file has been corrupted" )
        sys.exit( 0 )

# file operations can check names and hashes to ensure valid oprations.

def verify_decrypted_bytes( decrypted_bytes, byte_plain_text_digest ) :
    """
    Checks
    """
#    print( "len decrypted_bytes = ", len( decrypted_bytes ) )
#    print( bytes( decrypted_bytes ) )

    #
    # Hash the plain text and compare to the original hash in the file.
    #
    bytes_plain_digest, int_plain_digest, hex_plain_digest, \
        short_plain_digest = hash_text( decrypted_bytes )

    if byte_plain_text_digest != bytes_plain_digest :
        print( "!!!Error, the decryption is invalid!!!" )
        print( '\nhash_text() of plaintext ',
               '\nbytes plain digest = ', bytes_plain_digest,
               '\nint   plain digest = ', hex( int_plain_digest ), \
               '\nhex   plain digest = ', hex_plain_digest ,
               '\nshort plain digest = ', short_plain_digest, '\n\n' )

#        decode_file = open( "evocrypt_decoded_file.tmp", 'wb' )
#        decode_file.write( bytes( decrypted_bytes ) )
        sys.exit( 0 )

#

def decrypt_file( to_be_decrypted_file_name, password, system_type,
                  paranoia_level ) :
    """
    Decrypts a file, with appropriate checks for integrity.

    Password AND paranoia_level both need to be correct.

    24 April, 2018, this works again using the crypt_test.bash.
    """
    original_file_name = verify_evocrypt_file_name( to_be_decrypted_file_name )

    cipher_file_data = open( to_be_decrypted_file_name, 'rb').read()

    verify_cipher_text_digest( cipher_file_data )

    # first 64 bytes in the file are the sha512 hash of the original file
    byte_plain_text_digest = cipher_file_data[ 0 : 64 ]

    total_password = password + byte_plain_text_digest.hex()

    the_rnt       = RNT( 4096, paranoia_level, 'desktop', total_password )

    the_crypto = CRYPTO( password, system_type, paranoia_level )
    decode     = the_crypto.next()

    # at this point, decode is in the same state as encode, so 
    # we can decipher with the prng stream.

    # temp code to test that assertion.
    samint = 0
    for _ in range( 16 ) :
        samint  = samint << 8 
        samint += decode.next( 8, 1 )

    # 512 bits in each of 2 hashes is added by encrypt()
    cipher_byte_count = ( len( cipher_file_data ) - 128 )

    decrypted_bytes = bytearray( cipher_byte_count )
    for i in range( cipher_byte_count ) :
        # horribly inefficient, but simple, avoids the byte problem
        decrypted_bytes[ i ] = cipher_file_data[ i + 64 ] ^ decode.next( 8, 1 )

    verify_decrypted_bytes( decrypted_bytes, byte_plain_text_digest )

    # this should check candidate names, recursively. Wiping out files
    # by decoding is a real no-no.
    while i in range( 1000 ) : # vast overkill, necessary for testing
        candidate_file_name = original_file_name + '.v' + chr( i )
        if os.path.isfile( candidate_file_name ) :
            new_file_name = candidate_file_name 
            break

    output_file = open( new_file_name, 'wb' )
    output_file.write( decrypted_bytes )
    output_file.close()

    return decrypted_file_name

# Unix utility mode can have no checks done, so the burden of making
# sure operations are correct and files correctly named rests entirely
# on the user.

def crypt( password, system_type, paranoia_level ) :
    """
    the encryption/decryption function using stdio.

    Unix utility mode can have no checks done, so the burden of making
    sure operations are correct and files correctly named rests entirely
    on the person typing commands.

    This works.
    """ 

    the_rnt       = RNT( 4096, paranoia_level, system_type, password )
#   sys.stderr.write( "password hash = " + hex( the_rnt.password_hash ) + '\n' )

    the_crypto    = CRYPTO( password, system_type, paranoia_level )
    crypt_it      = the_crypto.next()

    # at this point, code_it is in a state entirely determined from the
    # password and RNT.

    bin_vector = array( 'B' )
    bin_vector.append( 0 )
             
    while True:
        try :
            in_byte = sys.stdin.read( 1 )
        except IOError as msg :
            break

        if len( in_byte ) == 0 :
            break

        if type( in_byte ) == type( 'a' ) :
            the_byte = ord( in_byte )
        else :
            the_byte = int.from_bytes( in_byte, 'big' )

        # horribly inefficient, but simple, avoids the byte problem
        bin_vector[ 0 ] = the_byte ^ crypt_it.next( 8, paranoia_level )
        if type( in_byte ) == type( 'a' ) :
            sys.stdout.write( chr( bin_vector[ 0 ] ) )
        else :
            bin_vector.tofile( sys.stdout )


def usage() :
    """
    This provides 'help' and other usage information.
    Usage for the initial linux utility version of this program.
    """
    usage_info = """
        This version of the program has 2 modes of operation.  Convenient mode
        encrypts or decrypts files with names and checks handled by the program.

        In the mode of a standard Unix command-line utility, stdin is the source
        and stdout the destination. Encryption and decryption are the same
        operation, so it doesn't need to know the intent.

        --help  Invokes this usage function
        -h      Invokes this usage function

        --password <password>
            The password used for encrypting the file
            Also, the password used to initialize all of the variables
            needed for generating a new program.


        --generate <size )
        -g <size )
            Generates a new random number table of size bytes, in
            16-digit hexadecimal format, 4 per line, line width of 60
            characters

            The array is printed to stdout.

        --encrypt <name>
        -e <name>

        --decrypt <name>
        -d <name>

        If neither --encrypt or --decrypt, evocrypt assumes it is being
        used as a standard Unix utility, input via stdin and output via
        stdout. !!!Warning!!! This assumes you know what you are doing,
        and how to avoid the dangers of a PRNG-XOR stream cipher. Chief
        of those is the danger of using the same PRNG stream twice.
        Don't do that, it can be the key to decoding both files and even
        working back to understanding the PRNG producing the random
        number stream.

        Unix utility mode cannot do checks or handle naming as do the
        encrypt/decrypt mechanisms.

        --paranoia <paranoia_level>
            1, 2, or 3, 3 being maximum paranoia

        --system_type
        -s           'big', 'desktop', 'laptop', 'cellphone' 
            Any Unix laptop can handle 'big' and maximum_paranoia, it
            will just take longer.

        --new <name>
        -n    <name>
            Generate a new program

            Every program is different, even if the same password is
            used again and again.
            
            The new default's program's name is 'evocrypt-xxxxxxxx.py',
            otheerwise <your name>-xxxxxxxx.py where the x's are
            the hex representation of the folded sha512-bit hash of the
            string just before writing it to the file.
    """

#SINGLE_PROGRAM_TO_HERE
    usage_info += """
        --assemble <name>
        -a
            Assemble a single file executable of this development. Each
            begins a new line of descent as each one can generate new
            versions of itself.

            The name of the program is 'evocrypt-xxxxxxxx' where the x's
            are the ?? hash of the string just before writing the file.
        
        --test  <test name>
            adds a test to the list to be executed. can be repeated.
            
            Current tests are:
                'code'  encodes, then decodes plain text

    """
#SINGLE_PROGRAM_FROM_HERE

    print( usage_info)

#
# main begins here, generally test code for the module.
#
if __name__ == "__main__" :

# stderr because stdin/stdout can be used for encryption

    sys.stderr.write( '# ' + __filename__ + ' : ' + __version__ + ' : ' +
                      str( sys.argv[ 1 : ] ) + '\n' )

    # which ones need an '=' ?
    SHORT_ARGS     = "a=d=e=g=hn=s=t="
    LONG_ARGS      = [  'assemble=', 'decrypt=', 'encrypt=', 'generate=',
                        'help', 'new=', 'paranoia=','password=', 'test=' ]

    TEST_LIST      = []        # list of tests to execute
    PASSWORD       = ''
    SYSTEM_TYPE    = 'laptop'   # default
    PARANOIA_LEVEL = 1          # default
    FILE_NAME      = ''

    try :
        OPTS, ARGS = getopt.getopt( sys.argv[ 1 : ], SHORT_ARGS, LONG_ARGS )

    except getopt.GetoptError as msg :
        print( "getopt.GetoptError = " , msg )
        sys.exit( -2 )

    for o, a in OPTS :
#        print( "o = '" + o + "' a = '" + a )
        sys.stdout.flush()
        if o in ( "--help" ) or o in ( "-h" ) :
            usage()
            sys.exit( -2 )

        if o in ( "--password" ) or o in ( "-p" ) :
            PASSWORD = a

        if o in ( "--system_type" ) or o in ( "-s" ) :
            SYSTEM_TYPE = a

        if o in ( "--paranoia" ) :
            PARANOIA_LEVEL = int( a )

        # note these options are sensitive to order, so new has to come
        # after password and paranoia level

        # how to encrypt 2 files together, 2 different passwords, the
        # password used to decrypt determines which one is seen? That
        # is a cool idea in a world that forces you to decrypt files.

        # once we have the concept of filler, diluting the signal, it is
        # easy to mix in a cover file.  This requires the pw in
        # decryption to guide decryption and a process that does not show there
        # is a second file. If that is part of the standard
        # decrypt, there is no way to know which stream is the filler
        # and which the file stream, there is nothing to explain,
        # either.

        if o in ( "--generate" ) or o in ( "-g" ) :
            ARRAY_SIZE_IN_BYTES  = int( a )
            THE_ARRAY = generate_random_array( PASSWORD, ARRAY_SIZE_IN_BYTES )
            print( "THE_ARRAY = ", THE_ARRAY )
            sys.exit( 0 )

        # new is always max paranoia.
        if o in ( "--new" ) or o in ( "-n" ) :
            FILE_NAME = a
            generate_new_program ( PASSWORD, sys.argv[ 0 ], FILE_NAME, 4096 )
            sys.exit( 0 )

        if o in ( "--decrypt" ) or o in ( "-d" ) :
            FILE_NAME = a
            if not PASSWORD :
                print( "you must specify the password before decryption")
                sys.exit( 0 )
            decrypt_file( FILE_NAME, PASSWORD, SYSTEM_TYPE, PARANOIA_LEVEL )
            sys.exit( 0 )

        if o in ( "--encrypt" ) or o in ( "-e" ) :
            FILE_NAME = a
            if not PASSWORD :
                print( "you must specify the password before encryption")
                sys.exit( 0 )
            encrypt_file( FILE_NAME, PASSWORD, SYSTEM_TYPE, PARANOIA_LEVEL )
            sys.exit( 0 )

#SINGLE_PROGRAM_TO_HERE

        if o in ( "--assemble" ) or o in ( "-a" ) :
            # assemble does not require a password
            FILE_NAME  = a
            THE_PROGRAM = assemble_program_from_dev_files() 

            # get a 128-bit hash of the program, used to make the new file name
            # this is both a part of decoding files and a self-check for the
            # program's integrity ?
            FOLDED_HASH = hash_text( THE_PROGRAM )[ 3 ]

            # Generate the new name
            if FILE_NAME[ -3 : ] == '.py' :
                FILE_NAME = FILE_NAME[ 0 : -3 ]

            FILE_NAME = FILE_NAME + '_' + FOLDED_HASH + '.py'

            PROGRAM_FILE = open( FILE_NAME, 'w' )
            PROGRAM_FILE.write( str( THE_PROGRAM ) )
            sys.exit( 0 )

        if o in ( "--test" ) or o in ( "-t" ) :
            TEST_LIST.append( a )

    if 'hash_file' in TEST_LIST :
        print( hash_file( "TestText.txt" ) )

    if 'update_name' in TEST_LIST :
        THE_HASH = hash_file( FILE_NAME )[ 3 ]

        NEW_NAME = FILE_NAME + '_' + THE_HASH

        shutil.copyfile( FILE_NAME, NEW_NAME )

    if 'final' in TEST_LIST :
        # final acceptance test : encode/decode sequence and make two
        # copies of evochat talk to each other.
        print( 'final' )


    if 'check_name' in TEST_LIST :
        print( sys.argv[ 0 ] )
        check_name_against_hash( sys.argv[ 0 ] )



#SINGLE_PROGRAM_FROM_HERE
    #!!! DANGEROUS !!!
    # Here no file operation has been specified, so we use stdin/out
    # example command :
    # ./evocrypt.py --password umberalertness < TODO.crypt > TODO.new \
    # 2> TD.stderr

    crypt( PASSWORD, SYSTEM_TYPE, PARANOIA_LEVEL )

    sys.exit( 0 )
#SINGLE_PROGRAM_TO_HERE
