#!/usr/bin/python3

import sys
import os
import io
import filecmp
import unittest
import random
import evornt
import copy
from evornt   import RNT
from evocrypt import crypt


from evocrypt import assemble_program_from_dev_files, generate_new_program, \
check_name_against_hash, generate_random_array, replace_random_table, \
encrypt_file, decrypt_file, crypt

def count_duplicates( the_list ) :
    """
    A weak check for randomness, are any values the same?
    16M comparisons for the dumb way on a 4K grid, K**2
    same number of ops as to sort, cheaper operations
    """
    duplicate_tally = 0
    for i in range( len( the_list ) - 1 ) :
        this_random = the_list[ i ]
        for j in range( i + 1, len( the_list ) ) :
            if( this_random == the_list[ j ] ) :
                print( "duplicate = ", this_random, "i = ", i, "j = ", j )
                duplicate_tally += 1

    return duplicate_tally


def chars_to_lines( text_as_chars ) :
    """
    I cannot make this work in the recommended ways.
    """
    this_line = ''
    return_list = []
    for i in range( len( text_as_chars ) ) :
        this_char = text_as_chars[ i ]
        if this_char == '\n' :
#            print( "it was a carriage return" )
            this_line += this_char
#            print( this_line )
            return_list.append( this_line )
            this_line = ''
        else :
            this_line += this_char

    return return_list

def extract_rnt_from_text( text_as_lines ) :
    """
    returns the text of a random number table
    """
    return_text    = ''
    n_k_found_flag = False
    for this_line in text_as_lines :
        if this_line == 'N_K_RANDOM_BYTES = [\n' :
            n_k_found_flag = True
            return_text += this_line
            continue

        if this_line == '    ] #END N_K_RANDOM_BYTES\n' :
            return_text += this_line
            return return_text

        if n_k_found_flag :
            return_text += this_line

def convert_string( the_program ) :
    """
    This is necessary because exec() does not work within the class.
    No idea why, PITA to figure that out.
    """
    exec( the_program, globals() )
    return N_K_RANDOM_BYTES

class TestEvoCrypt( unittest.TestCase ) :

    def __init__( self ) :

        self.the_assembled_program      = None
        self.the_program_list           = None
        self.the_generated_program_name = None

    def setUp( self ) :
        """
        All the stuff needing done for every test.
        """
        # instantiate a random number table
        # hard code desired RNT bytes and paranoia level for now
        random()
        password = 'TestEvoCrypt' + hex( random.getrandbits( 128 ) )
        self.the_rnt = RNT( 4096, password, 'desktop', 1 )
        SO = os.fdopen( sys.stdout.fileno(), 'wb' )
#       SE = os.fdopen( sys.stderr.fileno(), 'wb' )


    def tearDown( self ) :
        pass

    def test_assemble_program( self ) :
        """
        Test the function
        """
        print( "test_assemble_program" )

        the_program = assemble_program_from_dev_files()
        program_out = open( "test_evocrypt_assemble.test", "w" )
        program_out.write( the_program )

#        print( type( the_program ) )
#        print( len( the_program ) )

        text_list   = chars_to_lines( the_program )
#        print( type( text_list ) )
#        print( len( text_list ) )

        # does it pass the interpreter?

        # does it have one function from each of the files?
        function_list = [ 'generate_new_program', 'LcgCrypto',
        'FoldInteger', 'HASHES', 'rabin_miller', 'PRNGs', 'WichmannHill',
        'close_files_and_exit' ]
        
        for this_function_name in function_list :
            self.assertTrue( 'def '   + this_function_name in the_program or \
                             'class ' + this_function_name in the_program,
                             this_function_name )

        self.the_assembled_program = the_program
        self.the_program_list      = text_list

    def test_replace_4K( self ) :
        """
        test the function in the context of the program.
        """
        print( "test_replace_4K" )

        original_table = extract_rnt_from_text( self.the_program_list )
        print( type( original_table ) )
        print( original_table )

        original_table = convert_string( original_table )
        print( type( original_table ) )
        print( original_table )

        comma_count = original_table.count(',')
        print( "n ','s = ", comma_count )

        # check it produced the right length of original table 
        self.assertTrue( len( original_table ) * 8 > 4096,
                        "len( original_table ) = " +
                         str( len( original_table ) ) )

        new_program = replace_random_table( self.the_program_list,
                                          'this is the pw', 4096 )
        text_list      = chars_to_lines( new_program )
        new_table      = extract_rnt_from_text( text_list )
        print( "type( new_table ) = ", type( new_table ) )
        print( new_table )

        new_table = convert_string( new_table )
        print( new_table )

        # check it produced the right length of table
        self.assertTrue( len( new_table ) * 8 > 4096, "len( new_table ) = " +
                         str( len( new_table ) ) )

        # Probabilistic, but 64 bits is a big #, should be OK
        self.assertTrue( count_duplicates( new_table ) == 0 )
        
        for i in range( len( new_table ) ) :
            self.assertFalse( original_table[ i ] == new_table[ i ] )

        print( "test_replace_4K works" )

    def test_generate_new_program( self ) :
        """
        A new program should be identical to the current program,
        except for the RNT random number table and the lists,
        which are scrambled.

        generate_new_program( password, this_file_name, new_file_name,
                          array_size )
        """
        print( "test_generate_new_progrm" )

        new_name = generate_new_program( "frederico",
                                         "test_evocrypt_assemble.test",
                                         "test_evocrypt_generate", 4096 )
        self.the_generated_program_name = new_name


    def test_check_name_against_hash( self ) :
        """
        The hash value in base 16 is appended to the file name.  This
        makes sure they are consistent.

        check_name_against_hash( this_file_name )
        """
        print( "test_check_name_against_hash" )
        check_name_against_hash( self.the_generated_program_name )

    def test_cryption( self ) :
        """
        Encrypts and decrypts this file, compares it to the original.

        Encrypt and decrypt must be tested using an assembled program
        because of the checking done to validate program against
        decryption.

        So this can only test crypt.

        encrypt_file( to_be_encrypted_file_name, password, system_type,
                  paranoia_level ) :
        
        def encrypt_file( to_be_encrypted_file_name, password, system_type,
                  paranoia_level ) 
        """
        print( "test_cryption" )

        # this matches the chat setup.
        passphrase     = 'Frederikco'
        system_type    = 'desktop'
        file_name      = 'test_file_small.txt'
        paranoia_level = 1

        # get the text
        plaintext = open( file_name, 'r' ).read()
        print( "len( plaintext ) = ", len( plaintext ) )
        print( plaintext )

        # Fake stdin and stdout for a bit
        oldstdin   = sys.stdin
        oldstdout  = sys.stdout
        sys.stdin  = io.BytesIO( bytes( plaintext, 'utf-8' ) )
        sys.stdout = io.BytesIO()

        crypt( passphrase, system_type, paranoia_level )

        # retrieve the ciphertext
        sys.stdout.seek( 0 )

        ciphertext = sys.stdout.read()
        if len( ciphertext) == 0 :
            sys.exit( 0 )

        # ciphertext as stdin
        sys.stdin  = io.BytesIO( ciphertext )
        sys.stdout = io.BytesIO()

        crypt( passphrase, system_type, paranoia_level )
        
        # retrieve the decoded text
        sys.stdout.seek( 0 )
        decoded_text = sys.stdout.read()
        
        # restore standard io
        sys.stdin = oldstdin
        sys.stdout = oldstdout

#        print( type( plaintext ) )
#        print( "type( ciphertext ) = ", str( type( ciphertext ) ) )
#        print( "len( ciphertext ) = ",  str( len( ciphertext ) ) )
#        print( decoded_text )

        # check the decoded_text against the plaintext
        self.assertTrue( len( plaintext ) == len( decoded_text ) )
        decoded_text = decoded_text.decode( 'utf-8' )
        for i in range( len( plaintext ) ) :
            self.assertTrue( plaintext[ i ] == decoded_text[ i ],
                             str( i ) + ' ' +
                             plaintext[ i ] + ' ' + 
                             decoded_text[ i ] )

    def test_final_acceptance( self ) :
        """
        the final acceptance test
        """
        print( "test_final_acceptance" )

        the_rnt = RNT( 4096, 'this is a passphrase', 'desktop', 2 )
        self.assertTrue( the_rnt.password_hash != 0, "password hash was zero" )


if __name__ == '__main__':
# nothing I do allows accessing ../ python files from test/
# they show up on the search line, but it doesn't help. There is some
# other file I need to find.
    sys.path.insert( 0, '/home/lew/EvoCrypt' )

#    unittest.main()
    TEST_EVOCRYPT = TestEvoCrypt()
    TEST_EVOCRYPT.test_assemble_program()
    print( "assemble\n" )
    TEST_EVOCRYPT.test_replace_4K()
    print( "replace\n" )
    TEST_EVOCRYPT.test_generate_new_program()
    print( "generate\n" )
    TEST_EVOCRYPT.test_check_name_against_hash()
    print( "check_name\n" )
    TEST_EVOCRYPT.test_cryption()
    print( "cryption\n" )


