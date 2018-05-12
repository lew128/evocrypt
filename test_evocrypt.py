#!/usr/bin/python3

import sys
import unittest
import evornt


class TestEvoCrypt( unittest.TestCase ) :

    def setUp( self ) :

        # instantiate a random number table
        # hard code desired RNT bytes and paranoia level for now
        self.the_rnt = RNT( 4096, 1, 'desktop', 'TestEvoFolds' )
        SO = os.fdopen( sys.stdout.fileno(), 'wb' )
#       SE = os.fdopen( sys.stderr.fileno(), 'wb' )



    def tearDown( self ) :

    def test_replace_4K( self ) :
        """ test the function in the context of the program.
        """
        THIS_PROGRAM = """

import evohashes
import evoprngs


# This is the random number array maintained by RNT. and simulates the
# one in RNT.

FOUR_K_RANDOM_BYTES = [
0X721A614B6C1C32C0,0X6F6EA721BF318B00,0X30B29952AA7A6F07,0XB8CEC23B4E423BD1,
0X16E198C6DEB98C54,0X92DDBA4B5179C720,0X55AA3900E33EAEF0,0X1E8472171E55F19E,
0XA98258446FC18757,0X401A7757E1E04228,0XC08756D3E4929978,0XFEB312D927880452,
0X30AA0165E13A892C,0X61AA5AF433FF81C0,0XEE4788C2F8B2DC8A,0X3279550CEB9FB4A4,
0XCFB43E585BC2E78E,0X3717F49C3AFE798A,0X2745D67141A8860B,0X1AB27578CA75A9B1,
0X137937F86B36FC4D,0X3F104B940F2A7D1,0X4DB21F27731689A0,0X6CC76EF50E7AA38B,
0X2DC3D16E23F541A4,0X2BCAD5CF063E6C76,0XA8A4B59B3C3CD5AC,0X46ECD827CAB0D4E,
0XCC0FCF84FD677C09,0XE4F30943FD5F3416,0X30B1249789815E7A,0X3C8B8994897420F5,
0X6327ABA3F74A0324,0XACEE06EC1E8F484E,0XE20E2396CBA37CFA,0XAF451806FC0005D1,
0X436DCDFCFBFDB683,0X6172838B24C4B9DC,0X8F9BF0683948D8BB,0X3D9FE0873A06C499,
0X600FD27AB8E46C97,0X673CE6E00D4CCE92,0XF50E544E15CB5343,0XECA9B1FB87552A01,
0XB175CDD2476BAF3B,0X8641D89399C69103,0X66D9D080D365931B,0X7E9ACEE8C1AD9C09,
0X384D360A845DE5BE,0X3B76F85FB948045F,0XA2F8B3CBDAA6F79B,0X3EAC17C722193D9,
0XACDF68CC5C95F7F0,0X58FF384C30282F6E,0X80588F8FD343992,0XA87C2BBB28DDB9E1,
0X826882EE42C381F1,0XB3F18A024A6EFE79,0XE5013C13DACA28A3,0X494E2881FB5B8562,
]
more program here
"""

        original_table = copy.deepcopy( self.the_rnt.rnt )

        new_table = replace_4k_randoms( this_program, 'this is the pw' )

        # Probabilistic, but 64 bits is a big #, should be OK
        for i in range( int( 4096 / 16 ) ) :
            self.assertFalse( original_table[ i ] == new_table[ i ] )

    def test_assemble_program( self ) :
        the_program = assemble_program_from_dev_files()

        # does it pass the interpreter?

        # does it have one function from each of the files?
        funtion_list = [ 'assemble_program_from_dev_files', ]

        for this_function in function_list :

            self.assertTrue( 'def ' + this_function_name in the_program )

    def test_generate_new_program( self ) :
        """
        A new program should be identical to the current program,
        except for the RNT random number table and the lists,
        which are scrambled.
        """
        pass

    def test_hash_the_file( self, file_name ) :
        """
        Return the standard hash of the file.
        """
        self.assertTrue(  )

    def test_check_name_against_hash( self ) :
        """
        The hash value in base 16 is appended to the file name.  This
        makes sure they are consistent.
        """
        self.assertTrue( initial_list[ i ] in scrambled_list,
        ( "This value is not in the scrambled list", initial_list[ i ] ) )

    def test_cryption( self ) :
        """
        Encrypts and decrypts this file, compares it to the original.
        """

    def test_final_acceptance( self ) :
        """
        """
        print( "test_final_acceptance" )

        the_rnt = RNT( 4096, 2, 'this is a passphrase' )
        self.assertTrue( the_rnt.password_hash != 0, "password has was zero" )

        """
        """

if __name__ == '__main__':
#    sys.path.append( '../' )
    sys.path.insert( 0, '/home/lew/EvoCrypt' )

    import copy
    from evornt   import RNT
    from evocrypt import crypt

    unittest.main()
