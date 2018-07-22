#!/usr/bin/python3
"""
This reads an enormous file of integer_width-bit random numbers and sorts them
into a binary output file.

It then scans the sorted list to find duplicates, special values,
currently 0x0 and 0xFFF... (unsigned -1, a conceptual oxymoron description),
and out of order values in the sorted list.

The last is a check on the sort itself, have found none in initial
tests. Ditto special values, which I think are not allowed as output
from the evocprngs.py functions, and probably not from the evoprngs.py
functions. I can't decide whether that is a strength or a weakness in
the cipher, but given how unlikely they would be in a 64-bit number, and
the fact that 0x00 and 0xFF bytes exist in a random distribution in the
64-bit numbers, it doesn't seem like a weakness, so I ignore the
problem.

The duplicate values are likely parts of loops, will write another
search for those.

This program has many entities, so uses overkill on the descriptivenss of
names to avoid any confusion. Elegance is in the mind of the beholder, and
code is read far more often than it is written, so I think it is elegant,
in an overkill sort of way.
"""
#import io
import os
import sys
import getopt
import time
import array
import numpy


def extract_dups_and_special_values( the_sorted_numpy_array ) :
    """
    Scan the array beginning to end, checking for duplicates, zeros,
    ffs, and ??
    """
    shape_tuple = the_sorted_numpy_array.shape
    print( "shape_tuple of sorted numpy array = ", shape_tuple )

    number_of_sorted_integers = the_sorted_numpy_array.size
    print( "number of integers in the sorted numpy array= ",
           number_of_sorted_integers )

    # sort produces low to high, this verifies that visually
    print( hex( the_sorted_numpy_array[ 0 ] ),
           hex( the_sorted_numpy_array[ 1 ] ),
           hex( the_sorted_numpy_array[ 2 ] ),
           hex( the_sorted_numpy_array[ 3 ] ) )

    # list of tuples, ( i, dup )
    list_of_dups                 = []
    # list of tuples, ( i, first_value, second_value )
    list_of_out_of_order_values  = []
    # list of tuples, ( i, special value )
    list_of_special_values       = []
    for i in range( number_of_sorted_integers -1 ) :
        if the_sorted_numpy_array[ i ] == the_sorted_numpy_array[ i + 1 ]  :
            print( "dup at ", i, hex( the_sorted_numpy_array[ i ] ) )
            sys.stdout.flush()
            list_of_dups.append( ( i, hex( the_sorted_numpy_array[i] ) ) )

        if the_sorted_numpy_array[ i ] > the_sorted_numpy_array[ i + 1 ]  :
            print( "out_of_order at ", i, hex( the_sorted_numpy_array[ i ] ),
                                          hex( the_sorted_numpy_array[ i + 1 ]))
            sys.stdout.flush()
            list_of_out_of_order_values.append( ( i,
                                             hex( the_sorted_numpy_array[ i ] ),
                                             hex( the_sorted_numpy_array[i+1])))


        if the_sorted_numpy_array[ i ] == 0x0 or \
            the_sorted_numpy_array[ i ] == 0xFFFFFFFFFFFFFFFFF  :
            print( "0 or ffs at ", i, hex( the_sorted_numpy_array[ i ] ) )
            sys.stdout.flush()
            list_of_special_values.append(( i,
                                           hex( the_sorted_numpy_array[ i ] ) ))


    return list_of_dups, list_of_out_of_order_values, \
           list_of_special_values

#
# I need another one of these that checks for loops, the likely source
# of so many dups
#
def verify_out_of_order_values( the_numpy_array,
                                the_out_of_order_list_of_tuples ) :
    """
    Are the_out_of_order values actually in the original list?
    Not much checking I can do otherwise, and so far I don't see any of
    these anyway, so the sort seems accurate, not generating artifacts.

    Algorithm : this is simple, but there should not be so many, so not
    worth the effort to optimize.
        scan the array for each value, adding i and value to the tuple,
        append the tuple
    """
    unfound_first_values  = []
    unfound_second_values = []
    # list of tuples, ( i, first_value, second_value )
    for the_tuple in enumerate( the_out_of_order_list_of_tuples ) :
        first_value = the_tuple[ 1 ]
        for j in range( the_numpy_array.size ) :
            if the_numpy_array[ j ] == first_value :
                # now find the 2nd value
                second_value = the_tuple[ 2 ]
                for k in range( j, the_numpy_array.size, 1 ) :
                    if the_numpy_array[ k ] == second_value :
                        # OK, found them both, nothing further to do
                        break
                # here, didn't find the 2nd value 
                unfound_second_values.append( second_value )
                break
        # here, didn't find the first value
        unfound_first_values.append( first_value )

    return unfound_first_values, unfound_second_values

def verify_special_values( the_numpy_array, the_special_values_list_of_tuples) :
    """
    Are the special values actually in the original list.

    Algorithm : this is simple, but there should not be many, etc.
        scan the array for each value, append i and value to the list
        Big problem is that there may be dups of 0x0 and 0xffff...
        So keep a starting index for each, begin from there when the
        tuple's value is the special value. May be other special values,
        so make it easy to extend.
    """
    # list of tuples, ( i, special value )
    unfound_special_values  = []
    zeros_last_index        = 0
    ffs_last_index          = 0
    found_the_special_value = False
    for the_tuple in enumerate( the_special_values_list_of_tuples ) :
        special_value = the_tuple[ 1 ]
        if special_value == 0x0 :
            # found one of them, there may be more, so start here for the next
            for j in range( zeros_last_index, the_numpy_array.size, 1 ) :
                if the_numpy_array[ j ] == special_value :
                    zeros_last_index = j + 1
                    found_the_special_value = True
                    break

        # this should be conditional on the integer_width. Someday.
        if special_value == 0xFFFFFFFFFFFFFFFFF  :
            # found one of them, there may be more, so start here for the next
            for j in range( ffs_last_index, the_numpy_array.size, 1 ) :
                if the_numpy_array[ j ] == special_value :
                    ffs_last_index = j + 1
                    found_the_special_value = True
                    break

        # note that if we didn't find the last special value, we won't find any
        # more, as we have exhausted the numpy_array, could optimize
        # here, not worth the code.
        if not found_the_special_value :
            unfound_special_values.append( special_value )

        found_the_special_value = False

    return unfound_special_values

def verify_duplicate_values( the_numpy_array, the_duplicates_list_of_tuples ) :
    """
    Make sure the processing has not somehow generated the dups, etc. by
    showing that each reported dup or special value exists in the unsorted
    file, and reporting their position in it.

    Algorithm : this is simple, but may need to be optimized, seems like
    there are a lot of dups in the hash output.
        scan the unsorted, original, array for each duplicate value,
           append i and value to the list
        Begin at the index of the first searching for the 2nd 
            append the index of the 2nd, and also the difference between 
            1st and 2nd index
            if those are a small set of constants, it was a cycle.

        In fact, keep the differences as a separate list, sort it before
        returning, that may be all I need to clearly see that there are
        one or more cycles. 
    """
    print( "\nverify_duplicate_values" )
    print( "dups list of tuples = ", the_duplicates_list_of_tuples )
    print( "len( dups_list_of_tuples ) = ",
            len( the_duplicates_list_of_tuples ) )
    print( "the_duplicates_list_of_tuples[ 0 ] = ",
            the_duplicates_list_of_tuples[ 0 ] )
    print( "the_duplicates_list_of_tuples[ 1 ] = ",
            the_duplicates_list_of_tuples[ 1 ] )

    # list of tuples, ( i, dup )
    unfound_duplicate_values  = []

    # list_of_tuples ( dup value, 1st_index, 2nd_index, index_diff )
    duplicate_index_diffs_tuples = []
    duplicate_index_diffs_list   = []
    for the_tuple in range( len( the_duplicates_list_of_tuples ) ) :
        print( "the_tuple = ", the_tuple )
        duplicate_value = the_tuple[ 1 ]
        for j in range( the_numpy_array.size ) :
            if the_numpy_array[ j ] == duplicate_value :
                for k in range( j + 1, the_numpy_array.size, 1 ) :
                    if the_numpy_array[ k ] == duplicate_value :
                        # we have found both of them
                        duplicate_index_diffs_tuples.append( (
                                                duplicate_value, j, k, k - j ) )
                        duplicate_index_diffs_list.append( k - j )


    return unfound_duplicate_values, duplicate_index_diffs_tuples, \
           duplicate_index_diffs_list

def save_numpy_array_to_output_file( the_sorted_numpy_array, the_output_file ) :
    """
    Saves the numpy array in a form easy to read back as a numpy array.
    """

    numpy.save( the_output_file, the_sorted_numpy_array )
#                allow_pickle=False, fix_imports=False )

def sort_numpy_array( the_numpy_array ) :
    """
    Sort the list.
    """

    print( "the numpy_array size = ", the_numpy_array.size )

    the_numpy_array_shape_tuple = the_numpy_array.shape
    print( "shape_tuple of numpy array = ", the_numpy_array_shape_tuple )

    the_sorted_numpy_array = numpy.sort( the_numpy_array, None,
                                         kind='quicksort', order=None )

    print( the_sorted_numpy_array.size )

    the_sorted_numpy_array_shape_tuple = the_sorted_numpy_array.shape
    print( "shape_tuple of sorted numpy array = ",
           the_sorted_numpy_array_shape_tuple )



    return  the_sorted_numpy_array

def convert_binary_array_to_numpy_array( the_binary_array ) :
    """
    simple conversion of array.array() to numpy.array()
    """
    #bin_vector = array.array( 'Q' )     # now emits long long

    the_numpy_array = numpy.array( the_binary_array )

    return the_numpy_array

def read_binary_file_to_array( the_binary_file_name, integer_width ) :
    """
    This handles reading the file, passes back the in_memory buffer
    """

    bytes_in_integer     = int( integer_width / 8 )

    binary_file_size = os.path.getsize( the_binary_file_name )
    print( "binary file size = ", binary_file_size )
    number_of_integers_in_file = int( binary_file_size / bytes_in_integer )
    print( "integers in file = ", number_of_integers_in_file )

    dir_path = os.path.dirname(os.path.realpath(__file__))
    random_number_binary_file = open( dir_path + '/' + the_binary_file_name,
                                      "rb" )

    binary_array = array.array( 'Q' )

    binary_array.fromfile( random_number_binary_file,
                           number_of_integers_in_file )
    random_number_binary_file.close()

#    read_length = len( read_data )
#    n_integers = int( read_length / bytes_in_integer ) - 1 # -1 to be sure

    return binary_array, number_of_integers_in_file

def usage() :
    """
    This provides 'help' and other usage information.
    """
    usage_info = """
        --help  Invokes this usage function
        -h      Invokes this usage function

        --file   name of the file to be tested
        --width  width of the integers in the binary file.
    """
    print( usage_info )


if __name__ == "__main__" :

    SHORT_ARGS = "hi=o=w="
    LONG_ARGS  = [  'help' , 'width=', 'input=', 'output=' ]

    INTEGER_WIDTH = 0     # list of tests to execute
    THE_FILE  = ''
    try :
        OPTS, ARGS = getopt.getopt( sys.argv[ 1 : ], SHORT_ARGS, LONG_ARGS )

    except getopt.GetoptError as err :
        sys.stderr.write( "getopt.GetoptError = " + str( err ) )
        sys.exit( -2 )

    for o, a in OPTS :
        if o in ( "--help" ) or o in ( "-h" ) :
            usage()
            sys.exit( -2 )

        if o in ( "--width" ) or o in ( "-w" ) :
            INTEGER_WIDTH = int( a )

        if o in ( "--input") or o in ( "-i" ) :
            THE_INPUT_FILE = a

        if o in ( "--output") or o in ( "-o" ) :
            THE_OUTPUT_FILE = a

print( "\nTHE_INPUT_FILE  = ", THE_INPUT_FILE )
print( "THE_OUTPUT_FILE = ",   THE_OUTPUT_FILE )
print( "INTEGER_WIDTH   = ",   INTEGER_WIDTH, "\n" )

BEGINNING_TIME = time.time()
THE_BINARY_ARRAY, NUMBER_OF_INTEGERS = read_binary_file_to_array(
                                                        THE_INPUT_FILE,
                                                        INTEGER_WIDTH )
ELAPSED_TIME = time.time() - BEGINNING_TIME
print( "Elapsed time for reading the file = ", ELAPSED_TIME )

BEGINNING_TIME = time.time()
THE_NUMPY_ARRAY = convert_binary_array_to_numpy_array( THE_BINARY_ARRAY )
ELAPSED_TIME = time.time() - BEGINNING_TIME
print( "Elapsed time for converting binary numpy.array = ", ELAPSED_TIME )

BEGINNING_TIME = time.time()
THE_SORTED_NUMPY_ARRAY = sort_numpy_array( THE_NUMPY_ARRAY )
ELAPSED_TIME = time.time() - BEGINNING_TIME
print( "Elapsed time for sorting the list = ", ELAPSED_TIME )

BEGINNING_TIME = time.time()
LIST_OF_DUPLICATE_VALUE_TUPLES, LIST_OF_OUT_OF_ORDER_TUPLES, \
LIST_OF_SPECIAL_VALUE_TUPLES = extract_dups_and_special_values(
                                                       THE_SORTED_NUMPY_ARRAY )
ELAPSED_TIME = time.time() - BEGINNING_TIME
print( "Elapsed time for extracting dups and special value = ", ELAPSED_TIME )
print( "list of duplicate tuples = ", LIST_OF_DUPLICATE_VALUE_TUPLES )
print( "list of out_of_order tuples = ", LIST_OF_OUT_OF_ORDER_TUPLES )
print( "list of special value tuples = ", LIST_OF_SPECIAL_VALUE_TUPLES )
                   
BEGINNING_TIME = time.time()
UNVERIFIED_OUT_OF_ORDER_TUPLES = verify_out_of_order_values( THE_NUMPY_ARRAY,
                                LIST_OF_OUT_OF_ORDER_TUPLES )
ELAPSED_TIME = time.time() - BEGINNING_TIME
print( "Elapsed time for verifying out_of_order values = ", ELAPSED_TIME )
print( "unverified out_of_order tuples = ", UNVERIFIED_OUT_OF_ORDER_TUPLES )

BEGINNING_TIME = time.time()
UNVERIFIED_SPECIAL_VALUES_TUPLES = verify_special_values( THE_NUMPY_ARRAY,
                                   LIST_OF_SPECIAL_VALUE_TUPLES )
ELAPSED_TIME = time.time() - BEGINNING_TIME
print( "Elapsed time for verifying special values = ", ELAPSED_TIME )
print( "list of unverified special values = ",
        UNVERIFIED_SPECIAL_VALUES_TUPLES )

BEGINNING_TIME = time.time()
UNVERIFIED_DUPLICATE_VALUE_TUPLES = verify_duplicate_values( THE_NUMPY_ARRAY,
                                           LIST_OF_DUPLICATE_VALUE_TUPLES )
ELAPSED_TIME = time.time() - BEGINNING_TIME
print( "Elapsed time for verifying duplicate values = ", ELAPSED_TIME )
print( "list of unverified duplicate values = ",
UNVERIFIED_DUPLICATE_VALUE_TUPLES )

BEGINNING_TIME = time.time()
save_numpy_array_to_output_file( THE_SORTED_NUMPY_ARRAY, THE_OUTPUT_FILE )
ELAPSED_TIME = time.time() - BEGINNING_TIME
print( "Elapsed time for saving the sorted_numpy_array = ", ELAPSED_TIME )
 
#
# output on the last test. Lengths, etc. are correct, these are the 64-bit
# most- and least-significant halves of 128-bit output of LCG_CRYPTO().
#
# ~/EvoCrypt/test$ ./sort_binary_integer_file.py --width 64 \
# --input 128_bit_lcg_crypto_output_binary_0 \
# --output 128_bit_lcg_crypto_output_binary_0.sorted
#
# THE_INPUT_FILE  =  128_bit_lcg_crypto_output_binary_0
# THE_OUTPUT_FILE =  128_bit_lcg_crypto_output_binary_0.sorted
# INTEGER_WIDTH   =  64 
# 
# binary file size =  68266752
# integers in file =  8533344
# Elapsed time for reading the file =  0.07152438163757324
# Elapsed time for converting binary numpy.array =  0.031618356704711914
# the numpy_array size =  8533344
# shape_tuple of numpy array =  (8533344,)
# 8533344
# shape_tuple of sorted numpy array =  (8533344,)
# Elapsed time for sorting the list =  0.6596450805664062
# shape_tuple of sorted numpy array =  (8533344,)
# number of integers in the sorted numpy array=  8533344
# 0x284975c46ec 0x34fef22297c 0x4de64a54bd4 0x5766e648ae0
# Elapsed time for checking for dups and special value =  47.973814249038696
# Elapsed time for saving the sorted_numpy_array =  0.06818318367004395
#
