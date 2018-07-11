#!/usr/bin/python3
"""
Tests of the evoprngs.py code.

2018/06/23 this ran with no duplicates found.

That is not a strong test of randomness, more a simple check that the
code is working.
"""

import sys
import random

import unittest
import time

from evoprimes import get_next_higher_prime
from evofolds  import FoldInteger
from evornt    import RNT
from evoprngs  import LCG, byte_rate, PRNGs
from evocprngs import CRYPTO, generate_constants, generate_random_table,\
                      LcgCrypto,PrngCrypto, HashCrypto

"""
random_table = [ \
0X1E01DFE75E1EA19B,0X4337B61567BC7D63,0XC9FDCE53665EDBE2,0X23AE53FB975A8F79,
0XA1E34874964DE171,0X26DBA2D87191418D,0XC8537A73EADFA207, 0X6E3B78FD7D9A75,
0XD9FD45CEAA322AF8,0X9B3F8701C7A43201,0X70FD56F1BBA2E06B,0X1353BB98BA501409,
0XED8F29B5CD3C61EB,0X8DFD99A074B94502,0XE0935355E1F0B226,0XAD5B48C07F5F4CBC,
0XE4370D0D05F4140A,0X2299AED07A3C39B8,0XB1F9ECC9CC69BD29,0XA3B3451672C0BCA1,
0XD0536B7EB4C0D106,0X7134D5C2D53888D6,0X710F59D1F4582E31,0XF2EF00885CD2371C,
0X72B655061DC9C263,0XA87C3DD03B4ADD7E,0X4D16F22C2C8263B9,0XF9BF232D0824B958,
0X96D8CEF8EA856B31,0X1DA0B43F317B2011,0X1430C76D84FFF46D,0X643F5E6E5BBC7DB6,
0X9AE8AE8E49C9F230,0X574840E1F2993D6F,0X27CEDA940DCE88E8, 0X5312ED92744E92B,
0X8E7A35F33ACB6967,0X2A73C9462F9EA590,0XCD13FF00D2E3A6A0,0XB690EF252BEF3EBD,
0XC34C6E3AD584CC66,0XCCF4466A2D348D8A,0X6D84C8E21F04F7AC,0XA30C81EE019062E2,
0X5D61E9D36DE7BEE0,0XD94E5879E341B48C,0X75350ADDAA005D4A,0X5EF3E3A053CB8778,
0X51B3A196BAFA46D5,0XEA25D44B4F06542B,0X9A2CCD591D8B58EC,0XFC3494C5374667F8,
0X3368CB7772C76DF4, 0XE841BF53C0C3DAB,0X769AE1361BE74D58,0X1288137F8A09753B,
0X12D40E117B17E1E4,0X1950DE1E1402E95F,0X78CBA9390FA1283D,0X2CB7222E0EB98F35,
0X83CFABD5620A3487,0X5A39F6A10295ABD1,0X55C4F6264F5F0E6F,0X8155DA26AC0D9D09,
0XAC1F87F42023FA8D,0X4E2A0437683D6E34,0X128CFFCEAA2EC752,0XF81E35EA55978F0E,
0X1548C1091739EA05,0XD33CB0099D42EA8D,0X77F650AF77B7F50C,0X7ED59684EACA5A9A,
0XE938D14C5E4CFCAD,0X8E584564D4FC4785,0XEA5AD0BF69CC333F,0X44DF14E6D2998A33,
0XC578F64F13AD6D06,0X3D0DA2DFC7A77CE4,0XDD9D87CE185C8875,0XBF75D09227A0D3C0,
 0X5A732013DD9CEAA,0X448AC747F5BE2C97,0X30131E6A05F2408A,0XBA1E5C1D9D280441,
0XE61770A3EB656440,0XB7102CE89EB3C93C,0X7122653ABC3270C2,0X376D6C32A68899A2,
0XD55A13BE3C588900,0XE6FE6F483D3E1D50,0XE9C67E0710BD4432,0XFC366A6CB1575DE5,
0XF36639642D4232B9,0X606B00E5EA32ACAC,0XFCE86168D6565C79,0XEB71A2DABBC33766,
0X18E7BFF94CA21382,0X2F44B44DFDF01A0B,0X1FD2FC3BF261FE0A, 0XDD5B5FC66F31FBB,
 0XF203CC27668C220,0X15D214E5C033ACD1,0XC8123303EB60A717,0X58862221674ED933,
0X59379C33654ED182,0XE3C5D1D4AE49AC9A,0X63A9D350B3B303BD,0XEB18F2735B275410,
0X21B4346A810135D4,0XA0C4A203EBA265B3,0XC59E84E158E50419,0XBA1F0C145611BB3A,
0X5D830B5DDDA0786F,0XBB529CD96C627C6F,0XAA03A1CB024F1204,0XA77F97F3BF948BD3,
0X47E696B9B7810272,0XDCDF857A88D09BDC,0XE71F319725FC6384,0X28683B310CF82E59,
 0XE14022D9ACD0EDB,0X161C98F31254E2E3,0X864DD7CAD3066558,0X3CBB8F4E83690ABE,
0XCB1B5003C6B4E882,0X2B61DEA4C56D985E,0X478A697E078F97E3,0X8B6EFFC7CA7D5DEB,
0XF40D33108F2F852A,0X9B914F0FD85C00C0,0X59D7B7A5EC3D7324,0X5E04579586CF724A,
0X6E76D8EC69BC09B0,0XDF615D253ECEAB63,0XB0CA376DC7378DC9,0X4E736305A650DEA6,
0X6D0573F6FE6BB2C7,0X769E33C7FF084A70,0XA6280D306B6D6226,0XD70D2D506594034B,
0XBE82AD0427383B70,0X7D73DD9518244F6A, 0X4DCF7CF3DFF8860,0XCF9DDD3B4443906B,
0X727D09A68A1209CF,0X97D270062CACFFB9,0X50362B587FEEA1FA,0X4F49FF2CA32C9DE8,
0X25EB582ED677AB37, 0X10077AFC5377F82,0X3516370FFFA80739,0XDFB2FB866EE528FA,
0XD83150899F3A004E,0XDF4009C2328E6CB7,0XFA4354F82D431AE8,0X47FE8525F58D2544,
0X7E985F03BCE9111F,0XBF714ADD3DB755A0,0XCC351F61801A629D, 0X727DB753D01F0D6,
0X6DA85CDC172A1D8F,0XB631F394DCC74873,0XAA9F751CED3001CC,0X631396663968B84C,
0X1CFA027236BC0336,0X2AEDB8F0279E8867,0XAF2FA6911CDFC664,0XC51B79AE152DE8CB,
0X82FC23DE84A7FD06,0X387D142B72695947,0X6D3F49815C44B141,0X1AD545C9AC8D9F20,
0XF203429B03005776,0X548ED64F05B7C724,0X4F36C3368B3DCCEB,0XE5B07E17C7B39FDB,
 0XA4526CBBEB73B8EB, 0XB02A649DA030B87,0X7C18FF63D2F68E4A, 0X9981E3803A4B24,
0XC3DDB1E23F69BC7F,0X967CDB78C6069E39,0X254F2D54FFD36F39,0X6358B8311E1F152E,
0X5E80587512467A26,0XCC48D5202E168B37, 0XBA1CD5B27287BED,0X8BA89D76D2BD00DB,
0X1111CF6958039E9F,0XF3317964D80D9A9B,0X44A4C757146CAC26,0XB263D1BCD69347FE,
0X1FEEA19999135B5C,0X2E5E0B1D95FA8276,0XFBFACFE53B58F553,0X5EEAB9793A17F275,
0X10B01A1F7C9614D5,0XF73B745300658B6D,0X62787276C3FAFEAF,0X22FA4E0C2F3E66F9,
0X323381F4C3135329,0X550C81E5D419794B,0X7EE20D982CB87B8E,0XC8F2670F8CDE8557,
0XAE8EC869524456ED,0X575191FCD1CDA4F7,0X3A4C241FA2F87019,0XAAEB1A3DBBD6D1DC,
0XBFF144DF5B37713B,0X9A164F6AF5174A05, 0X22EC67E522A34B3,0XCFBDBEF620D7C10B,
0X91D9BED6BC4DAA94,0X4F75BD1C95229B3B,0XE2065F14AA1C69EB, 0XD1A3EC295415FFE,
0X46DEA870F273F303,0XD8A7417F3299E0EA,0XF4CC2B94D7F4E0D0,0X748C8E0B7324A065,
0XEDDC4BB5A28F8118,0XA0B5DBE027FF23A6,0X9978F129211E8F19,0X49E0E7370415789F,
0X76D1DFD74B01A248,0XC6F7D4E93E53A306,0XF1FEB72059C7055C, 0XEDDBC60F344C287,
0X553CAD87F2394E56,0XBA849D5A63D21607,0X1FED8A7B3A8A2DFE,0XAD2D775C0E0AD3C4,
0X60BC50397A3EEEF1,0X916C9034C042B83C,0XD08BF8DA6D4ECA49,0X2E1FAA9F0B845AA2,
0XAFC0E8531B17594D,0X36DD66FE3B79E035,0X17AEE9C924019BDD,0XDB96F2D165739A26,
0XB61C87F80EC6CC13,0XB06C14727BC345EB,0X4A526868E7706F71,0X3A1DA6540253C557,
0XB4C343333D140FC6, 0XA0A8AC1A87151CD,0X9ADB935C68FFD4E2,0XA47848567BCFF4FA,
0XC8A8F837B72FD1CB,0XEC7F76D3F76E7601,0X357B523CC247008A,0XD7D6447DDE9BA4FE,
0X66706143B8EB4219,0X95DA4F72AA15B801,0XE107425B465BBBE4,0XD97782F67FE7863B,
0X1DF80C1E5B9A4121, 0X723AA5AD46B1497,0XD11483B1C9CE9EDD,0X58B0CC5DD28FD81D,
0XB21804D83F63C917,0X280639141701119F,0X27636E98EFEE37E3,0XC226D69CAAD240D1,
0XF30F60AF5A895C08,0XBF2F513D86AE1921,0XB01BFC0AAE99153E,0X5299C6CF1D99EED5,
0X259B6733B8F4B2FC,0XE476599782A05A5F,0X77D377373B2FC671,0X10DFD112FA137230,
0X930A42F879927446,0XA01F8CF6749DC176,0X1BEF6B3B71DC22D1, 0X117B3F2C8B2A5E1,
0XD51F24C77BFCAE44,0XA79FC9C3BC4E1435,0XAC97CE2A070974C2,0X46332F34898534F2,
0X14F75B89658289FD,0X6D457A83A785BC62,0XE0BB9B6D6AAC37C7,0X7FF511E672C23B47,
0XB86BDA4C7CD9024D,0X54AD42C8D8DCD2EE,0X6486FF8461AB560E,0X903E18327F274910,
0XDDE63AF45CFF3265,0XA4268BF7B5552CF0,0X84CCAA9601A2CA91,0X875979BACC4255D7,
0X5E38B7EA6C248F27,0X144B933C82991B08,0XF5E6B618E6CBF824, 0XF50CF577BA79DD6,
0X2A088FA7BD7A24C6,0XE11280C3FCFDB516,0X7C179F7004D9A408,0X524FD3F098EA8BC2,
0X28B8A77FF9421F93,0X44A6EE2835F3D75A,0X9667620903D77BD2,0X6E1401AA0345D160,
0X7BA26D5605047C8B,0X599F96161CB0EE1A,0XD3ADE474E8AF4CBC,0XB4822149E819033D,
0XD6D70477C90E934B,0X7C2F4C02E1AC64BA, 0XA60E714B6CA40DC,0X8DA04C07D5161BDE,
0XD397352AB09004E3,0X562C2B4DE37886D0,0XC969B084BCD77CA8,0X743AFD54BD528178,
0X86F21B1DC4DC2414,0XD1C5865FD31D1C7F,0XCFD8B50CD1504348,0X9EDB24E722B6BEBA,
0X729613E1317C81B2,0X8A138F07942669C7,0X9C80947A90E98078,0X4DD253465C1D44CC,
0X81A278B42700656E,0XAC6A333ED8875DCF,0X82D8490F50F1EB8E,0XD84DA48D00ADD00B,
0X2719F7B460A41172,0XF8326D77D52D187E,0X1993A0F0AD84CB1B,0X992611E7B6DBAE7A,
0X3868C08C6E2DBB58,0XC4B0CCF2FEE8D35B,0XF8844584D690177F,0X590C570922EFCD68,
0XA1CC327A90FB2FFE,0X17349F0C9D71463D,0XC62C8EE558E6FDE5,0X6D4E9786390F5607,
0X2E82F8FBF23F9288,0X9CB108EF1A89B9FE,0X336859B2F42944CA,0XB6A3A11D8CEEA5F7,
0X6A9A4C3CE2C62F23,0X73ACBEBB9F09254C,0XC240DF73CA4295A6,0X5FCE2EF4B153E481,
0X9463EAAF1A6EFB4F,0X2CA4816FB67886D2, 0X36464111C072B1F,0X75C7379D0D08D4F2,
0XA6B90CDCF874ECD5,0X1E2447F07A0B8A93,0X2765740E382C2636,0X8CA45689D5E1E1F8,
0XCB70AD720A48F3D4,0X86263B22C0713CFE,0X57CBE3676B212C98,0X9B144FF5E97033E4,
0X78F02F6D6775267E,0X8B79777A2A9F064A,0X84D9431DA40AE92A, 0X4B0C633074668B2,
0XC26F593BAF9346A5,0XB3E8A4994D2FABAE, 0XA8BFAB28FB47992,0X3525C1F7ADCCE237,
0X91B7FC954FC3E14C, 0XD5911DBCC2FC0D6,0X532BE4F2C5EADEC5,0X11A9E86A92588344,
0XEE141F79D6300A50,0X7A37EF3F989B2568,0XEEC982F14A12554E,0XEAD2CA4E35D0A4BB,
0XF5BE0A159E05D7AD,0X801A605EB41BDC51,0XBE02E627F4D315A7, 0XB6A65BB01AEDDB7,
0XE53FC874B4FDD40F, 0X2C7102659517A0C,0X3B70F57CBA980778,0X6550E0DF49EC658F,
0XA4C08FC497698658,0XA841BD299F8F9456,0X163429FA46963974,0XBBA750B57BEA3108,
0XA3234A1F1AA62F6,0X40C6D3616B29143F,0X72F19617701B35E0,0XF5405D77D855EBBB,
0XE73774EC333DC524,0XAFBB3D724722DB56,0X83C1136923BA3BC4,0X8A08B59ADB5EE5A3,
0XC042C3645930B4CA,0XE7DC12F28C12D069,0XD2F92B0D6BD11DA3,0X3EF988E669DC6963,
0X211CCCEED8B68B8C,0X7077B6CDAA522C84,0XAE60B5E150D8597F,0XB0DAAAC61B61AA25,
0X6280C155E1F14BEB,0X63C58E8E7514B4DD,0X6DFD5D60BF3A5E72,0XBAA8308014A30B7F,
0XBA914564D2E7FBBF,0X2B2797A4D3CB2345,0X66B5E80AF3B65DEA,0XE15026F351BC7E0C,
0X83872365674443C5,0X93592A59510A26D6,0X9F5D4D1A1D0C750D,0X15FBE24C551724DB,
0XF3C1D73BA637660D,0X30A3C168AF10543B,0X3CBE779B22EB27B8,0XC8FA9842B4B09E18,
0XAC63D53DE6250B0C,0X2E36BAE35794CA8D,0X9EF3715736B714B2,0X17659D62085D4BC0,
0X56463DF812E839C8,0X910D28DF7C2D6F25,0X422C46D23CD8F4F8,0X53172BB16178B5B1,
0XF8250CAB21F42433,0X78C09D3CBA1A903D,0XF33D3163A1E52CD2,0X899751F2E288F114,
0X77E4553ECCF6D361,0X7355B09C3A465177, 0X7C9A83A058CD2D4,0X893F0398A6F8869C,
0XB4899E8981AFFF47, 0X9D2840E182EBFF7,0XF118B467A9890A86,0X41B3897F5084B661,
0XECC3157310D5F686,0XD1682183EA2036B0, 0X75A0ED97B318AAC,0X23A35616438B15C3,
0X6E07399A95B68E16,0XE573E2A3CC6BAA87,0X1CE4A51FEFBA309D,0X56A76F18C2E2E122,
0XA72CE9A409F11822,0X3A4A296AD6ACE310,0X32B8BAC91874F4F6, 0X28ADF29EA41B86B,
0X673873759719BF6C,0X680B98A0BC6B65CE,0X5903B8AF97547E36,0XCF5E6D0A71ABCE9A,
0X20E86501D7ED930C,0XE9E01A27A3E16253,0X2F823A88D731C83E,0XCCF147050167D81B,
0X2805B1CE8D71A2EC,0X255BBF811E405069,0X1B5E6E5B45F77C82,0X5082E2537E056DAD,
0X30092DC35B054390,0XBFED20A8EE8BF544,0XBAAB391F7C3E21E1,0XFFAF4B81DC415316,
0XCA09C699134F7B2A,0X59706E901E68BE90,0X9F05B5D20A123A56,0XE2E94B482D4B86CB,
0XB30B9A5183736624,0X49B1663AC2AB9CF3,0X327010F1C2F6B447,0X72917A6B34B4CF4E,
0X928A3EB464605150,0XD99484EFCC356A1D,0X17F8E2247F159561,0XD2DD45E549563AF0,
0XC8E800A655797B7B,0X73970B1A8BDF8F81,0X6049345022B0B5B7,0XE0BEB2293F2F9BE8,
0X8C9C6DAAF39F33B3,0X35B2B3AB9CD40CCA, 0X2DCA5B89BCE9EC5,0X1F72A0E6E898D5B0,
0X9C90214F2562ED92,0X3C79B6AB12EE9031,0XF7A5E148312213CF,0X8B57C042AA5B7FDC,
0X4E3718E0D25A0CF6,0XAE4DC0AD273DAB0C,0X7F48ECFDB346EAC8,0X64F48D6E3EAF5313,
0XCC190758CDAEBA8D,0XB4C499912FBD9CEA,0X9D3959436C10215A,0XF797BAB9B745D100,
0X30FF83B6054B10CF,0XA9A32AF50AF1EB8F,0XE5D01DF5EB6A7A40, 0X46829579EA1AE7F,
0XA106498AFE113B76,0XB7687839E9B1A2A0,0X3A6DAAFD5C9F50E9,0X81F93F8577564520,
0X4DD7188F5B66C2D5, 0XB77991A4DD7A072,0XB70C8CDC4166F15F,0XB429BADC8BE208CC ]
"""

def count_duplicates( the_list ) :
    """
    A weak check for randomness, are any values the same?
    16M comparisons for the dumb way on a 4K grid, K**2
    same number of ops as to sort, cheaper operations
    """
#    print( "count_duplicates, len( the_list ) = ", len( the_list ) )
    duplicate_tally = 0
    for i in range( len( the_list ) - 1 ) :
        the_random = the_list[ i ]
#        print( "i = ", i )
        for j in range( i + 1, len( the_list ) ) :
            if( the_random == the_list[ j ] ) :
                print( "duplicate = ", hex( the_random ) , "i = ", i,
                       "j = ", j )
                duplicate_tally += 1

    return duplicate_tally

def count_zeros( the_list ) :
    """
    Zero should not be a returned value.
    """
#    print( "count_zeros, len( the_list ) = ", len( the_list ) )
    zero_tally = 0
    for the_random in enumerate( the_list ) :
        if the_random == 0 :
            print( "zero = ", hex( the_random ) )
            zero_tally += 1
    return zero_tally

def count_all_fs( the_list, integer_width ) :
    """
    0xFFFF... should not be a returned value.
    How to represent the general case?
    """
#    print( "count_minus_ones, len( the_list ) = ", len( the_list ) )
    all_fs = ( 1 << integer_width ) - 1
    fs_tally = 0
    for the_random in enumerate( the_list ) :
        if the_random == all_fs :
            print( "All ffs.. = ", hex( the_random ) )
            fs_tally += 1
    return fs_tally

def check_limits( the_crypto, the_rnt, lower_limit, difficulty ) :
    """
    This commons out the rate checking
    """
    print( "the_crypto      = ", the_crypto )
    print( "the_crypto.next = ", the_crypto.next )

    # instantiate the crypto
    the_function = the_crypto( the_rnt, 19, 64, 29, 1 )

    crypto_byte_rate = byte_rate( the_function, 64, difficulty * 1024*1024 )
    print( str( the_crypto ) + "byte rate = " + ' ' + str( crypto_byte_rate) + \
           ' ' + str( lower_limit ) )

    if crypto_byte_rate < lower_limit :
        return False

    return True

def check_function( self, the_function, the_rnt ) :
    """
    Commons out the code checking function settings for randomness

    Interesting to see that the rates go up with increasing width of
    word. No doubt because it is spending proportionately time in highly
    optimized math routines.

    Lots of patterns in that data, not a waste of time, but insight/hour
    is low, I think.

    24 June 2018 -- the first set of 32-bit tests consistently have a
    duplicate, just one. Always with paranoia level 2, tho not so many
    only the last 3 runs of test_evocprngs.py show this.

    Actually, all of them do, because it is the same sequence every
    time, I don't have outside entropy. Fixed that.

    5 July, 2018 I made the executive decision to prohibit 32-bit
    integers for the PRNs and hashes. I could produce code that
    passed Dieharder, but not cleanly, and had dups, 0s and all FFs,
    0xFFF... So, given that everything is 64 bit now, including cell
    phones, further effort wasn't time-effective.

    Further analysis indicates that the dups are legit, birthday
    paradox. The fact that thee are 14-18 dups / 1M randoms is
    plausible, tho I haven't had the mental energy to grasp those
    equations and try them out, and they all give the 50% probability
    number for a given size of the sampled unvierse, so it isn't
    straightfoward from what I have read so far.

    I don't have a good explanation for the 0s and ffs. That is too high
    a probability of a particular number, far too high.
    And I see the same now in the 64-bit randoms, it must be due to the
    fold, and or the next() function, the dump of the integer vectors
    does not reveal anything obvious, they look random to me.

    Need more debug info. Tomorrow.
    """
    print( the_function )
    print( "vec_size int_width statesize p_lvl difficulty " +
           "duplicates zeros all ff's elapsed time byterate" )
    sys.stdout.flush()

    function_return = True
    n_samples = self.difficulty * 64 * 1024
    random_table = [ 0 for _ in range( n_samples ) ]
    for n_lcgs in [ 7, 11, 19 ] :
        for integer_width in [ 64, 128 ] :
            for lcg_depth in [ 9, 17 ] :
                for paranoia_level in [ 1, 2 ] :
                    beginning_time = int( time.time() )
                    the_crypto = the_function( the_rnt, n_lcgs,
                                               integer_width, lcg_depth,
                                               paranoia_level )
                    for i in range( n_samples ) :
                        # this becomes slower over time. Why?
                        new_random = the_crypto.next( integer_width,
                                                      paranoia_level )
                        random_table[ i ] = new_random

                    ending_time = int( time.time() )
    
                    sys.stdout.flush()

                    elapsed_time = ending_time - beginning_time 
                    if elapsed_time == 0 :
                        elapsed_time = 1
                    byte_rate = ( n_samples * ( integer_width / 8 )) / \
                                                elapsed_time

                    duplicates       = count_duplicates( random_table )
                    function_return &= duplicates == 0

                    zeros            = count_zeros( random_table )
                    function_return &= zeros == 0

                    # these are not signed numbers, 0xFFFF... is problem
                    all_fs = count_all_fs( random_table, integer_width )
                    function_return &= all_fs == 0

                    print( "%5d %10d %8d %7d %10d %7d %7d %7d %7d %18.2f" %
                           ( n_lcgs, integer_width, lcg_depth, paranoia_level,
                             n_samples, duplicates, zeros, all_fs, 
                             ending_time - beginning_time, byte_rate ) )

                    sys.stdout.flush()

    self.assertTrue( function_return )

def convert_string( the_program ) :
    """
    This is necessary because exec() does not work within the class.
    No idea why, PITAkkkk to figure that out.
    """
    exec( the_program, globals() )
    return N_K_RANDOM_BYTES

class TestEvoCPrngs( unittest.TestCase ) :
    """
    tests of functions in evocprngs.py
    """
    def __init__( self, difficulty_level ) :
        """
        setUp, including setting the difficulty
        """
        self.difficulty = difficulty_level
        self.system_type = 'desktop'
        self.the_rnt     = None
        self.the_fold    = None
        self.n_samples   = 32 * 1024
        self.test_name   = 'sam_colt, peacmaker'

        print( "self.difficulty = ", self.difficulty )

    def setUp( self ) :
        """
        This is run before every test.
        """
        # instantiate a random number table
        # need a different password every run
        # test_name is necessarily the last test? How to know the name of
        # the next test inside setUp? doesn't really matter, so long as
        # different.

        self.the_fold    = FoldInteger()

        random.seed()

        # a random password so the runs are different.
        password = 'TestEvoCPrngs' + self.test_name
        password += hex( random.getrandbits( 128 ) )
        self.the_rnt = RNT( 4096, password, self.system_type, 2 )

        sys.stdout.flush()

    def test_generate_constants( self ) :
        """
        Just to be sure the constants returned by the generator are reasonable
        and the correct number.
        """
        print( "test_generate_constants" )

        entropy_bits = \
              0xd262fbc7cbc7e757d16234bd7e88f12cc5dfef7c2ee82c9a4e289113d83d8724
        n_prngs = 19
        for integer_width in [ 64, 128, 256 ] :

            for n_prngs in [ 7, 19, 31 ] :
                constant_generator = generate_constants( integer_width, n_prngs,
                                                    entropy_bits )

            for _ in range( n_prngs ) :
                multiplier, addition, lag, delta = next( constant_generator)
                print( multiplier, addition, lag, delta )

            try :
                multiplier, addition, lag, delta = next( constant_generator)

            except StopIteration :
                print( "StopIteration -- Proper result" )

        print( "success test_generate_constants" )


    def test_generate_random_table( self ) :
        """
        Just what it says, do we produce a good random table?
        Real randomness is not for these tests, that is dieharder for
        components.  This just makes sure something stupid isn't wrong.
        Dieharder is part of the final acceptance test, this is just
        simple software checks.
        """
        print( "\ntest_generate_random_table" )
        self.test_name = 'test_generate_random_table'

        self.setUp()

        str_random_table = generate_random_table( self.the_rnt, 4096, 64 )

        # that is strings, so need an integer array
        the_program = '\nN_K_RANDOM_BYTES=[\n' + \
                            str_random_table + ']\n'

        N_K_RANDOM_BYTES = convert_string( the_program )
 
        self.assertTrue( count_duplicates( N_K_RANDOM_BYTES ) == 0 )
        self.assertTrue( count_zeros(      N_K_RANDOM_BYTES ) == 0 )

    # the rest of these are quick versions of dieharder tests from evocprngs.py
    #
    # the rate tests
    def test_lcg_crypto_rate( self ) :
        """
        verifies that the rate is > a minimum, warns about loss of
        performance as things change.
        """
        print( "\ntest_lcg_crypto_rate" )
        self.test_name = 'test_lcg_crypto_rate'

        self.setUp()    # setup() after setting test_name

        lower_limit = 2000

        self.assertTrue( check_limits( LcgCrypto, self.the_rnt, lower_limit,
                                       self.difficulty))

    def test_prng_crypto_rate( self ) :
        """
        Verify minimum rate of producing the variables.
        """
        print( "\ntest_prng_crypto_rate" )
        self.test_name = 'test_prng_crypto_rate'

        self.setUp()    # setup() after setting test_name

        lower_limit = 5000

        self.assertTrue( check_limits( PrngCrypto, self.the_rnt, lower_limit,
                                       self.difficulty))

    def test_hash_crypto_rate( self ) :
        """
        Verify minimum rate of producing the variables.
        """
        print( "\ntest_hash_crypto_rate" )
        self.test_name = 'test_hash_crypto_rate'

        self.setUp()    # setup() after setting test_name

        lower_limit = 12000

        self.assertTrue( check_limits( HashCrypto, self.the_rnt, lower_limit,
                                       self.difficulty))

    def test_lcg_crypto( self ) :
        """
        checks the lcg crypto function for randomness at different sizes.
        These are complex and exhustive tests.
        """
        print( "\ntest_lcg_crypto" )
        self.test_name = 'test_lcg_crypto'

        self.setUp()    # setup() after setting test_name

        check_function( self, LcgCrypto, self.the_rnt )
 
    def test_prng_crypto( self ) :
        """
        checks the prng crypto function for randomness at different sizes.
        These are complex and exhustive tests.
        """
        print( "\ntest_prng_crypto" )
        self.test_name = 'test_prng_crypto'

        self.setUp()    # setup() after setting test_name

        check_function( self, PrngCrypto, self.the_rnt )

    def test_hash_crypto( self ) :
        """
        checks the hash crypto function for randomness at different sizes.
        These are complex and exhustive tests.
        """
        print( "\ntest_hash_crypto" )
        self.test_name = 'test_hash_crypto'

        self.setUp()    # setup() after setting test_name

        check_function( self, HashCrypto, self.the_rnt )

#    @unittest.skip("demonstrating skipping")
    def test_crypto( self ) :
        """
        Exercises encrypt() and decrypt() with the full range of paranoia
        levels.
        """
        print( "\ntest_crypto" )
        for system_type in [ 'big', 'desktop', 'laptop', 'cellphone' ] :

            for paranoia_level in [ 1, 2, 3 ] :

                # must set these up identically
                encrypt_crypto = CRYPTO( 'this is a phrase',
                                         system_type, paranoia_level )

                decrypt_crypto = CRYPTO( 'this is a phrase',
                                         system_type, paranoia_level )

                # repeat to be sure there are no problems in transitions
                # from one message to another.
                plain_in = "this is a test case"
                for _ in range( 4 ) :
                    encode = encrypt_crypto.next()
                    decode = decrypt_crypto.next()

                    # to make this work, we need to have encode and
                    # decode PRNGs processing the same number of characters.
                    # dropping a character in transmission causes loss of the
                    # ability to stream.
                    cipher_text = encode.encrypt( plain_in, 1 )
                    plain_out   = decode.decrypt( cipher_text, 1 )

                    self.assertTrue( plain_in == plain_out,
                        ( 'test_crypto', encode, decode, plain_in,
                          plain_out, system_type, paranoia_level ) )


if __name__ == '__main__':
#    sys.path.append( '../' )
    sys.path.insert( 0, '/home/lew/EvoCrypt' )

    print( FoldInteger.fold_xor0,     FoldInteger.fold_xor1,
           FoldInteger.fold_xor_add0, FoldInteger.fold_xor_add1 )

#    I could not make this work with unittest running the tests
#    because exec() doesn't work.
#    unittest.main()
    THE_TEST = TestEvoCPrngs( 1 )

#    THE_TEST.test_generate_constants()
#    THE_TEST.test_generate_random_table()

#    THE_TEST.test_hash_crypto_rate()
#    THE_TEST.test_lcg_crypto_rate()
#    THE_TEST.test_prng_crypto_rate()

    THE_TEST.test_lcg_crypto()
    THE_TEST.test_prng_crypto()
    THE_TEST.test_hash_crypto()

    THE_TEST.test_crypto()

