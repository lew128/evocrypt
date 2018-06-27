#!/usr/bin/python3

"""
evorandoms.py

Utility functions used by evo modules.

Current limitations of the code :

"""
__version__   = "0.1"
__revision__  = "$Id$"
__date__      = "2017-05-01"
__author__    = "nobody@nowhere.com"
__copyright__ = "None"
__license__   = "None"
__filename__  = "evorandoms.py"
__history__   = """
0.1 - 20170501 - started this file.

TODO :
0) 

These do not pass dieharder yet. Generally passes birthdays and fails or
weak on the rest.
"""

import sys
import os
import math
import traceback
import copy
import getopt
#import random
from evoutils import debug, print_stacktrace, print_stacktrace_exit
from evofolds import FoldInteger
from evohashes import HASH0

#SINGLE_PROGRAM_FROM_HERE

# This is a random number table used throughout the code.
# It is replaced with new random numbers for every 'new' program
# For most of testing, it was 128 lines of 64-bit numbers expressed in
# hexadecimal, 4 words per line.
N_K_RANDOM_BYTES = [
    0x7384b2ed6c6bf279,0xeb866bfbf6d4c441,0x1d945932fddfb184,0x3fc3bbeefef55230,
    0x9a38a4f05ad8d95d,0x942b8fe0ce7e7762,0x83d7ac771e3e2265,0x4e6455ead65351a1,
    0xa56509985e1f7146,0x7b683b71d1aef4b4,0x505449accb49cdfc,0x2608d46174f356af,
    0x39a6dff140bcc1ea,0xe18979b0b75f238f,0xa8a5db2c9cb6578e,0x5313dea4c3e5f10d,
    0x0cbcd46dec216e9e,0xef4cb4b1bfff6d1b,0xed5ecf25629ab14c,0x75e9a94cad279bb5,
    0x51eb301e612f9526,0x2208363b6ebf7ba1,0x2b194a62a9c8c757,0xaa204c1bb52cb9dc,
    0x4325528c2605752a,0xeaba5db8efb19cab,0x21cf809a3a0af108,0x608e522d01afe4e9,
    0xc13d5ebc4838c904,0xf1de01df89da29bb,0x2cf12a85edb98ed3,0xecbf319662585255,
    0x985ad0a5bacef579,0xcf1eea3c8e6115e2,0xcbf28e00d8c73289,0x63ac767fe240ee06,
    0xc3ce5cf52248b98b,0xbc2a222660d0cf82,0x3995ae2edf270956,0x5d6f3d8b08fe45f3,
    0xd2725a4f81cf6c23,0xcb4d513b0171b326,0x2b54b44c5516e546,0xa2d4eafb2c78ee06,
    0x89fed8b3c86e8b11,0x34886570902589ac,0xbb99b0804a2c3bb2,0x940c9204c7c273d0,
    0xb802be7bd3c6b72b,0xde621aab582d3aea,0xc8efc579501ac501,0x62c940b2d0a973f8,
    0x3e03cc5165f4f43b,0xa3e4e57b5a2614e5,0x1c45a6f17cbc00b5,0x082eb40bd4d09ee7,
    0x921947b9a4112b11,0xbd161b7c183c3ac9,0xf486225e094be9a9,0x2f899da334124049,
    0x42c36e4b4b0e2b7b,0x2412103edc660087,0x6c671156ef9d11d7,0x5ce813a03df2af2f,
    0xfe96eec8d457f014,0x2865b570ad48e873,0x33a350f420f5e5d5,0x930826843c73dfa9,
    0x6ad6b719aa0ecd3a,0xba9e04880276c01c,0xee3ad6898e999025,0xb3fb66a89d045d46,
    0x7c84e6dd65981d10,0x0945d81faeb1083d,0x74e3bd1b8ade7c4a,0xc4de31fe865ce62b,
    0x288a7354014ef4a6,0xb7c9ac5843b41107,0x4e1e9516a069e97a,0xff7d113b87571277,
    0x827a6e3770d9d0c1,0x883398f90c13b10c,0xcee8cacc7c64ee29,0x956f0fdc4d9db377,
    0xa8a597fbf4d1e02a,0xa9964227c8a217c9,0xb3b79b81899502dd,0x648a235743c1c4f9,
    0x5ae014c4bd348b1c,0x33acbaee85434353,0x2e439e46fdd7a6ac,0x2b6dab919ae622df,
    0x7832e74dc5919c6b,0xaf307cbaa7dc92da,0x8bd2d8e716632f89,0xa6bbd3750a61664a,
    0xc813b95a91c7d9ef,0xfce708ff687459e2,0xfb621c8bdee9e0db,0x2c513bb2473fc9bc,
    0x0891340a7263dcf6,0xed89a7ea5dd688f7,0x6f1ae9b90807dae6,0x6964adc2ba4658f0,
    0xe9f850ecf46dbc95,0xaf5e5ef59fe0a8c4,0xf2d2c4f1b0500968,0x0f7ea7787faa5228,
    0xb593488741ece442,0xc02a22908d25aea3,0xe731e9258b3bb466,0x7c37d9182c9a117b,
    0xc39504c9d4f68092,0xf01d7c52d0170a97,0xbd95a07f610012a7,0xf1d8448174fd1dcd,
    0xe9dab00f214ea5dc,0xd80f8cb6285bd403,0x75a03d2faa81d204,0xcdb0f2e35a9da97d,
    0x8282cb48a8059f40,0x7bee30546cddf801,0x45f42b5b3a87b2df,0xbce169f9201ca4f2,
    0xa55237ee644d569a,0x76a8a553db0c833e,0x7a70c5701dc3058e,0xbffc3774578b9311,
    0xeb0020b35c831c5e,0x643fccb5cc66a9bf,0x6e4a31cf6201d7fa,0x534b0f8d7527bf16,
    0x2e4ba06e22810ac0,0x861ce14ce6b818d3,0x1c4c320e2e28400a,0xc0d27bcea0a3c86c,
    0x420ee59cc4ff1bc8,0xdcf7f36743ef2ea3,0x05c5fd93aa07fa96,0xdec9135fac244f0a,
    0xa8c2d5bc36a7cebc,0x031d905e8217057c,0xe59fbb41f59ac25a,0x4fd3c6bd0b1dee26,
    0xcc752478c352d219,0xd3d9c16c42ed4078,0x2919275a28a1b81c,0x8a4df511489c8177,
    0x067ee6e9ad72e9af,0x9f7f527dbe6027ab,0x8d3f841462e379a8,0x293345fd1277cb52,
    0xda1b1ee80fa6878e,0x1e99af339f13e01d,0x63dc9478f152e161,0xe1d8bc5e366cd6f1,
    0xa5d4d58220b4af3b,0x3ec2298593aeeca7,0x45d1861316248168,0x3ccedd107f3b4356,
    0xe9877c73d063c09a,0xe08a2aa0bde9dd7b,0xc6530963c15274ea,0x52582cab24d3c2b7,
    0x569755559908d241,0x32cd2afe3636aa48,0x44278f7068e06ec6,0xd19266da3da02504,
    0x005c52eb0b6a7e7a,0x2a029c955e5ae5d9,0x983f80afc302fd58,0x94d03718c0caf97a,
    0x3d276875f62008fe,0xd672616dcb664f4d,0x098830a74e22c2f5,0x176fb552cfe19535,
    0xee6638fe85eba906,0x50065ae8ff456b1b,0xd3418b3c4947addd,0xe9effefd7c9831e3,
    0x38b926f0b1044725,0xa7e7cf76a15b950e,0xaad6f1354933f9ed,0x71904f440ee397fe,
    0xc62cc1523b0d4d95,0xc34397d4f071ad3a,0x1850ebc75770b6cb,0x77f743c5fbfbda29,
    0x42d36a229644c012,0x5c881526c130ccc0,0xe4b9f6e4d8103f51,0xbd2d80206abc7697,
    0x7b6723684ca87b21,0x6fd7f75fd33a66ee,0x76f588ca8b337cdc,0xf9f3d674f1438324,
    0x6280ea5327ac072d,0x33d181f9927bdde7,0x0791b5d2bdcb689c,0xc293b4580d3a6777,
    0xb405ac4f0c73479a,0x5626492bbd8b5376,0xa99fbf624da45293,0x2d71fb7bb4479579,
    0x9fa183409e05c4ae,0xf63f203223030c42,0xef1c99697e2fdcaa,0xc0868b6d8e705c0d,
    0x4e018e221b46aba9,0x52f633da72c1fbd0,0x940a64e349d5b89b,0x6fb95eb1bddca185,
    0x676a8de1137f8fae,0xa74c75c5e8169c72,0xd2f155fdf5145deb,0xb01eee32459e88e4,
    0x2c899971b64f591d,0xbfe63715e0d488fe,0x01a59d116154e740,0xb8a0a7608d4f9a45,
    0x83f944f02dbcf6a1,0x0818ab6c279bea47,0x31bd3d37a132d453,0xf2ee49caf9845839,
    0x8963b2b4a4ba45b1,0x6b74a0e255c27f65,0x8d8ea41d762fc376,0x6fac6520139f0a28,
    0x751bb895d2928ab4,0x90df64b2458665ad,0x1c9f1b68e0481738,0x3e2b1dea437509ac,
    0x12d31cdbcb8826ae,0xe0bd4040f17c66e0,0x78a0d4705f115e34,0x1706738e3d0e6d3f,
    0x1feb2b4aa6209b01,0xcddce02f10bf51b4,0xab67c0eec11f9c71,0xacd1a51b6943a5f3,
    0x72355916f11185df,0xc070239b48fab29b,0x345ba91e5e34b7a6,0x8580a13047720c67,
    0x5642ec45727a474a,0x996873c9fdd376b9,0xe888bb786bbfcf85,0x146e1e4f03b30e1f,
    0x4c123f36bf07b94e,0x55653bf23b255cd3,0x28eb6496203be70c,0x19069abd663e9795,
    0x2eda821dc2011397,0x08ef7cacfa56a161,0xbfc82079af2b2515,0xa353ca6539c271c4,
    0x753d85659bde5a37,0x16548a903091df48,0x37c95d27a7f9a443,0x297f92b6b5f6f55c,
    0xda609e69195b1249,0x75702254231a620e,0xb5e9a90385d12541,0xf61f2d02547c9814,
    0xed34bd3e8310561b,0x69ddc94b6976e022,0xcc7667a871476ef4,0x418370a48207c594,
    0x0cfe82acb2231392,0xbf99ed1e2f6f7ae7,0xbb72f378b7c8cafe,0x635c17d5daeda560,
    0x7ee0380a96e454cb,0x173636e1df4c57c1,0x91fbfd0875b39526,0x7d2ed22d2ae3dc71,
    0xce7e06eb0566940d,0xb9becb6ccdeb0284,0x75b3f52830da9667,0x3fa75e31d9787c18,
    0x5d176700992d4dc9,0x7ab57cfc0f874c8c,0xb0a1a475cca436c5,0xf5cfd9313f3d6a3e,
    0xa4c6603564c041ee,0xcc49dda0d6dc04d3,0x72c9ac82526f2d5e,0xa418b7c7a776d442,
    0xd335e2cd9f0046aa,0x5194eb539100b910,0xada57b50aa35dd11,0x2fc615624428da0f,
    0xaf0373365e867b69,0x1d97b54f54c3d6f1,0xf193f46caf2cc43a,0x27c589cd9946a915,
    0xe2feb9079d566e37,0xef1d1a72c4707569,0xc427d4f489a4f1ff,0xcd6b93704bb3372f,
    0x31f861142179554c,0x094cc9e22f4b5938,0x540402cee14a9761,0x945eb92ca4484533,
    0xf6f3e9db4d6382b6,0xceab8123468541bc,0x111ba05c8c2538e4,0xc6f13d1522b1e58b,
    0xc2ed2baa69d717de,0x83fe02676c80e347,0xd383e713323a7346,0xe977412aa6756763,
    0xd7b4713e4885b560,0xb0d89e79ec3e9424,0xfc2ac2935fb37070,0xfd1385bd35ee9893,
    0xbd73e313abfa9681,0x055cb7adfa6b5b89,0x9a3d5680ae37eda6,0x18b45a8d3ee5d50a,
    0xeea1a266e103e69b,0x6f6f0a0dcb8075ef,0xd8ed4ba8ea3f9d23,0x5eb4ab75e09c6b81,
    0xa8ef175d57508deb,0x44fcf4cb0259f88a,0x582c714a20dd98ee,0x67cb393f566c1d72,
    0x5a50c85fb3ac78f1,0x3a937f21842d0adf,0x6055c7abbda2e8d2,0xab5008e22ffa5b53,
    0x4898ea6d33a531fc,0x25d88d3c372be0b2,0xc49fce747a03aeb3,0xf699874c27d28132,
    0xe70be27529ee751d,0x0a6d292438d8922a,0x30818a867ebc2492,0x476b75e7f6e26cf9,
    0xd782dbef7ac0303b,0xee4fe8076467dcde,0x62d2487b215f4470,0x1357fa45bdad1468,
    0xd8197b9d65717966,0x2ce7c1f405fc0cb5,0xc123fd7be331daa6,0x6e716963cb46eeaa,
    0x6889990bb040f271,0x24e450619e986b65,0x70ff05dbe89009a2,0x68247dd60fcab6f0,
    0x7c624ce3f4ce9482,0x52ad1338e3a36587,0xabbf9965c721edaf,0x5511ab5fe053e076,
    0x1576a977e87afd2a,0x59e38cd214cccd17,0x51a92acfcde301ba,0x8cfd8f50b6f1be71,
    0xb1b7337dd410a7aa,0x3ce257811e4c9260,0x4a524d89ebace3a1,0x298cf159a3c8e33f,
    0x063516d97d72bdad,0x22de5685e7ad6c9d,0x99e7546accc90946,0xe27d0e39721c5a6c,
    0x228a5fc29a702e2c,0xbd3f6d130557007a,0x0c1e6b0ab8cf41b2,0x3cc166ef3807f8d9,
    0x00a523b75cbb067c,0x005027155bd98ac1,0xa4c66ff579d95c36,0x882c4a90abcc1100,
    0xe7caa973ebf33b37,0xc5e1e0ffb04e54fc,0xe21f893ebbc2e498,0xfb8abca8ff5bae57,
    0x064a721c7f0b02cf,0xa1ebfb29ae28bae9,0xc76717812a9468ef,0x3e245962b1114577,
    0xf467fbdc8d5dea5c,0xc020aeb9d471622b,0xde3ee652508800b6,0x7d067a11d94fe05b,
    0xf2b178a056e4a532,0x28b08eabe2f19828,0x9fe21e06924264e4,0x92313fa90e54c838,
    0x71d360b35d821715,0x7a76d4d344f462b8,0x74dc88318d101e95,0x9481b2980df6bc70,
    0x536b02d652192207,0xc8a32893034d0f3b,0x49a5599375ada953,0x4eedffe84aed4909,
    0x1fab9c54cc947833,0x00d3a2fdfa6cc99c,0x63505f200b905025,0xa7234e964866f837,
    0x5a00f0b4b824057d,0xfe65c75fe5969383,0xa315504710db88b4,0x9ef8d613ee7f9a7f,
    0x654a2ff6eceeff71,0xb7ffa9007b0369b2,0x24ef8536e9a557ab,0x47397d79c364d87d,
    0xe8d3c27041ad720e,0x6ba33ae26e85f862,0x336e18be3a0f590b,0x4e8bd81d4dee05a9,
    0x6ebe27966a14a215,0x6b868fdd0cf4ba5d,0xbff15b8e098953a0,0x84376de04c0b4d7e,
    0xf8a817df529fb09d,0xe91fb595aade0710,0x4b35b15324ec61b7,0x445c400e0e239c55,
    0x3f8d0b7506f81dcf,0x503ac582445d3333,0x05bd301459f7cc6b,0x56a85544399ad8dc,
    0x63d6d5d03b5ba753,0x7b24150dd1ec69dd,0x959b2feba47292ad,0x36c5efbd8faebd0b,
    0xf516f9df1ec335af,0x0dd6204f5b60cfe2,0x2f709d6145d034e9,0x969616db8e9915a2,
    0x45369afefb99e41d,0x4daed50d505afe78,0x2c4abdd0dccaaf5e,0x60ac39e27a07dfe8,
    0x76258dbf755150f9,0x8272d3e928b0167e,0xb6e5d02b3c23044e,0xeee79df536ae12e2,
    0x8fc0af8a0a358026,0x3587e4ae2092a97b,0x4db800885121588d,0x45c962f313368494,
    0x3153d3d31e42b763,0x807018fb119cb2c6,0xa8968b724a3bfe53,0x502b5e7b3bc9b892,
    0xc8d4d1f53edf4e71,0xcd6a2d473145fd4b,0xca3c2ce78cd02a10,0xe1ec9b567de9ec69,
    0x29e27298fb65d240,0x348cd7b2e492d7d8,0x4977f0171d993f02,0x20705841e9c36223,
    0x86d48944b02ffffa,0xf1a58f60c815af43,0xd3b1d891857da972,0xd50892529c6f0674,
    0x479f361577d5717f,0x005f72bd3c06d384,0x7b2ab690c9f44ff6,0xa50a4053a7cb02d1,
    0xcfa16317daf9f1d0,0x2a11d9953c89e2f6,0x932472775ba2dd89,0x2dbd595a592769dd,
    0xcd47f95af5c99b2c,0x5ae6b28529e0e6c0,0xe19e1b43cee68478,0xd85e8408c0605313,
    0x300873d940b46459,0x10c06b0ed43ed2b0,0xe4744d3769af9aae,0x87ab19cf5bebeb96,
    0x54bf382c86782d95,0x604379c8c182882c,0x7f5d5e36d8ee9bef,0xf16cbc4716c28972,
    0x1ec5554b2786664d,0xbf36af1235a20187,0x00f7e5414460d3f8,0xf6fb56f1b65544d7,
    0xf4e65d251652fc84,0xa853c7d3c99ee11d,0x491aa82be611a4aa,0xeaba5fd17334d986,
    0x2ebb538b1c30452a,0x5be883c295e1e1d3,0xc67d10ae84eba976,0x219aa3df786a6d92,
    0x6240e7f6e188863c,0x994c8f13445bcb7e,0x0a4a772d9dae70b0,0x98dc8b0c30be3212,
    0xafa96e667a121637,0x081d976af75f6e82,0x4007eb0a2611aea8,0x02d59f417c8cede4,
    0xf17de131d033d5eb,0x7527469b2b0ff3e4,0xaefe5598a31c1495,0x0d533736fcc6c2fb,
    0x498d909ab47d8c17,0x19d02376f2afca0b,0xd8033db84da0b278,0x4351a6ddd2043a61,
    0x174204dadb739120,0x16c207cd58cead81,0xfabe09a1e6faafd0,0xe4f90a996c70ac47,
    0xeb8d38284e5e023e,0xc5ffc696dd1f114b,0xdceffbb178c524f3,0xda6447e7b3fd0b26,
    0x6010b13bcccb4d1b,0x36537ef270c5c241,0xef06d27cc009b5e0,0xa7cb088f2688ad5c,
    0xd24059550c4c26a6,0x6477366aff945c0a,0x4fe89b4a22f56b6c,0x04e8d938a8798b15,
    0x154387bc0b0733ec,0xf4b5e06959b9af9e,0x7b7b08afe9d16999,0xa7b8078cd225e2d6,
    0xc0bc2e5a1c9cfee1,0xa91680efc36bca2c,0xe28f9e5c4109e1b2,0xa89d04fce4ff5a13,
    0x3fdaa3ccf3de4446,0xcf29638b5f01876c,0xa89d23f32b18a8bb,0x3ecdce8a749fbe27,
    0x175a1410020a3ae7,0x475b22ebb77d9d79,0x4acd63bf37b9e739,0xc928e3587f748bc7,
    0xc307fd74e6145d8d,0xeebccb3ca8e7fc2a,0xd2b1e7ec847b4b1c,0x2a60e06a031f03c5,
    0x5d9dc00b56b704c1,0x7ed1ae596adbe660,0xb219985fbbac947c,0x4e2261ae6bdb479e,
    0x4c94ef00d4a54ace,0x3591232f429425f7,0x869fd684c35da943,0xf3efba90bf84615c,
    0x44a135180af3dbc2,0x802c43635a92f560,0xb9b44edb752f695c,0xe3a9ecacd7e9a0b7,
    0x35d0247f554aa7b2,0x9ea8b759b1318e85, 0xf5e3c43b10ebbce,0xb7aabe85299ec232,
    0x256922aefb9715d7,0xf04ef45fc860db38,0x8581283aba241939,0x93de5fdfdec351d7,
    0x29fe23721585677a,0x7b1d0717f621c869,0x53b07c6c79642b07,0xc250cf2f42ef8007,
    0x1e637eadb42578e8,0x73b2fb26a8cab461,0x13ce4ff83fd18b6b,0x9b97340ab0885070,
    0xecdad3544e7b8d9d,0x5901b690fe3cfbf1,0xc62f4b3526f93031,0x316b4592b4a47d8a,
    0xc1164af4c2106c56,0xbc68d29944d1b865,0x545b2f93575c1070,0x288877094aad2ff6,
    0xd01e89b0b00785ed,0x3fdd2a130141c1e5,0x3cb674e425007757,0xb2dd2093f0219ce9,
    0x5868a25083d33675,0xf2b23f2900ea246d,0xc2931a8807205489,0x43232ea8e6154e6d,
    0xf3e9cf2a24bbcd8c,0xa1928d75521c9267,0x49a1fa57c7c7b517,0x8eedfc36b9b371b8,
    0xc0c56a9b4606fa99,0xe2907f88256a3b57,0x2cfc90998e857e07,0x642fffc591caccb3,
    0x2fa3b650998f0e9c,0x5814ff5a1c0418ab, 0xe59178c78eaad30,0xa1ee374b3538ebfe,
    0x2db179d65671cd10,0xdbb2cd5261d88afa,0x50aecb142463e9a4,0xb0e4ef3b4e365870,
    0x52726da3c5ab11f, 0xa7a4a0c01705562e,0x36baef2880dcfaaa, 0x2f8fa4702901d76,
    0x6d1158db200c0b0f,0xfde0f1b2e31afcde,0xebb8cf960942467d,0x905a820c79277dca,
    0x4f9403db264d07e2, 0x111228910c4fb54,0x7a8e6491ce4fce79,0x109385a356ab78a4,
    0x6dd0b2d637be545d,0x6b625b97cd9bbb99,0x2af92c2a45e1870a,0x84512b235e342676,
    0x63f8b8bb301626a0,0xca93666050004174,0x8efa0c6558a16647,0x21f12b370cf566d8,
    0x6d9efeeca8c7b6b, 0xa7b565c1592efd4d,0xd4625a0b4c272354,0xe9331c8c6193a094,
    0x3699a43bd2115506,0xfb9767566504cfe2,0x187e53f526a61580,0xbd680ea5716a86aa,
    0x7db13a53a6c49182,0x26d740275eee7091,0x11811da52038c902,0xaeca645fe59bc9ac,
    0x35a99d36986b4f1b, 0x4dd8a0af346ca61,0x753aed46e92b0eaf,0xc8e6f073b9cf1de2,
    0xf01a953293f518ef,0xefab2951eb057cc6,0x8e0f7bf4cdaa2f43,0xf88b0149696512a4,
    0xd44af1c9f1329ca5,0xd2367eed999c2f51,0x1923e762e27a415d,0x59ad46d677dc8ba7,
    0x17ab8489f698334f,0x701cf9765f229362,0xf76dee6e8043d8f3,0x4cae4e9d88209ba9,
    0x3a7132fa713d5dd8,0xde911f86880d20bd,0xce6ec0d70be845b9,0xbca5106e33a433fb,
    0xf3344dbdc7345fcc,0x43c88a698dd33363,0xec6156e114aae7bf,0x7c145c46303ad953,
    0xcd9cada5218bdc1, 0x85aecd2475acfa89,0x8f13caee3296af93,0x807cfa97cee9042c,
    0xa439e37eb02332c9,0xe13feb7765c4336c,0x70211a892df6d9a4,0xa9cd4cc273d5cc8c,
    0xf582a24f1ba4ba53, 0xb07b562be37ef6a,0x7ddcab2cabde31a2,0x6ec4e3290a868c8d,
    0xd2dd4ae50e2d12df,0x2a34d8694afde69e,0xfd4fba25544070c8,0xb9acb9f0080b5222,
    0xbda023ef6782af65,0x626a0b04b8fe154e,0x34294c29f792c442,0xc41790b38856f3e4,
    0xf720bce5040695ef,0xb2667e77a7fd538e,0x93410f2d202d1de8,0xf5d24be6a5f99014,
    0xb22a0f6195a43271,0xff1fc3caa966bd93,0x789f1cc7c29ef0b6,0x78f666bd3f5151e2,
    0x135f9b74bbfe388f,0xa26d702234922ff8,0x611652c076bac672,0x21e774952be5521b,
    0x2bf6ec9cdde59b75,0xa5a09d843b1f86a4,0x81fcb7c35518bb92,0xbeeda2e0246478a9,
    0x4da8914b9d8cbad5,0x13fa0ba302374fbe,0xd234057730e21355,0xaf4d65e811395c41,
    0x15a09823e73b244f,0x6db90175a87958ff,0x5a2562fca3836db7,0x67dc3d0d2dc3d51d,
    0x4779828381681a7, 0x7d503ba7871b0d79,0xc4b134424fe09ff0,0xfcc8dc9f62720b00,
    0xdaf6dbb5a8faafea,0xa2a62642f2a8ebd2,0x360affed30c9d11c,0x3103c7b7f1f8385d,
    0x993f923dc3087b42,0x2aea613462f99497,0x885d6ece67728d74,0x484c92220921c1ba,
    0x80c2c160fb50ee4b, 0x9e465536e076279,0xaf475549a97f1b37,0xc30b800d546b1b66,
    0xc1d0dd577dd80802,0x76ac655c18ed967a,0x3b8cf1f5b6db89a3,0x617ff1a7629421d9,
    0xd2de9f2a2539ccc, 0x30eddf20a7e5d40d,0xb7d3db259faccf6b,0xeb7e387229314c7d,
    0x19358e018d7ef4cd,0x835ef2f66e568f67,0xfbfb3f4eb6176b2a,0x1af8b00ede0b666e,
    0x266d07cf4888ae60,0x8a135ead15148e34,0x75f8b469cf9eb7a9,0xf586ad2314a47560,
    0x32b7dfb77b42b75b,0x70aa48b5991be7d9,0x3304239d26fe2801,0xfb29251a6e9a71d8,
    0xcff092f446cac107,0x4c18f0d37b22e42a,0x7ba9d8397155bc2d,0x47a46e5ffb990e41,
    0xe6e3c1a914bb16a9,0xb26980c97740e7f9,0x6d376449d98c5558,0x4a01e5d0f58feef0,
    0xb184595441bbfc7e,0x8068627970ed1321,0xd538a8569749313b, 0x5e6bf21789a5a2a,
    0x401170abc9522d03, 0x27f6f1c3d300091,0x5960d108cf44822e,0x3346feb46a80e5f6,
    0xc400f4a21a1d2df3,0xe38eb32d01f1ff5a,0x1b156f3f75478e42,0xc606fc30106a7762,
    0xac23797f2d3c0da8,0x364dfc283621ec63,0x2b1f56c4c0a0f6c1,0xb265f0c6c8ff3fff,
    0xe83ed5f8baea5804,0xd1584a7a62cf3655,0xb38228e1437f1b07,0x590e9467adf75eab,
    0x57b2ac8b82b2788a,0x284215c5123fa7fa,0x6cf5b900361484b8,0xbe6282c71e006764,
    0xc3d315ef78df452d,0x4e8a289207e07b44,0x52ad8a1b8957abd8,0xf70884bbf2e73a37,
    0x757f29c69b0e9972,0x469f6ab50b3e1f7f,0xc4d9bb415e3d173b,0x191830ccb6c8b6e9,
    0xc4aa7e9aac29dada,0x7894fd81a5292ce4,0x19e70a860d2f4901,0x7e7966c9ade657a0,
    0x203ef23219e01b4a, 0x47b6b451bdb8b12,0x98b9950cfb4e7bf1,0x55b35abd4757f4e9,
    0xd9529e2b7bdaa8ee,0xa629cd92323a5589, 0x9fed0ace41d32fa,0x4382742dc5f233c6,
    0x25b0856b8102410f,0x21d330cb5a382ef1,0xffc624447fc8d8e2,0xbc5ab07cc40036f0,
    0xae7b139839cdbf08,0x462d3bdf3f6ede59,0x8c52e6b539db59a2,0xdc154c74bb1c3460,
    0xdf23c2e010b4320d,0x4be0bd27adc712c1,0x82c647850ad8c771,0xc4ee4d17441cf26b,
    0xf0019d3a2312f464,0xd03e4dd46701c1b3,0x1295db1ae2b576fe,0x10d7bef222ca59d9,
    0xef32338b198fbd3a,0xf6bf18252fef0301, 0x87a5e9a5a3c458e,0xc0dba6b84b6ab7cd,
    0xf7f7afeade0834cc,0xca03887d48ba833e,0x1ea7369d6d3130c2,0x921aba332c01d7be,
    0xf799fc2b10a3a77, 0x9ba154d00e98ded9,0x87c1b979a3f533d7,0xe4884f6e268e6a8f,
    0x1517f52f3f8284b, 0xdda1603d49aaa906,0xe2b31f321cb2544b,0xcfa5d897ba613959,
    0x2d3defe5a3cb5a4e, 0x2bc79df250609af,0xa6ebfcf14373a36f,0x27023d5aaed77718,
    0x6c33767514144d0c,0x396588ae8e935726,0x4b7dd953ffdd91a0,0xa86c1b332c672b8c,
    0x6c1a32b215933796,0xab76f0f3f48b4353,0x1f20bb563e9742f2,0x23109520773f9c02,
    0xb7a366cd378aa7b0,0xa9a6e23d2ac2da03,0xcb3d143859df828d,0xe43638729e67dd84,
    0xa078736538bfe5b8,0xf4fd8a80510a864f,0x42cc4c7b3a0f1013, 0x62043874c619ca0,
    0x7d9074616dad2e98,0xe8f50d626510c7f5,0xcf70f8143c10d6a0,0xb31bffc3d560116e,
    0x9c7bcbcc0310b9c, 0xc274b2bd950e30fe,0x95fa2c3cdaf27f57,0x51db11bf54e86779,
    0x841f3184e996a167,0x4da6c0b6c7758c35,0x50f3225748b41850,0x152d5b967a47744a,
    0x1a146105a8d9f129,0x3fdb75f640d2cc31,0x63ce531a2de531e8,0xa23f9ad7c325f143,
    0x398830be6cc2efd1,0xb8a5e5fa2b655ce7,0x4975e38fe0f822a1,0x35bf0ad8a77adf34,
    0xc375e9348f4b17a6,0x2166e420d5396853, 0x8f8c8ada53296e4,0x5c82f509e3f7aead,
    0xf710628d76378e32,0x4ceb7cd4a47fa9e0,0xe47731bff704c8b6,0x2c387e4d3352066d,
    0xa19c30e9fa83326f,0x5fd7bbb457716496,0xe46e8324b5b8fd6d,0x3aaf4c02540b0d76,
    0x4cfad9747cf415ac,0xdf3c5d10585e0288, 0xd4b262332ee542b,0x9e1f11b29c38639e,
    0x95154152185c5a9b,0x302f349c8096b90b,0xa045cf27f16e0c64,0xf96377e966f6b802,
    0xbfc7498811d6bd67,0xa0d27369f19d772d,0x54ceb27251cd9c2d,0x1b1d43aaedbb6a33,
    0x140419c12a289f11,0xf0ca3d7453960434,0xc7b31ce3a7f8a54e,0x3f4078b8e1b6f7e1,
    0xbd09b5a8a9f98b0b,0x84be9fe8c355d6b5,0x6cd9675405b637bb, 0x8d0aaaa70349efa,
    0x795207c8e89bb944,0xbc203a0c5cb423ee,0xdc625061e1a9878c,0xc99048a11ad0ea89,
    0x19c1fd0a49ebe45d,0xbe6dc18cd43f4c20,0x399d1f634a10432a,0xa58e088cf6b7596c,
    0x4bb91ed1295f34a7,0x335c8b96c3eab437,0x9e9f58d40604b27f,0xf157931a3f5e19eb,
    0x1a76f349455b1065,0x39305cb4be10dbee,0x37b4c902f21d812c,0xa1098670120c8a3c,
    0xab4f0e9d36220fc9,0x3a6fa53275e6925c,0x355b18ad3b920f3b,0x625febed1e10c508,
    0xbd30ff8cf1b92961,0xa16f7aab524797ec,0x5f0547e26fb87816,0x31afbb60aca442b4,
    0xbc3af0aed8dae7b1,0xea66ea8570c886b6,0x2e4704e8075d8c4c,0x7d35b56213c93f21,
    0xfb028a134268cef5,0x10d1316ab2e8de33,0x887ca5aa44708c1b,0x34207a011932c222,
    0xe945b7594b194db1, 0x32115e8d9bb20b6,0xd9dd7a737ff53069,0x78bc59e030005e3e,
    0x65687fa134823094,0x981e515ad85dc7dc,0x9b841839bf78fafe,0xdb2569a493897d1b,
    0xa3f62bcf99eed10, 0x59be7a123bcfcc42,0x96fa97f8322c0c70,0xc645dac29bcbdfd0,
    0xd830ce4ec0cbe622,0x63474b40bc13b67d,0xe2ca27d355459d5d,0x8ea015b78baf7de6,
    0x8552279f71148406,0xef410864c4be61a0,0x16e048717fadfc94,0x7ed6d7da11fdca03,
    0xf7165ca733c15608,0x76dfc39516756ca1,0x529d8ad5fd355bc5,0xee760ba7f1f1a838,
    0x45e3f725e5172a0f,0xf09235edf3ccd001,0x1d1570ecb48b9b25,0x8e36b57a2aaba1e1,
    0xcbf92a4ee3a0cc55,0x5ec27c91a68b736f,0x67ff0628f9c08e8f,0xa0c28219a1d6fc27,
    0xb14e92eed7051288,0x9dc74d01eca7b00f,0x1bf5d160eaa22669,0xd07b2446e523dd9e,
    0xd3696078ad47c19d,0x11cab0e1915f3200,0xf3b6ece8d6b7a638,0x576c9bc326f2caea,
    0xe8fdf4ed2b63931d, 0xa9e0343ccac135d,0x588a27a7137aab32,0xbb4109adfc912682,
    0xb1222ea95c5ec114,0x9cbb09af3bc505b6,0x36d8efd355d5e676,0x4c8136f7b6831fbe,
    0x6aacfc69bea778a7,0xa7c7ea733c0f8afd,0xcbfe0974dfd93c11,0x5d9490176461567a,
    0x8be3540a3a2217,  0x441d5737ecd10db2,0x9269400fda7e904b,0xe4113e630d22b553,
    0xf557d0004ab812ae,  0xd5c93cf5d7d351, 0x9980bc7d35535de,0xd319ae2a948ef0d3,
    0xfd7d6b9fe74cab1, 0x7273000b1b6872d2,0xb92427d344c81257,0xa47ddebce4e05ee1,
    0x4584853b75b30dcf, 0xb180ae0c2ad5f7c,0xd9228109c451fb0e,0x9493753797861881,
    0xbc3eb136431fb269,0x709f4aa34f869502,0x5fac35bf99857777,0xad3c934dce21e00c,
    0x490e8b90ab92d746,0x72ec28502c86f11d, 0x56d7738ed7bb74c,0x9a20df4b110cae08,
    0x5ff40724ec388798,0x9b59ca20425e643d,0xf733b9864185d713,0xd4b7eb51fdeb4070,
    0x6941ebd6ef89a910,0x28233b5678787802,0xcbc233473fa11218,0xd4bd674fd488fee1,
    0xa888c0f265a8685f,0x62c616e3ad9bbace,0x72bc6500e5b14f84,0x47c21d3e828b9f79,
    0x5aabe3067734f015,0xd952051f7a7a8ca6,0x1900d7c6ca07fcb3,0xeb58a9bda5e081d3,
    0x94e7677f88a405a4,0x6f98d1103c1f1248,0x625e2daf7a9f2eb5,0xbbf4545e3470ee12,
    0x90b06efb03e4f865,0xdd591b675772ff81,0x4351e0ff03fffb4e,0x69d19aa320e969cd,
    0xe6ac7f0e9b21df1c,0x344f466fe076a8ae,0x9e175fba47fc9203,0xdc3fb2e1757f1585,
    0x9855402c1c4425e7,0x22acbb972117cfb9,0x5be327be33c531a8, 0xbed32cb8c5c0673,
    0xff91a377a9e0fb61,0x1d5528c6dc3f80fa,0x4cb1d062a83b90ad,0x76bc36603826926b,
    0xe2c9297ec45a0a9, 0x6d418d7004631411,0xa80d5612c6254728,0x3eb23a557af5e514,
    0x275e875f96a94b16,0x30dd1ced9a8f46e5,0xe4ad6c5e153caef4,0x86f3619d0729e35f,
    0xd683f58b9a287d60,0xbea9e815aaad2dba,0xc4bc5dc7695a5ae3,0x46bb68fdc7c4dfef,
    0xa11197cd10160423,0x570d9e3d673ef9a2,0xbd9e8b535bc48b5a,0xa88b8a75a3f679f1,
    0xab3f1a4a7502a5a0,0xb95d0dd1273518bf,0xe2c343d29fa16d00, 0xa9f65cfa01f09d4,
    0xff9e3d0b7639f5af,0x26e00aab24def7ac,0x796ef5a2f2c43fe2,0x7911b707282e9946,
    ] #END N_K_RANDOM_BYTES

# the maximum integer size for this program
MAX_INTEGER_BIT_WIDTH = 1024

class WichmannHill(object):
    """
    An implementation of the Wichmann-Hill pseudo-random number generator.
    This is only used by RNT to ensure there are not cycles, and is not
    one of the PRNGs for crypto.

    The rate is about 300,000 32-bit ints / second in dieharder.
    A version that put 2 32-bit integers together passed dieharder for
    64-bt randoms through 26 iterations of rgb_lagged_sum with
    rank_32x32 and one of 12 rgb_bitdist weak.
    """

    mix_0 = [ 171, 172, 170 ]
    mix_1 = [ 177, 176, 178 ]
    mix_2 = [ 2, 35, 63 ]
    divs = [ 30269, 30307, 30323 ]

    def __init__( self, seeds, paranoia_level ):

        assert seeds

        self.seeds = list(seeds)
        self.paranoia_level = paranoia_level

        self.fold = FoldInteger( )

    def next( self, steps, int_width ):
        """
        Although randint currently passes dieharder, I worry about the
        probability of cycles if the 4K rnt is the source of randomness
        in selecting bits from the RNT. Thus, I use this function to index
        into the RNT.

        This computes a larger-than desired number, then folds it, as my
        minor addition to the algorithm.
        """
        temp = float(0)

        desired_size = 1 << int_width
        return_value = 0
        while return_value < desired_size :
            # problem is making this produce int_width numbers, as it is
            # intrinsically a long float's faction.
            for j in range( steps ) :
                for i, seed in enumerate( self.seeds ):
                    seed = self.mix_0[ i ] * ( seed % self.mix_1[ i ] ) - \
                           self.mix_2[ i ] * ( seed / self.mix_1[ i ] )

                    if seed < 0:
                        seed += self.divs[ i ]

                    temp += seed / self.divs[ i ]
                    self.seeds[ i ] = seed

            # This returns the fraction scaled up and made into an int
            if return_value < 0 :
                return_value = -return_value
            return_value = ( return_value << 32 ) | \
                                        int( ( temp - int(temp) ) * 0xFFFFFFFF )

    # This passes dieharder, and fold_xor passes dieharder but the general
    # fold_it fails returning shorter numbers 2 in a row, then 2
    # full-sized, etc. in a cycle
    # this means the fold tests are missing something.
#        return return_value & ( ( 1 << int_width ) - 1 )
        return self.fold.fold_it( return_value, int_width )

class PasswordHash :
    """
    The interface to password hashes using the RNT.

    Returns the next pw hash function in the randomized hash.

    There is a tricky bootstrap sequence here, so randomizing the
    function list can't be done until RNT is fully up and working.

    A genuinely paranoid program would use a first RNT to produce a 2nd,
    complete with a new random number table, so the same password
    hashed the 2nd time produces a completely different value.  That
    would be hard to make fast in a hardware accelerator.

    Just another idea for the future, in addition to the many, many,
    many different ways that a password can be combined with 4KB of random
    numbers.
    """

    def __init__( self, the_rnt, passphrase ) :

        """
        Calls a hash function from the list, based on the password.
        """
        password_functions = [ self.hash_password_0, self.hash_password_0 ]

        password_sum = sum( [ ord( byte ) for byte in passphrase ] )

        the_function = password_functions[ password_sum % \
                                                len( password_functions ) ]

        the_function( the_rnt, passphrase )

    def hash_password_0( self, the_rnt, password ) :
        """
        The first transform mixing passphrase and random number table.

        These are not hashes, tho I haven't thought of a better name.
        """
        if len( password ) < 8 :
            debug( "Password must be 8 characters or longer", None, 0 )

        # first mix the password  to make a seed for the WichmannHill
        password_sum = sum( [ ord( byte ) for byte in password ] )

        first  = password_sum * ord( password[ 1 ] ) + ord( password[ 3 ])
        second = ( password_sum + ord( password[ 5 ] ) ) * ord( password[ 7 ] )
        third  = password_sum * ord( password[ 2 ] ) + ord( password[ 4 ])

        the_rnt.wichmann = WichmannHill( [ first, second, third ], 
                                         the_rnt.paranoia_level )

        # Wichmann-Hill mixed with the password to produce an initial
        # password hash.
        rnt_bit_index = 1
        for cycle in range( the_rnt.paranoia_level ) :
            for this_byte in password :

                rnt_bit_index += \
                    ( ord( this_byte ) * rnt_bit_index * 
                      the_rnt.wichmann.next( 1, the_rnt.bits_in_rnt_mask ) )

                the_rnt.password_hash ^=  \
                       the_rnt.bit_string_from_randoms( rnt_bit_index, 64 )

    def hash_password_1( self, the_rnt, passphrase ) :
        """ a 2nd of the multitude of ways in which a password can be
        hashed, each putting their hash in the_rnt.password_hash """
        if len( passphrase ) < 8 :
            debug( "passphrase must be 8 characters or longer", None, 0 )

        # first mix the passphrase  to make a seed for the WichmannHill
        passphrase = sum( [ ord( byte ) for byte in passphrase ] )

        first  = passphrase * sum( ord( byte ) for byte in passphrase[ 3 : 7 ])
        second = passphrase * sum( ord( byte ) for byte in passphrase[ 7 : ])
        third  = passphrase * sum( ord( byte ) for byte in passphrase[ 1 : 5 ])

        the_rnt.wichmann = WichmannHill( [ first, second, third ], 
                                         the_rnt.paranoia_level )

        # Wichmann-Hill mixed with the passphrase to produce an initial
        # passphrase hash.
        rnt_bit_index = 1
        for cycle in range( the_rnt.paranoia_level ) :
            for this_byte in passphrase :

                rnt_bit_index += \
                       ( ord( this_byte ) * rnt_bit_index * 
                         the_rnt.wichmann.next( 1, the_rnt.bits_in_rnt_mask ))

                the_rnt.passphrase ^=  \
                            the_rnt.bit_string_from_randoms( rnt_bit_index, 64 )

    # ideas for other passphrase hashes are using the hash functions
    # instead of wichmann, or hashing numbers in the rnt selected by the
    # passphrase.

def isPowerOfTwo( x ) :
    """ a quick boolean return if a power of two """

    return (x != 0) and((x & (x - 1)) == 0)

class RNT() :
    """
    Operations on the Random Number Tables
    """

    def __init__( self, desired_rnt_bytes, paranoia_level, system_type,
                  passphrase ) :
        """
        Transforms the password into random integers within certain bounds
        with a mechansism that ties it to this particular program.

        This is the first function called from the initialization of a
        crypto-prng.
        This, in turn, initializes a number of other functions called below.

        This is not meant to be a PRNG, merely to deterministically
        extract enough computational entropy from the password mixed
        with the Random Number Table to initialize mechanisms to
        extract more entropy from better computations.
        """

        # check on desired_rnt_size, must be a power of two for the mask
        # to work.
        assert isPowerOfTwo(  desired_rnt_bytes ), \
               "RNT bytes is not a power of 2!"

        # paranoia level controls the complexity of entropy-producing
        # calculations
        self.paranoia_level = paranoia_level
        self.system_type    = system_type

        self.desired_bytes  = desired_rnt_bytes

        # always begin with the static text identifying this program
        # the Password will produce a new rnt
        self.rnt = copy.deepcopy( N_K_RANDOM_BYTES )

        # if the size of the rnt is changed, there is a boot-strap problem.
        # I am ignoring that, it is currently 8K in my tests. It can be
        # fixed by testing desired size against actual size of
        # N_K_RANDOM_BYTES and adding more pseudo-random numbers.

        # need the length of the bit-string and a mask
        self.rnt_bit_size      = desired_rnt_bytes * 8 # bits / byte
        self.rnt_actual_bytes  = desired_rnt_bytes

        # assumes a power of 2, or it doesn't work
        self.rnt_bit_index_mask  = self.rnt_bit_size - 1 

        # The width of that mask is important in shifting
        self.bits_in_rnt_mask = bin( self.rnt_bit_index_mask ).count( '1' )

        self.fold = FoldInteger()
        self.wichmann = None

        # the random data is produced by a hash
        self.hash = None

        # password hash should not change after being set, as it
        # coordinates 2 sides of the link.
        self.password_hash   = 0

        # the password hash, may be recalculated.
        self.randint_hash    = 0
        self.randint_index_0 = 0
        self.randint_index_1 = 0
        self.randint_index_2 = 0
        self.randint_index_3 = 0
        self.randint_function = 0

        PasswordHash( self, passphrase )

        # Password hash is the initial set of indexes
        if self.randint_index_0 == 0 :
            self.randint_index_0 = self.password_hash & self.rnt_bit_index_mask

        if self.randint_index_1 == 0 :
            self.randint_index_1 = \
                ( self.password_hash >> 16 ) & self.rnt_bit_index_mask

        if self.randint_index_2 == 0 :
            self.randint_index_2 = \
                ( self.password_hash >> 32 ) & self.rnt_bit_index_mask

        if self.randint_index_3 == 0 :
            self.randint_index_3 =  \
                ( self.password_hash >> 48 ) & self.rnt_bit_index_mask


        # Now the RNT can produce entropy to initialize a hash function.
        # to be part of the entropy-production henceforth
        self.hash = HASH0( self, 64, 19 )

        # At this point, the rnt has sufficient entropy to continue

        # replace the table with one of the desired size 
        for i in range( self.paranoia_level ) :
            an_integer = self.randint( 64 )
            self.hash.update( an_integer )

            self.password_hash += self.hash.intdigest()

            self.rnt = self.new_rnt( self.password_hash, self.desired_bytes )

        # At long last, initialization is complete, having burned enough
        # processor instructions over enough different functions that it
        # cannot be accelerated directly in logic as a reasonable-sized
        # engineering task. Thus, no password-space attacks are
        # possible.

        # But, computational overkill being the goal, we don't stop yet.
        # There are initializations of hashes and levels of PRNGs still
        # ahead, and they use the accumulated entropy to compute more entropy 
        # from the table, which maybe be made very large for extreme
        # paranoia levels.

        # Once you have a random bit string, the cipher is unbreakable
        # so long as you don't re-use the bit-string.


    def new_rnt( self, entropy_bits, desired_table_size_in_bytes ) :
        """
        Uses the existing RNT and the password to construct another prng
        which produces a new RNT to replace the existing table.

        # depends on desired being a power of 2, should check
        """
        if desired_table_size_in_bytes < 4096 :   # the initial 4K bytes
            desired_table_size_in_bytes = 4096    # don't let it go below that

        return_list = []
        # hash_password produces enough entropy to  allow an initial
        # get_next_random, used to init a hash
        new_hash = HASH0( self, 64, 19 )

        # save a lot of runtime checking by making the array larger
        # than desired and not worrying about the index at the end
        actual_size = int( desired_table_size_in_bytes / 8 ) + \
                      2 * int( MAX_INTEGER_BIT_WIDTH / 8 )

        for i in range( actual_size ) :
            the_integer = self.next_random_value( entropy_bits + i, 64 )
            # hash update is expensive, so don't update entropy often
            # this is an improvement to get_next_random
            if i & 0x010 :
                new_hash.update( the_integer )
                entropy_bits = new_hash.intdigest()

            return_list.append( the_integer )

        self.rnt_actual_bytes    = desired_table_size_in_bytes
        self.rnt_bit_size        = desired_table_size_in_bytes * 8
        self.rnt_bit_index_mask  = self.rnt_bit_size - 1 
            # log-base2 for a one-field mask right-justified
            # there must be a better way
        self.bits_in_rnt_mask    = int( math.log( self.rnt_bit_size, 2 ) )

        return return_list

    def bit_string_from_randoms( self, rnt_bit_index, field_width ) :
        """
        returns the consecutive field_width bits beginning with rnt_bit_index
        from the 4KB RNT represented as 64 bit numbers, treated by this
        function as one long string of bits.

        In fact, it is important to have some extra words because I
        don't check bounds in any of the accesses, they can run over the
        end of the 4KB. So I think I add 32 words, way more than enough.
        """
        if isinstance( self.rnt, type( None ) ) :
            print_stacktrace_exit( " self.rnt is NoneType", self.rnt )

        rnt_bit_index %= self.rnt_bit_size

        bit_offset = rnt_bit_index % 64
        word_index = rnt_bit_index >> 6
        consecutive_words = 1 + int ( ( field_width + bit_offset ) / 64 ) 

#        print( "bit_string_from_randoms : ", self.desired_bytes,
#                len( self.rnt ), rnt_bit_index )

        bits = 0
        for i in range( consecutive_words ) :
            word_index += i
            bits <<= 64

#            assert word_index < self.rnt_bit_size/64, word_index
            bits += self.rnt[ word_index ]

        total_width = 64 * consecutive_words

        bits_shifted_right =  bits >> ( total_width - \
                                ( bit_offset + field_width ) )

        mask        = ( 1 << field_width ) - 1
        masked_bits = bits_shifted_right & mask

        return masked_bits

    def randint( self, field_width ) :
        """
        The two versions of randint pass dieharder.  OTOH, they
        obviously are subject to different kinds of problems, so why not
        use both?

        In some ways, this is terrible : more code is more ways to go
        wrong. More code is slower.

        OTOH, more code with more natural complexity is less likely
        to reveal some regularity that allows cracking the cipher, and
        is intrinsically less susceptable to any crack.

        This is not security by obscurity, it is security by
        combinatorial complexity.

        This should be another function list mechanism, with randomization.
        """
        assert( field_width > 0 )

        self.randint_function += 1

        if self.randint_function & 0x01 :
            return self.randint1( field_width )
        else :
            return self.randint2( field_width )

    def randint1( self, field_width ) :
        """
        This uses Wichman-Hill to select bits from the RNT.rnt and
        combines those.

        A puzzle is that wichman passes dieharder, randing2 passes
        dieharder, the numbers in RNT.rnt are random according to
        dieharder, but randint1 does not consistently pass.

        More tests of the fold as a first step.
        """
        return_integer = 0
        for cycle in range( self.paranoia_level ) :
            self.randint_index_0 += self.wichmann.next( 1, 
                                                        self.bits_in_rnt_mask )

            self.randint_index_1 += self.wichmann.next( 1, 
                                                        self.bits_in_rnt_mask )

            self.randint_index_2 += self.wichmann.next( 1, 
                                                        self.bits_in_rnt_mask )

            self.randint_index_3 += self.wichmann.next( 1,
                                                        self.bits_in_rnt_mask )

            # fetch the 4 values from the RNT
            randint_0 = self.bit_string_from_randoms( self.randint_index_0,
                                                      field_width )
            randint_1 = self.bit_string_from_randoms( self.randint_index_1,
                                                      field_width )
            randint_2 = self.bit_string_from_randoms( self.randint_index_2,
                                                      field_width )
            randint_3 = self.bit_string_from_randoms( self.randint_index_3,
                                                      field_width )

            # Scramble those values.  The scramble is very sensitive,
            # and this the best of a half dozen I tried.
            return_integer += ( randint_0 * randint_1 ) + ( randint_2^randint_3)

        return self.fold.fold_it( return_integer, field_width )

    def randint2( self, field_width ) :
        """
        This selects a random field from the rnt.

        This is a boostrap random number generator, sufficient for
        initializing the hashes and LCGs.
        
        It uses each of 4 indexes to get an initial 16 bits, then uses
        that to indirect another level before returning the field_width
        bits at that last bit-index.

        It xors the 4 integers togather to produce the random number.
        Repeat paranoia level times.

        If the bits in the original table are random, this should
        produce random output for some time.  4KB is 32Kbits.
        Almost 32K worth of 64-bit integers can be extracted from that
        string. 32K = 2**15, any 2 bitstrings xored 2**30,
        any 3 2**45, any 4 2**60.  That is not 64-bits.  8K takes it to 2**64
        but it still wouldn't be good enough for crypto use, so further
        improvements aren't useful.

        It now passes dieharder up to craps, weak on 2 craps passes.
        3.07e+04 rands / second.

        So, this is random enough, but too slow.  Next_random_value is
        faster and more random.

        Now it fails dieharder badly, the reason is that there are zero
        counts in 0, 0.  Zeros in the high order byte are never. Some of
        the others are consequently out of whack, as high as .16.
        """
        return_integer = 0
        for cycle in range( self.paranoia_level ) :
            # get 4 bit strings from the indexes, mask to an index
            rnt_bitstr_0     = \
                    self.bit_string_from_randoms( self.randint_index_0, 32 )
            rnt_bit_index_0  = rnt_bitstr_0 & self.rnt_bit_index_mask

            rnt_bitstr_1     = \
                    self.bit_string_from_randoms( self.randint_index_1, 32 )
            rnt_bit_index_1  = rnt_bitstr_1 & self.rnt_bit_index_mask

            rnt_bitstr_2     = \
                    self.bit_string_from_randoms( self.randint_index_2, 32 )
            rnt_bit_index_2  = rnt_bitstr_2 & self.rnt_bit_index_mask

            rnt_bitstr_3     = \
                    self.bit_string_from_randoms( self.randint_index_3, 32 )
            rnt_bit_index_3  = rnt_bitstr_3 & self.rnt_bit_index_mask

            # Compute the next indexes from the bitstrings. Scrambled
            # makes cycles long, at least. Also, leave the index masked
            # rather than checking it every use.
            # The new index is based on the randint hash + 2 different
            # 16-bit values. This is prone to cycles, so getting enough
            # entropy in the indexes is the key. The folds do that, also the
            # addition of the shifts of the randint hash.
            # The randint_hash is produced by this code, it is the xor
            # of the aggregate output. The shift furtherfuzzes any
            # cycles.
            self.randint_index_0 += \
                    rnt_bitstr_0 + rnt_bitstr_3 + self.randint_hash
            self.randint_index_0  = \
                    self.fold.fold_it( self.randint_index_0,
                                       self.bits_in_rnt_mask )

            self.randint_index_1 += \
                    rnt_bitstr_1 + rnt_bitstr_2 + \
                                ( self.randint_hash >> cycle + 3 )
            self.randint_index_1  = \
                    self.fold.fold_it( self.randint_index_1,
                                       self.bits_in_rnt_mask )

            self.randint_index_2 += \
                    rnt_bitstr_2 + rnt_bitstr_1  + \
                    ( self.randint_hash >> cycle + 7 )
            self.randint_index_2  = \
                    self.fold.fold_it( self.randint_index_2,
                                       self.bits_in_rnt_mask )

            self.randint_index_3 += \
                    rnt_bitstr_3 + rnt_bitstr_0 + \
                    ( self.randint_hash >> cycle + 17 )
            self.randint_index_3  = \
                    self.fold.fold_it( self.randint_index_3,
                                       self.bits_in_rnt_mask )

            # fetch the 4 values from the RNT
            randint_0 = self.bit_string_from_randoms( rnt_bit_index_0,
                                                      field_width )
            randint_1 = self.bit_string_from_randoms( rnt_bit_index_1,
                                                      field_width )
            randint_2 = self.bit_string_from_randoms( rnt_bit_index_2,
                                                      field_width )
            randint_3 = self.bit_string_from_randoms( rnt_bit_index_3,
                                                      field_width )

            # scramble those values.  This scramble easily produced non-random
            # sequences, this version is the best of a half dozen I tried.
            return_integer += ( randint_0 * randint_1 ) + ( randint_2^randint_3)

            self.randint_hash ^= return_integer

        # return the random value masked to the field width.
        return return_integer & ( ( 1 << field_width ) - 1 )

    # other versions of randint could reset seeds to Wichmann or other
    # PRNGs from the RNT.rnt at frequent intervals or hash N values from
    # the table, with prime-number strides through the table so as to
    # ensure long periods.

    def next_random_value( self, entropy_bits, integer_width ) :
        """
        This combines a hash with the RNT to produce pseudorandom
        values.

        This is intended to be faster than randint, more random.

        This now passes dieharder, but 1.14e+04 so slow. The HASH0
        is 5X faster at 5.92e+04, also passes randint.

        Everything got slow, I think the paranoia level is the reason.
        """

        return_integer = 0
        for cycle in range( self.paranoia_level ) :

            # from the entropy_bits retrieve a RNT index for the bit-string.
            rnt_bit_index = entropy_bits & ( self.rnt_bit_index_mask )

            # get the integer
            the_integer = self.bit_string_from_randoms( rnt_bit_index,
                                                        integer_width )
            # one of many masking possibilities, another list of functions
            entropy_bits   += the_integer
            self.hash.update( entropy_bits )
            return_integer ^= self.hash.intdigest()

        return return_integer & ( 1 << integer_width ) - 1
            

    def scramble_list( self, the_list ) :
        """
        Scramble the ordering of elements in the list.

        Algorithm is to append randomly-selected elements from the original
        """
        new_order = []
        i = 0
        while i < len( the_list ) :
            this_index = self.wichmann.next( 1, 32 ) % len( the_list )
            if this_index not in new_order :
                new_order.append( this_index )
                i += 1

        out_list = []
        for i in range( len( the_list ) ) :
            out_list.append( the_list[ new_order[ i ] ] )

        return out_list

def clean_line( input_line ) :
    """
    Removes '\n', leading spaces and comments.

    Returns the line.
    """
#    debug( "\n\nclean_line : input_line = '" + input_line + "'", None,
#    5 )

    this_line = input_line.strip().rstrip()

    line_len = len( this_line )

    # before or after, the line can be nil
    if line_len == 0 :
        return ''

    if line_len > 0 :
        if this_line[ 0 ] == '>' :
            this_line = this_line[ 1 : ]
        line_len = len( this_line )

    if line_len > 1 :
        if this_line[ 0 : 2 ] == '>#' or \
           this_line[ 0 : 2 ] == '=>' or \
           this_line[ 0 : 2 ] == '+>' :
            this_line = this_line[ 2 : ]
        line_len = len( this_line )

    if line_len > 0 :
        if this_line[ 0 ] == '#' :
            return ''

    return this_line


def clean_lines( input_lines ) :
    """
    cleans all of the input lines, returns the list of clean lines.
    """
    new_list = []

    for this_line in input_lines :
        the_clean_line = clean_line( this_line )
        
        if the_clean_line :
            new_list.append( the_clean_line )

    return new_list

def construct_clean_lines( input_fd ) :
    """
    Commons out all the handling of the input file and cleaning the lines.
    """
    #
    # read the entire file into a list.
    #
    debug( "construct_clean_lines : Reading the input file", None, 5 )

    input_lines = input_fd.readlines()
    debug( "construct_clean_lines : Read the input lines OK", None, 5 )
    clean_line_list = clean_lines( input_lines )
    debug( "construct_clean_lines : Cleaned the input OK", None, 5 )
    # add a couple of lines to prevent the most common problem
    clean_line_list.append( "" )
    clean_line_list.append( "" )

    debug( "construct_clean_lines : clean lines OK", None, 5 )
    return clean_line_list

def rnt_rate( the_function, result_width, n_results ) :
    """
    The_function is one of the crypto or PRNG functions with a 'next'.
    Result_width is the desired width of the result of that function in
bits.
    N is the number of results to compute before returning bytes/second.
    """
    beginning_time = int( time.time() )
    for i in range( n_results ) :
        this_result = the_function( result_width )
    ending_time = int( time.time() )

    return ( n_results * ( result_width / 8 ) ) / ( ending_time - beginning_time )


#SINGLE_PROGRAM_TO_HERE

def usage() :
    """
    This provides 'help' and other usage information.
    """
    usage_info = """

        --test  <test name>
            adds a test to the list to be executed. can be repeated.
            
            Current tests are:
                'code'  encodes, then decodes plain text
    """
    print( usage_info )


#
# main begins here, generally test code for the module.
#
if __name__ == "__main__" :

    from array import array
    import random
    import time
                               
    BIN_VECTOR = array( 'L' )
    BIN_VECTOR.append( 0 )

    FILENAME = ''
    PASSWORD = ''
    SIZE     = 0

#    print '#' + __filename__
#    print '#' + __version__
#    print '#' + str( sys.argv[ 1 : ] )

    # which ones need an '=' ?
    SHORT_ARGS = "hf=p=s=t="
    LONG_ARGS  = [  'help', 'file=', 'password=', 'size=', 'test=' ]

    TEST_LIST = []      # list of tests to execute

    try :
        OPTS, ARGS = getopt.getopt( sys.argv[ 1 : ], SHORT_ARGS, LONG_ARGS )

    except getopt.GetoptError as err :
        print( "getopt.GetoptError = ", err )
        sys.exit( -2 )

    for o, a in OPTS :
#        print( "o = '" + o + "' a = '" + a )
        if o in ( "--help" ) or o in ( "-h" ) :
            usage()
            sys.exit( -2 )

        # note these options are sensitive to order, so new has to come
        # after password
        if o in ( "--file" ) :
            FILENAME = a

        if o in ( "--password" ) :
            PASSWORD = a

        if o in ( "--size" ) :
            SIZE = int( a )

        if o in ( "--test" ) :
            TEST_LIST.append( a )

#    print( "Test list = ", TEST_LIST )

    SO = os.fdopen( sys.stdout.fileno(), 'wb' )
#   SE = os.fdopen( sys.stderr.fileno(), 'wb' )

    BIN_VECTOR = array( 'L' )
    BIN_VECTOR.append( 0 )

    # need a random factor to prevent repeating random sequences
    random.seed()

    PASSPHRASE = 'this is a seed' + hex( random.getrandbits( 128 ) )

    THE_RNT = RNT( 4096, 1, 'desktop', PASSPHRASE )

    if 'randint' in TEST_LIST :

        while True :
            BIN_VECTOR[ 0 ] = THE_RNT.randint( 64 )
            BIN_VECTOR.tofile( SO )
#            BIN_VECTOR.tofile( SE )


    if 'randint1' in TEST_LIST :

        while True :
            BIN_VECTOR[ 0 ] = THE_RNT.randint1( 64 )
            BIN_VECTOR.tofile( SO )
#            BIN_VECTOR.tofile( SE )

    if 'randint2' in TEST_LIST :

        while True :
            BIN_VECTOR[ 0 ] = THE_RNT.randint2( 64 )
            BIN_VECTOR.tofile( SO )
#            BIN_VECTOR.tofile( SE )


    if 'randint_rate' in TEST_LIST :
        print( 'twister crypto byte rate = ',
               rnt_rate( THE_RNT.randint, 64, 1024*1024 ) )


    if 'next_random_value' in TEST_LIST :
        ENTROPY_BITS = 0XF3AF33210ED7FCA6F64C4C72488AC5DF
        while 1 :
            THE_RANDOM_NUMBER = THE_RNT.next_random_value( ENTROPY_BITS, 64 )
            BIN_VECTOR[ 0 ] = THE_RANDOM_NUMBER
            BIN_VECTOR.tofile( SO )
            ENTROPY_BITS ^= THE_RANDOM_NUMBER

        
    if 'wichmann' in TEST_LIST :
        WICHMANN = WichmannHill( [ random.getrandbits( 16 ),
                                   random.getrandbits( 16 ) , 0xfef ], 2 )

        while True :
            BIN_VECTOR[ 0 ] = WICHMANN.next( 1, 64 )
            BIN_VECTOR.tofile( SO )

