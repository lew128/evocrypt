#!/bin/bash

# These are Dieharder tests I have run, here put into a script.
# the tail allows watching progress without wasting a window.

# Running this serially through ALL of the dieharder tests will take a
# very long time.

./evofolds.py --password umberalertness --test xadd0 | dieharder -a -g 200 -p 200 -t 200 > folds_xadd0.stdout 2> folds_xadd0.stderr 

 ./evofolds.py --password umberalertness --test xadd1 | dieharder -a -g 200 -p 200 -t 200 > folds_xadd1.stdout 2> folds_xadd1.stderr 
 folds_xadd1.stdout

./evofolds.py --password umberalertness --test xor0 | dieharder -a -g
200 -p 200 -t 200 > folds_xor0.stdout 2> folds_xor0.stderr 

 ./evofolds.py --password umberalertness --test xor1 | dieharder -a -g 200 -p 200 -t 200 > folds_xor1.stdout 2> folds_xor1.stderr 

./evohashes.py --test hash0 | dieharder -a -g 200 -p 200 -t 200 > hashes_hash0.stdout 2> hashes_hash0.stderr 

./evohashes.py --test hash1 | dieharder -a -g 200 -p 200 -t 200 > hashes_hash0.stdout 2> hashes_hash0.stderr 

./evornt.py --password umberalertness --test next_random_value | dieharder -a -g 200 -p 200 -t 200 > rnt_nrv.stdout 2> rnt_nrv.stderr 

./evornt.py --password umberalertness --test wichmann | dieharder -a -g 200 -p 200 -t 200 > rnt_wich.stdout 2> rnt_wich.stderr 

./evornt.py --password umberalertness --test randint | dieharder -a -g 200 -p 200 -t 200 > rnt_randint.stdout 2> rnt_randint.stderr 

./evornt.py --password umberalertness --test randint1 | dieharder -a -g 200 -p 200 -t 200 > rnt_randint1.stdout 2> rnt_randint1.stderr 

./evornt.py --password umberalertness --test randint2 | dieharder -a -g 200 -p 200 -t 200 > rnt_randint2.stdout 2> rnt_randint2.stderr 

Results :

wichmann was weak in 1 lagged sum

But, having changed most of the functions to compute a result twice as
many bits long as asked for, then folding to the required length,  I need
to run all those again.  I predict many fewer weak results next run.
