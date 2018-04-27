#!/bin/bash

# These are Dieharder tests I have run, here put into a script.
# the tail allows watching progress without wasting a window.

# Running this serially through ALL of the dieharder tests will take a
# very long time.

./evofolds.py --password umberalertness --test xadd0 | dieharder -a -g 200 -p 200 -t 200 > folds_xadd0.stdout 2> folds_xadd0.stderr &; tail -f folds_xadd0.stdout

 ./evofolds.py --password umberalertness --test xadd1 | dieharder -a -g 200 -p 200 -t 200 > folds_xadd1.stdout 2> folds_xadd1.stderr &; tail -f
 folds_xadd1.stdout

./evofolds.py --password umberalertness --test xor0 | dieharder -a -g
200 -p 200 -t 200 > folds_xor0.stdout 2> folds_xor0.stderr &; tail -f folds_xor0.stdout

 ./evofolds.py --password umberalertness --test xor1 | dieharder -a -g 200 -p 200 -t 200 > folds_xor1.stdout 2> folds_xor1.stderr &; tail -f folds_xor1.stdout

./evohashes.py --test hash0 | dieharder -a -g 200 -p 200 -t 200 > hashes_hash0.stdout 2> hashes_hash0.stderr &; tail -f hashes_hash0.stdout

./evohashes.py --test hash1 | dieharder -a -g 200 -p 200 -t 200 > hashes_hash0.stdout 2> hashes_hash0.stderr &; tail -f hashes_hash1.stdout

./evornt.py --password umberalertness --test next_random_value | dieharder -a -g 200 -p 200 -t 200 > rnt_nrv.stdout 2> rnt_nrv.stderr &; tail -f rnt_nrv.stdout

./evornt.py --password umberalertness --test wichmann | dieharder -a -g 200 -p 200 -t 200 > rnt_wich.stdout 2> rnt_wich.stderr &; tail -f rnt_wich.stdout

./evornt.py --password umberalertness --test randint | dieharder -a -g 200 -p 200 -t 200 > rnt_randint.stdout 2> rnt_randint.stderr &; tail -f rnt_randint.stdout

./evornt.py --password umberalertness --test randint1 | dieharder -a -g 200 -p 200 -t 200 > rnt_randint1.stdout 2> rnt_randint1.stderr &; tail -f rnt_randint1.stdout

./evornt.py --password umberalertness --test randint2 | dieharder -a -g 200 -p 200 -t 200 > rnt_randint2.stdout 2> rnt_randint2.stderr &; tail -f rnt_randint2.stdout

Results :

wichmann was weak in 1 lagged sum
