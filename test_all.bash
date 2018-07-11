#!/bin/bash
cd ~/EvoCrypt/test/

today=`date '+%Y_%m_%d__%H_%M_%S'`;
./test_evofolds.py > test_evofolds.py_$today

today=`date '+%Y_%m_%d__%H_%M_%S'`;
./test_evohashes.py > test_evohashes.py_$today

today=`date '+%Y_%m_%d__%H_%M_%S'`;
./test_evoprimes.py > test_evoprimes.py_$today

today=`date '+%Y_%m_%d__%H_%M_%S'`;
./test_evoprngs.py > test_evoprngs.py_$today

today=`date '+%Y_%m_%d__%H_%M_%S'`;
./test_evornt.py > test_evornt.py_$today

today=`date '+%Y_%m_%d__%H_%M_%S'`;
./test_evocprngs.py > test_evocprngs.py_$today

today=`date '+%Y_%m_%d__%H_%M_%S'`;
./test_evocrypts.py > test_evocrypt.py_$today
