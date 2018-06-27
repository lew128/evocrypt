#!/bin/bash

./evocrypt.py --password ultraamber < test_file.txt > test_file.txt.encoded

./evocrypt.py --password ultraamber < test_file.txt.encoded > test_file.txt.v2

diff test_file.txt test_file.txt.v2
