#!/bin/bash
# this runs evocrypt to extract a single-file program, 'evo_new0.py'
# evo_new0.py is used to generate a next-generation, 'evo_new10x*.py'
# evo_new10x*.py is used to encrypt and decrypt a program.

rm evo_new0*.py evo_new0.stderr evo_new0.stdout

./evocrypt.py --password amberalertness --assemble evo_new0.py > evo_new0.stdout 2> evo_new0.stderr

chmod +x evo_new0*.py

if [ ! -f evo_new0*.py ]; then
    echo "evo_new0*.py not found!"
    exit 0
fi

rm evo_new1*.py evo_new1*.stderr evo_new1*.stdout
./evo_new0*.py --password amberalert --new evo_new1 > evo_new1.stdout 2> evo_new1.stderr


if [ ! -f evo_new1*.py ]; then
    echo "evo_new1*.py not found!"
    exit 0
fi
chmod +x evo_new1*.py

./evo_new1*.py --password umberalertness --encrypt test_file.txt > evo_new1_encrypt.stdout 2> evo_new1_encrypt.stderr

./evo_new1*.py --password umberalertness --decrypt test_file.txt*.evocrypt > evo_new1_decrypt.stdout 2> evo_new1_decrypt.stderr

