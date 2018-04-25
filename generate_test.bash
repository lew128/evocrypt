#!/bin/bash
# this runs evocrypt to extract a single-file program, 'lew.py'
# lew.py is used to generate a next-generation, 'fred0x*.py'
# fred0x*.py is used to generate a new random number table
rm lew*.py lew.stderr lew.stdout

./evocrypt.py --password amber --assemble lew.py > lew.stdout 2> lew.stderr

chmod +x lew*.py

if [ ! -f lew*.py ]; then
    echo "lew*.py not found!"
    exit 0
fi

rm fred*.py fred*.stderr fred*.stdout
./lew*.py --password amberalert --new fred > fred.stdout 2> fred.stderr


if [ ! -f fred*.py ]; then
    echo "fred*.py not found!"
    exit 0
fi
chmod +x fred*.py
./fred*.py --password umberalertness --generate 8192 > fg.stdout 2> fg.stderr

