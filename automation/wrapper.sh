#!/bin/sh
# This script is a wrapper for our fuzzer tester
# example:
#  python FileTests.py -pi ../afl-1.83b/ImageMagick-6.5.4-10/utilities/inimage/ -po ../afl-1.83b/oi -p ../afl-1.83b/ImageMagick-6.5.4-10/utilities/convert -f ../afl-1.85b/afl-fuzz -o testdir -s ../afl-1.83b/ImageMagick-6.5.5-10/utilities/convert ../afl-1.83b/ImageMagick-6.7.0-10/utilities/convert ../afl-1.83b/ImageMagick-6.8.6-10/utilities/convert
#
 
# The input to the fuzzer
pi="/home/wrv/afl-1.83b/ImageMagick-6.5.4-10/utilities/inimage/"
# the output to the fuzzer
po="/home/wrv/afl-1.83b/oi"
# the program to fuzz
p="/home/wrv/afl-1.83b/ImageMagick-6.5.4-10/utilities/convert"
# the link to the fuzzer
f="/home/wrv/afl-1.85b/afl-fuzz"
# the output directory for our results
o="testdir"
# the other programs
s="../afl-1.83b/ImageMagick-6.5.5-10/utilities/convert ../afl-1.83b/ImageMagick-6.7.0-10/utilities/convert ../afl-1.83b/ImageMagick-6.8.6-10/utilities/convert"

python FileTests.py -pi $pi -po $po -p $p -f $f -o $o -s $s
