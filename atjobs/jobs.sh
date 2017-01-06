#!/usr/bin/bash

# $1 = Where at jobs are stored
# $2 = Outputfilename

find $1 -name “at*job” -print -exec ./jobparser.py -f {} \; >  $2.s1
grep Parameters $2.s1 | cut -d: -f 2- | sort | uniq -c | sort -h >  $2_review.txt
