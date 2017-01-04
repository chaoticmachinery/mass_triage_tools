analyzeMFT.py -p -f ../MFT -o out.csv --bodyfull
cut -d, -f 8  win10_mft.csv | grep -v "NoFNRecord" | grep -v "Corrupt MFT Record" |sort |sed 's/$/,\"win10_64\"/ > z1
 sed 's/\//\\/g' win10_64.csv > win10_64a.csv

