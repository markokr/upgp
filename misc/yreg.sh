#! /bin/sh

kdir=/opt/src/pgcrypto/upgp/crap
key=$kdir/rsa2048
key=$kdir/elg2048
key=$kdir/test

tmp=/tmp/utest

enc_file=$tmp/upgp.enc
dec_upgp=$tmp/uphp.dec.sha1
dec_gpg=$tmp/gpg.dec.sha1
dec_test=$tmp/real.sha1

for f; do
test -d "$f" && { echo "skip dir: $f"; continue; } 
test -f "$f" || { echo "file not found: $f"; exit 1; }

echo -n "testing $f ... "

echo -n "upgp.enc "
./upgp -c -p parool --key $key.pub $f > $enc_file \
|| { echo -e "failed\nupgp enc failed: $f"; exit 1; }

echo -n "upgp.dec "
./upgp -d -p parool --key $key.sec $enc_file | sha1sum > $dec_upgp \
|| { echo -e "failed\nupgp dec failed: $f"; exit 1; }

echo -n "gpg.dec "
gpg --quiet < $enc_file | sha1sum > $dec_gpg \
|| { echo -e "failed\ngpg dec failed: $f"; exit 1; }

echo "cmp"
cat "$f" | sha1sum > "$dec_test"
cmp "$dec_upgp" "$dec_gpg" || { echo -e "\ncompare1 failed: $f"; exit 1; }
cmp "$dec_test" "$dec_gpg" || { echo -e "\ncompare2 failed: $f"; exit 1; }

done

exit 0

