#! /bin/sh

. ./libtest.sh

ulimit -c unlimited
test -x upgp || { echo compile first; exit; }

mkdir -p tmp

dir=tmp
debug=1
pfx_gpg="gpg"
pfx_upgp="upgp"

rm -f $dir/$pfx_upgp.*
rm -f $dir/$pfx_gpg.*

## generate clears
echo @@@ Generating data
echo foobar > $dir/dat1
dd if=/dev/zero of=$dir/dat2 bs=1024 count=128 2> /dev/null
dd if=/dev/urandom of=$dir/dat3 bs=1 count=1 2> /dev/null
dd if=/dev/urandom of=$dir/dat4 bs=1 count=35 2> /dev/null
dd if=/dev/urandom of=$dir/dat5 bs=1024 count=80 2> /dev/null
#cp gx.upgp.c $dir/dat5
clear_list="dat1 dat2 dat3 dat4 dat5"

echo "@@@ Short check"
clear_list="dat1"
pass="foobar"
ciph_list="aes aes256"
hash_list="sha1"
mdc_list="nomdc mdc"
s2k_list="3"
cmp_list="0 1"
sessk_list="nosk"
pgp_test
#ciph_list="cast5"
ciph_list="aes"
clear_list="dat5"

echo "@@@ Checking ciphers"
clear_list="dat1 dat2 dat5"
pass="foobar"
ciph_list="cast5 blowfish "
ciph_list="aes"
ciph_list="3des blowfish cast5 aes aes192 aes256"
hash_list="sha1"
mdc_list="nomdc mdc"
s2k_list="0 1 3"
cmp_list="0 1 2"
sessk_list="nosk sk"
pgp_test
#ciph_list="cast5"
ciph_list="aes"
clear_list="dat5"

echo "@@@ Checking MDC modes"
mdc_list="nomdc mdc"
pgp_test
mdc_list="mdc"

echo "@@@ Checking hashes"
hash_list="md5 sha1"
pgp_test
hash_list="sha1"

echo "@@@ Checking S2K modes"
sessk_list="nosk sk"
s2k_list="0 1 3"
pgp_test
s2k_list="3"
sessk_list="nosk"

echo "@@@ Checking compression modes"
clear_list="dat1 dat2 dat3 dat4 dat5"
cmp_list="0 1 2"
pgp_test
clear_list="dat5"
cmp_list="1"

echo "@@@ Checking longer passwords"
pass="0123456789abcdefghij"
pgp_test
pass="0123456789abcdefghij2jk4h5g2j54khg23h54g2kh54g2khj54g23hj54"
pgp_test
pass="x"
pgp_test


