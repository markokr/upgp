
pgp_test () {
#clear_list="$1"
#pass="$2"
#ciph_list="$3"
#hash_list="$4"
#mdc_list="$5"
#s2k_list="$6"
#cmp_list="$7"
#sessk_list="$8"
#dir=tmp
#debug=1
#pfx_gpg="gpg"
#pfx_upgp="upgp"

rm -f $dir/$pfx_upgp.*
rm -f $dir/$pfx_gpg.*


##
## decrypt test
##
for clear in $clear_list; do
for cipher in $ciph_list; do
for hash in $hash_list; do
for mdc in $mdc_list; do
for s2k in $s2k_list; do
for cmp in $cmp_list; do
  fn="$pfx_gpg.$clear.$cipher.$hash.$mdc.s2k$s2k.z$cmp"
  echo -n "Testing $fn ... "
  
  mf="--force-mdc"
  test $mdc = nomdc && mf="--disable-mdc"
  
  echo "$pass" | \
  gpg -c -a -q --batch $mf \
	--passphrase-fd 0 \
  	--s2k-mode $s2k \
	--cipher-algo "$cipher" \
	--digest-algo "$hash" \
	--compress-algo "$cmp" \
	-o "$dir/$fn" "$dir/$clear" 2> /dev/null && \
  { true; } || { echo "gpg failed"; }

  ./upgp -d -p "$pass" "$dir/$fn" > "$dir/$fn.out" \
  || {
  	echo decrypt failed.
	test $debug = 1 && {
	  rm -f core core.*
	  ./upgp -d -p "$pass" "$dir/$fn" -v -v
	}
	exit 
  }
  cmp -s "$dir/$clear" "$dir/$fn.out" || {
    echo CMP FAILED
    ls -l "$dir/$clear" "$dir/fn.out"
    exit
  }
  echo OK
done
done
done
done
done
done

##
## encrypt test
##
for clear in $clear_list; do
for cipher in $ciph_list; do
for hash in $hash_list; do
for mdc in $mdc_list; do
for s2k in $s2k_list; do
for cmp in $cmp_list; do
for sk in $sessk_list; do
  fn="$pfx_upgp.$clear.$cipher.$hash.$mdc.s2k$s2k.z$cmp.$sk"
  
  mf="--force-mdc"
  test $mdc = nomdc && mf="--disable-mdc"
  sf="--enable-sesskey"
  test $sk = nosk && sf="--disable-sesskey"
  
  echo -n "Testing $fn ... "
 
  ./upgp  -c -a -q --batch $mf \
  	--password "$pass" \
  	--s2k-mode $s2k \
	$sf \
	--cipher-algo "$cipher" \
	--digest-algo "$hash" \
	--compress-algo "$cmp" \
	"$dir/$clear" > "$dir/$fn" \
	|| { echo "## Generating $fn failed"; }

  ./upgp --decrypt "$dir/$fn" --password "$pass" > "$dir/$fn.out" \
  || {
  	echo failed.
	test $debug = 1 && {
	  ./upgp -d -p "$pass" "$dir/$fn" -v -v
	  #exit 
	}
  }
  cmp -s "$dir/$clear" "$dir/$fn.out" || {
    echo "CMP FAILED"
    ls -l "$dir/$clear" "$dir/$fn.out"
    exit
  }
  echo OK
done
done
done
done
done
done
done
} # pgp_test

