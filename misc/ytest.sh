#! /bin/sh

key=crap/rsa2048
key=crap/elg2048

echo "==encrypt=="
echo Foo | ./upgp -c -v -v -p parool --key $key.pub > $key.msg \
|| { echo "enc failed"; exit 0; }

echo "==decrypt=="
./upgp -d -v -v -p parool --key $key.sec < "$key.msg" \
|| { echo "dec failed"; }

