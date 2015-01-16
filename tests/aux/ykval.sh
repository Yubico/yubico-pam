#!/bin/bash

out=`mktemp /tmp/ykval_mock.XXXXXX`
rm -f $out
mkfifo $out
trap "rm -f $out" EXIT
while true
do
  cat $out | nc -l 8888 > >(
    while read line
    do
      line=$(echo "$line" | tr -d '[\r\n]')

      if echo "$line" | grep -qE '^GET /'; then
        REQUEST=$(echo "$line" | cut -d ' ' -f2)
      elif [ "x$line" = x ]; then
        echo $REQUEST
        nonce=`echo "$REQUEST" | awk -F\& '{print $2}'`
        otp=`echo "$REQUEST" | awk -F\& '{print $3}'`
        if [ x$otp = "xotp=vvincredibletrerdegkkrkkneieultcjdghrejjbckh" ]; then
          status="status=OK"
        else
          status="status=BAD_OTP"
        fi
        echo "h=ZrU7UfjwazJVf5ay1P/oC3XCQlI=
$nonce
$otp
$status" > $out
      fi
    done
  )
done
