#!/bin/bash


argc=$#
if [ $argc != 1 ]; then
	echo "Usage:resign.sh src.apk"
	exit
fi

verify='apksigner verify -v '$1
echo $verify
is_sign=$($verify)
#echo $is_sign

function do_signapk(){
	command='apksigner sign '
	ks=' --ks my-release-key.jks --ks-pass pass:123456'
	ver=' --min-sdk-version 16 '
	v1=' --v1-signing-enabled true '
	v2=' --v2-signing-enabled true'
	v3=' --v3-signing-enabled false'
	v4=' --v4-signing-enabled false'
	apk=' --out out-signed.apk '$1

	command=$command$ks$ver$v1$v2$v3$v4$apk
	echo $command
	$($command)
}

function del_meta_file(){
	echo "del apk/META-INF"
	mkdir out
	cp $1 ./out
	cd out
	jar -xvf $1
	rm -rf META-INF
	rm $1
	jar -cvfM out.apk ./
	mv out.apk ../
	cd ..
	rm -rf ./out
}

Verified='Verified'
case $is_sign in
  *"$Verified"*)
    echo "Verified."
    #signed
    del_meta_file $1
    do_signapk out.apk
    rm -f out.apk
    apksigner verify -v out-signed.apk
    echo 'signed ok'
    exit
    ;;
esac

#unsigned
do_signapk $1
apksigner verify -v out-signed.apk
echo 'signed ok'
exit


