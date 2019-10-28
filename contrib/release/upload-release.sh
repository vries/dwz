#!/bin/sh -x

set -e

pwd=$(pwd -P)

version="$1"

tag=dwz-$version
rootdir=dwz
tarfile=dwz-$version.tar
server=sourceware.org
ftpdir=/sourceware/ftp/pub/dwz/releases
# The server itself seems to add a sha512.sum file, so lets not duplicate that
# effort.
#checksums="md5sum sha512sum"
checksums="md5sum"

repo="$pwd"

dir=$(mktemp -d)

cd $dir
git clone \
    $repo \
    $rootdir

cd $dir/$rootdir
git ch $tag

rm -Rf .git

cd $dir
tar cvf \
    $tarfile \
    $rootdir

xz \
    --best \
    -k \
    $tarfile

gzip \
    --best \
    -k \
    $tarfile

files=$(echo $tarfile.*)

[ "$files" != "" ]

ssh $server \
    "mkdir -p $ftpdir"

scp \
    $files \
    "$server:$ftpdir"

ssh $server \
    "cd $ftpdir && chmod 644 $files"

for checksum in $checksums; do
    ssh $server \
	"cd $ftpdir && touch $checksum && chmod 644 $checksum && ( $checksum $files >> $checksum )"
done

rm -Rf $dir
