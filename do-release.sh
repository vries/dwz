#!/bin/sh

set -e

do_minor=false
do_major=false

while [ $# -gt 0 ]; do
    case "$1" in
	--minor)
	    do_minor=true
	    ;;
	--major)
	    do_major=true
	    ;;
	*)
	    echo "Unknown option: $1"
	    exit 1
    esac
    shift
done

if $do_minor && $do_major; then
    echo "Can only bump minor or major, not both"
    exit 1
fi

if ! $do_minor && ! $do_major; then
    echo "Need to bump minor or major"
    exit 1
fi

git checkout master

version=$(cat VERSION)

minor=$(echo $version \
	    | sed 's/.*\.//')
major=$(echo $version \
	    | sed 's/\..*//')
echo Current version: major: $major,  minor: $minor

if $do_minor; then
    echo "Bumping minor version"
    minor=$(($minor + 1))
elif $do_major; then
    echo "Bumping major version"
    major=$(($major + 1))
    minor=0
fi
echo Bumped version: major: $major,  minor: $minor

version=$major.$minor

echo $version > VERSION

git add VERSION

git commit -m "Bump version to $version"

git tag dwz-$version
