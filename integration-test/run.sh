#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd $DIR

sed -e "s#%%%VER%%%#2.263.4-lts#g" ./Dockerfile.jenkins > ./Dockerfile.jenkins0
sed -e "s#%%%VER%%%#2.249.3-lts#g" ./Dockerfile.jenkins > ./Dockerfile.jenkins1

printf "Running tests against python2.7\n"
docker-compose run --rm test-jenkins
status=$?

docker-compose down

printf $status
exit $status
