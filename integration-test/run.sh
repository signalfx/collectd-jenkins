#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd $DIR

sed -e "s#%%%VER%%%#2.60.3#g" ./Dockerfile.jenkins > ./Dockerfile.jenkins.2603
sed -e "s#%%%VER%%%#2.46.3#g" ./Dockerfile.jenkins > ./Dockerfile.jenkins.2463

printf "Running tests against python2.7\n"
docker-compose run --rm test-jenkins
status=$?

docker-compose down

printf $status
exit $status
