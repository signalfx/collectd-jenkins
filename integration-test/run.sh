#!/bin/bash

DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

cd $DIR

cp Dockerfile.jenkins Dockerfile.jenkins.2603
sed -i -e "s#%%%VER%%%#2.60.3#g" ./Dockerfile.jenkins.2603
cp Dockerfile.jenkins Dockerfile.jenkins.2463
sed -i -e "s#%%%VER%%%#2.46.3#g" ./Dockerfile.jenkins.2463

printf "Running tests against python2.7\n"
docker-compose run --rm test
status=$?

docker-compose down

printf $status

if [ "$status" != "0" ]; then exit $status; fi

printf "\nRunning tests against python2.6"
docker-compose run --rm test26
status=$?

docker-compose down

printf $status

exit $status
