#!/bin/bash
echo "Running docker image"
docker run --rm --log-driver local --mount source=vol,destination=/storage -it fordefi.jfrog.io/fordefi/api-signer:latest
