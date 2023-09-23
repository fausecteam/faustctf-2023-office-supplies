#!/bin/sh -eu

DOCKER_BUILDKIT=1 docker build -f Dockerfile.build . --output=bin/
