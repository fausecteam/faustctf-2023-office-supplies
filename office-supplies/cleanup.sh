#!/bin/sh -eu

while true; do
	sleep 1m
	# Cleanup old objects
	find -type f /app/objects/ -mmin +20 -delete
done
