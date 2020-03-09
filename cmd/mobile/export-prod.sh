#!/usr/bin/env bash

#gomobile bind --target=android -v
gomobile bind --target=android -ldflags="-s -w" -v --trimpath
#gomobile bind --target=ios -ldflags="-s -w" -v --trimpath