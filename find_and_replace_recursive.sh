#!/bin/bash
#find . -type f -name "*.go" -exec sed -i'' -e 's/github.com\/deroproject/github.com\/deromask/g' {} +
find . -type f -name "*.go" -exec sed -i'' -e 's/github.com\/deroproject\/derosuite/github.com\/deromask\/derosuite/g' {} +
