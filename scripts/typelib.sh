#!/usr/bin/env bash

cargo run --features stl --package commit_verify commit-stl -s
cargo run --features stl --package commit_verify commit-stl -b
cargo run --features stl --package commit_verify commit-stl -h
