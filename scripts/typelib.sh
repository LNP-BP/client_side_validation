#!/usr/bin/env bash

cargo run --features stl,vesper --package commit_verify --bin commit-stl -- --stl
cargo run --features stl,vesper --package commit_verify --bin commit-stl -- --sty
cargo run --features stl,vesper --package commit_verify --bin commit-stl -- --sta
