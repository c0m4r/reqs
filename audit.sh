#!/bin/bash

if ! command -v cargo-audit &>/dev/null ; then
    cargo install cargo-audit --locked
fi
cargo audit
