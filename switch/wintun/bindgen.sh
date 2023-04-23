#!/bin/bash
bindgen \
--allowlist-function "Wintun.*" \
--allowlist-type "WINTUN_.*" \
--dynamic-loading wintun \
--dynamic-link-require-all \
wintun/wintun_functions.h > src/wintun_raw.rs
