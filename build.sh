#! /bin/bash
set -x
set -e

(cd libaes_siv && git clean -fdx && cmake . && make)
