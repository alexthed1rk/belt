#!/bin/bash
# -sanitize:address
build_flags="-o:aggressive -disable-assert"
vet_flags="-strict-style -vet-tabs -disallow-do -warnings-as-errors"
define_flags="-define:ODIN_TEST_THREADS=1 -define:ODIN_TEST_RANDOM_SEED=2048 -define:ODIN_TEST_TRACK_MEMORY=false"
odin test . $build_flags $vet_flags $define_flags
