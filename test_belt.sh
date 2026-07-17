#!/bin/bash
# -sanitize:address -disable-assert
build_flags="-o:speed"
vet_flags="-strict-style -vet-tabs -disallow-do -warnings-as-errors"
define_flags="-define:ODIN_TEST_THREADS=0 -define:ODIN_TEST_RANDOM_SEED=2048 -define:ODIN_TEST_TRACK_MEMORY=false"
odin test . $build_flags $vet_flags $define_flags
