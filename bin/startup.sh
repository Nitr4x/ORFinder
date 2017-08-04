#!/bin/bash

tor&
sleep 10
./bin/orfinder $@
