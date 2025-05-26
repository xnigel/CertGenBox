#!/bin/bash

cmd=`openssl rand -hex 4096 > randpool.dat`
echo $cmd
