#!/bin/bash
# use testnet settings,  if you need mainnet,  use ~/.tiajians/tiajiansd.pid file instead
tiajians_pid=$(<~/.tiajians/testnet3/tiajiansd.pid)
sudo gdb -batch -ex "source debug.gdb" tiajiansd ${tiajians_pid}
