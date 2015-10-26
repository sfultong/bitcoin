Bitcoin Core fork for spinoff snapshot creation
===============================================

Forked from https://github.com/bitcoin/bitcoin

Changes
-------

Added RPC command to write snapshot file (writesnapshot)

Building
--------

I've hardcoded some paths into src/Makefile.am that will need to be changed.

New dependencies:
 * https://github.com/libbitcoin/libbitcoin
 * https://github.com/sfultong/bitcoin-spinoff-toolkit

