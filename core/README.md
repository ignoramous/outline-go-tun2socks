This directory contains a small subset of files from https://github.com/eycorsican/go-tun2socks.

This branch of outline-go-tun2socks does not rely on eycorsican/go-tun2socks, but the included files here are needed to match interfaces and maintain the DNS fallback behavior.

If this branch progresses, it will not be necessary to maintain the interfaces used by eycorsican/go-tun2socks, and this code can be removed.  The `core.*Conn` and `core.*Handler` interfaces can be replaced by a `Dialer`-type interface.