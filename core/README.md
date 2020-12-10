This directory contains a small subset of files from https://github.com/eycorsican/go-tun2socks.

This branch of outline-go-tun2socks does not rely on eycorsican/go-tun2socks, but the included files here are temporarily needed to match interfaces and maintain the DNS fallback behavior.  This copy is used to avoid a dependency on go-tun2socks/core, which pulls in LWIP.

If this branch progresses, it will not be necessary to maintain the interfaces used by eycorsican/go-tun2socks, and this code can be removed.  The `core.*Conn` and `core.*Handler` interfaces can be replaced by a `Dialer`-type interface.