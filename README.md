Go to [the Miniscript website](http://bitcoin.sipa.be/miniscript/).

This repository contains a C++ implementation of Miniscript and a number of
related things:
* The core Miniscript module ([cpp](bitcoin/script/miniscript.cpp), [h](bitcoin/script/miniscript.h)) together with a number of [dependencies](bitcoin/) based on
  the Bitcoin Core source code.
* A policy to Miniscript compiler ([cpp](compiler.cpp), [h](compiler.h)).
* Javascript wrappers for the website ([cpp](js_bindings.cpp)).
* The project website ([.html](index.html)).
