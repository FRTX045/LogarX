# Code compiled into go-re2

`github.com/wasilibs/go-re2` v1.6.0, the RE2 engine behind the sidecar's
`@rx` (`crs/rx.go`), carries other projects' code inside it. Its
`internal/wasm/libcre2.so` is a WebAssembly module that its
`buildtools/re2/Dockerfile` builds with wasi-sdk-22 from:

| Component | Version | Licence | Here |
|---|---|---|---|
| RE2 | 2023-03-01 | BSD-3-Clause | `re2/LICENSE` |
| cre2, RE2's C wrapper | as copied into go-re2 | BSD-3-Clause | `cre2/NOTICE.txt` |
| wasi-libc, with musl and cloudlibc in it | wasi-sdk-22 | Apache-2.0 with LLVM exception, or MIT; musl MIT; cloudlibc BSD-2-Clause | `wasi-libc/` |
| libc++, libc++abi, compiler-rt | LLVM, wasi-sdk-22 | Apache-2.0 with LLVM exception | `llvm/LICENSE.TXT` |

The go-re2 module carries its own licence and cre2's notice, but not the
others. So `packaging/crs_bundle.py` cannot find them the way it finds every
other module's licence, and this folder ships beside go-re2's licence in the
packaged application instead.

The texts were taken from each project's repository at the version above.
When go-re2 is upgraded, read its Dockerfile again: the versions it builds
from may have changed, and so may the list. `tests/packaging/test_crs_bundle.py`
fails until the version in the first line here matches `crs/go.mod`.
