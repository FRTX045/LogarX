# Code compiled into go-re2

`github.com/wasilibs/go-re2` v1.12.0, the RE2 engine behind the sidecar's
`@rx` (`crs/rx.go`), carries other projects' code inside it. Its
`buildtools/wasm/Dockerfile` builds RE2 to a WebAssembly module with
wasi-sdk-25 and then translates that module to Go with wasm2go, which is the
`internal/wasm/libcre2.wasm.go` the sidecar compiles. Built from:

| Component | Version | Licence | Here |
|---|---|---|---|
| RE2 | 2025-11-05 | BSD-3-Clause | `re2/LICENSE` |
| Abseil, which RE2 needs | 20240722.0 | Apache-2.0 | `abseil/LICENSE` |
| cre2, RE2's C wrapper | as copied into go-re2 | BSD-3-Clause | `cre2/NOTICE.txt` |
| wasi-libc, with musl, cloudlibc and musl-fts in it | wasi-sdk-25 (`574b88d`) | Apache-2.0 with LLVM exception, or MIT; musl MIT; cloudlibc BSD-2-Clause; musl-fts BSD-3-Clause | `wasi-libc/` |
| libc++, libc++abi, compiler-rt | LLVM, wasi-sdk-25 (`ab4b5a2`) | Apache-2.0 with LLVM exception | `llvm/LICENSE.TXT` |

wasm2go itself is not in the list: its output is that module rewritten as Go,
importing nothing but the standard library. Neither is wazero, which go-re2
still requires but compiles in only under its `re2_wazero` build tag, and the
sidecar is built without it.

The go-re2 module carries its own licence and cre2's notice, but not the
others. So `packaging/crs_bundle.py` cannot find them the way it finds every
other module's licence, and this folder ships beside go-re2's licence in the
packaged application instead.

The texts were taken from each project's repository at the version above;
`llvm/LICENSE.TXT` is libc++'s own, identical at wasi-sdk-22 and wasi-sdk-25.
When go-re2 is upgraded, read its Dockerfile again: the versions it builds
from may have changed, and so may the list. `tests/packaging/test_crs_bundle.py`
fails until the version in the first line here matches `crs/go.mod`.
