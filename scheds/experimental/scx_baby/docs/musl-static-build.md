# Building a static musl binary

On musl-based hosts (Chimera Linux for example) the scheduler is linked
statically. From a glibc build host, `musl-gcc` needs the kernel UAPI
headers and `argp`, and musl ships neither. Install `argp.h` and
`libargp.a` from argp-standalone into the musl include and lib trees, then
build with:

```sh
sudo cp -r /usr/include/{asm,asm-generic,linux} /usr/lib/musl/include/
rustup target add x86_64-unknown-linux-musl

CC_x86_64_unknown_linux_musl=musl-gcc \
ac_cv_search_fts_close='none required' \
ac_cv_search_fts_open='none required' \
ac_cv_search__obstack_free='none required' \
ac_cv_search_obstack_free='none required' \
cargo build --release --target x86_64-unknown-linux-musl -p scx_baby \
    --features 'libbpf-sys/vendored-libelf libbpf-sys/vendored-zlib \
                libbpf-sys/static-libelf libbpf-sys/static-zlib'
```

The `ac_cv_search_*` settings skip configure probes for symbols that the
static musl link resolves elsewhere. The result is a static-pie binary
that runs on any x86_64 Linux host.
