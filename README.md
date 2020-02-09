# bpf-map-fuse

FUSE-based filesystem for displaying the content of BPF maps.

## Getting started

```
make
make start
sudo ls -l /mnt/bpf
```

## Goals (TODO)

- Hash maps (key-value store) have a directory for each key and the content of the file is be the value
- Use BTF (BPF Type Format) to discover the format and display the content in an human-friendly wau
- Ring buffers could be read by continuously reading the file with `cat`


## Dependencies

- libfuse
- libbpf

## FAQ

*Q* Linux already has a BPF filesystem (/sys/fs/bpf), why another one?

*A* bpffs exists but it has a different purpose and cannot be used to
read or write map content from the shell.

