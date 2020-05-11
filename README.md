# bpf-map-fuse

FUSE-based filesystem for displaying the content of BPF maps.

## Getting started

### From the sources

```
make
make start
sudo ls -l /mnt/bpf
```

### From the container image

```
make image/start
sudo ls -l /mnt/bpf
```

### Usage example

```
$ sudo bpftool map
10: lpm_trie  flags 0x1
	key 8B  value 8B  max_entries 1  memlock 4096B
11: lpm_trie  flags 0x1
	key 20B  value 8B  max_entries 1  memlock 4096B
$ sudo ls -l  /mnt/bpf/
total 0
drwx------ 2 root root 0 Jan  1  1970 10
drwx------ 2 root root 0 Jan  1  1970 11
$ sudo ls -l  /mnt/bpf/10
total 0
-r-------- 1 root root 0 Jan  1  1970 info
-r-------- 1 root root 0 Jan  1  1970 type
$ sudo cat /mnt/bpf/10/info
id 10 name  type lpm_trie key 8B  value 8B  max_entries 1
$ sudo cat /mnt/bpf/10/type
lpm_trie
$
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

