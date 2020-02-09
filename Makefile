CC=gcc
CFLAGS=-Wall -Werror -D_FILE_OFFSET_BITS=64 $(shell pkg-config --libs libbpf fuse)
LDFLAGS=$(shell pkg-config --libs libbpf fuse)

SOURCES=$(wildcard *.c)
EXECUTABLES=$(patsubst %.c,%,$(SOURCES))

all: $(EXECUTABLES)

start:
	sudo mkdir -p /mnt/bpf
	sudo ./bpf-map-fuse /mnt/bpf

stop:
	sudo killall bpf-map-fuse

clean:
	rm -f bpf-map-fuse

image/build:
	docker build -t docker.io/kinvolk/bpf-map-fuse .

image/start:
	docker rm bpf-map-fuse || true
	docker run -d --name=bpf-map-fuse --pid=host --privileged -v /mnt:/mnt:rshared kinvolk/bpf-map-fuse

image/stop:
	sudo umount /mnt/bpf/ || true
	docker stop bpf-map-fuse
	docker rm bpf-map-fuse || true
