FROM fedora:31

WORKDIR /usr/src/bpf-map-fuse
RUN \
	dnf install -y @development-tools fuse-devel libbpf-devel && \
	mkdir -p /mnt/bpf

COPY . .
RUN \
	make && \
	cp bpf-map-fuse /bin/

CMD ["/bin/sh", "-c", "mkdir /mnt/bpf ; bpf-map-fuse -d /mnt/bpf & sleep infinity"]
