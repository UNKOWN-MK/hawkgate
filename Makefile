.PHONY: all kernel hawkgated clean rebuild

all: kernel hawkgated

# kernel must build first — produces kernel/build/hg_reader.o that hawkgated links
kernel:
	$(MAKE) -C kernel

hawkgated: kernel
	$(MAKE) -C hawkgated

rebuild:
	$(MAKE) -C kernel clean
	$(MAKE) -C hawkgated clean
	$(MAKE) all

clean:
	$(MAKE) -C kernel clean
	$(MAKE) -C hawkgated clean
