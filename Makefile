b:
	clang -O3 -Wno-deprecated-declarations -o macos_kfd macos_kfd.c

r:
	sync
	./macos_kfd

br:
	make b
	make r

s:
	sudo sysctl kern.maxfiles=262144
	sudo sysctl kern.maxfilesperproc=262144
