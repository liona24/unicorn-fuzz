The example was built using in the given docker environment using the build.sh.
To keep things simple they are built statically linked.

After that it was emulated using gdb-server in an emulated system using qemu-system-mipsel with a custom kernel (any should work)
Then the usual gdb_dump_snapshot.py was used to dump the process.

Sadly the coverage instrumentation does not seem to be that powerful for MIPS, thus fuzzing may take a looong time..
