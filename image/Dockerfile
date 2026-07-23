# limes base image — near-scratch host-mirror skeleton.
#
# The container mounts the host's /usr read-only at runtime, so the image itself
# ships almost nothing: just the usr-merge symlinks (so /bin, /lib, /lib64 resolve
# into the mounted host /usr), the mountpoint directories, and a static rescue
# busybox stashed at /limes (a path the host mounts never shadow) for when a mount
# is missing and you need a shell to debug.
#
# Built with no build context (`docker build -`): everything comes from the busybox
# builder stage, nothing from the host filesystem.

FROM busybox:musl AS bb
RUN set -eux; \
    root=/rootfs; \
    mkdir -p \
        "$root/usr/bin" "$root/usr/lib" "$root/usr/local/bin" \
        "$root/etc" "$root/home" "$root/root" "$root/run" "$root/tmp" \
        "$root/var" "$root/proc" "$root/sys" "$root/dev" "$root/limes"; \
    cp /bin/busybox "$root/limes/busybox"; \
    # usr-merge: mirror a modern Arch/Debian layout so host binaries and the
    # dynamic linker (/lib64/ld-linux-*) resolve into the mounted host /usr.
    #
    # /lib64 points at usr/lib64 rather than usr/lib because the two distro families
    # disagree about where the linker lives, and only usr/lib64 is right on both:
    # Arch has /usr/lib64 as a symlink to lib, while Debian/Ubuntu make it a real
    # directory holding ld-linux-x86-64.so.2 and put everything else under
    # /usr/lib/x86_64-linux-gnu. Pointing at usr/lib resolves on Arch and leaves
    # Debian with no interpreter at the path every one of its binaries requests --
    # which surfaces as `exec /usr/bin/zsh: no such file or directory`, an ENOENT
    # about the interpreter that reads as if the binary itself were missing.
    # /sbin points at usr/sbin, not usr/bin, for the same reason /lib64 points at
    # usr/lib64: the families disagree and only usr/sbin is right on both. Debian keeps
    # admin tools in a real /usr/sbin (and ships an ldconfig wrapper that `exec`s the
    # hardcoded /sbin/ldconfig.real -- broken if /sbin lands in /usr/bin); Arch has
    # /usr/sbin as a symlink to bin, so usr/sbin resolves back to /usr/bin there. Pointing
    # at usr/bin left every /sbin tool missing on Debian, which is how `ldconfig -p` (and
    # so anything locating a lib through it, e.g. idapyswitch) came back empty.
    ln -s usr/bin   "$root/bin"; \
    ln -s usr/sbin  "$root/sbin"; \
    ln -s usr/lib   "$root/lib"; \
    ln -s usr/lib64 "$root/lib64"; \
    ln -s /run    "$root/var/run"; \
    chmod 1777 "$root/tmp"

FROM scratch
COPY --from=bb /rootfs/ /
# /limes holds the rescue shell; host /usr/bin wins for everything else. The sbin dirs are
# on PATH because the sandbox runs as (mapped) uid 0, for whom admin tools like `ldconfig`
# are expected on PATH -- without them a bare `ldconfig` is simply not found, which is a
# different failure from the /sbin symlink above and had to be fixed alongside it.
ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/limes
CMD ["/limes/busybox", "sh"]
