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
        "$root/usr/bin" "$root/usr/sbin" "$root/usr/lib" \
        "$root/usr/local/bin" "$root/usr/local/sbin" \
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
    # /sbin points at usr/bin, not usr/sbin, and this is load-bearing for `--init`.
    # `docker run --init` bind-mounts the host's docker-init onto /sbin/docker-init, and
    # since the host /usr is mounted read-only, that only lands if the path resolves to a
    # file that already exists on the host. The host's docker-init lives at
    # /usr/bin/docker-init, so /sbin must resolve there -- usr/bin does (directly, and on
    # Arch via /usr/sbin -> bin), usr/sbin does not on Debian, where it is a real directory
    # without docker-init. Point /sbin at usr/sbin and no sandbox starts at all:
    #   stat /sbin/docker-init: no such file or directory
    # The cost falls on Debian's ldconfig, which is a wrapper that `exec`s the hardcoded
    # /sbin/ldconfig.real -- now /usr/bin/ldconfig.real, which does not exist. Most sbin
    # tools are real binaries and work fine once /usr/sbin is on PATH (below); ldconfig is
    # the exception, and bending /sbin to fix it would break --init, so it is left alone.
    ln -s usr/bin   "$root/bin"; \
    ln -s usr/bin   "$root/sbin"; \
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
