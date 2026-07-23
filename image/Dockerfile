# limes base image — near-scratch host-mirror skeleton.
#
# The container mounts the host's /usr read-only at runtime, so the image itself
# ships almost nothing: just the usr-merge symlinks (so /bin, /lib, /lib64 resolve
# into the mounted host /usr) and the mountpoint directories.
#
# `/limes` is limes' own namespace: an invented top-level name no host will ever
# mount, so nothing limes puts there can be shadowed by a host bind. That property is
# load-bearing -- it is why the rescue busybox (a static shell for when a mount is
# missing and you need to debug) and the ldconfig shim (below) both live here rather
# than under /usr or /opt, which a host mount could cover. Internal tools go in /limes;
# shims that must win over a host tool go in /limes/sbin, which is prepended to PATH.
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
        "$root/var" "$root/proc" "$root/sys" "$root/dev" "$root/limes/sbin"; \
    cp /bin/busybox "$root/limes/busybox"; \
    # ldconfig shim. Debian ships /usr/sbin/ldconfig as a wrapper that execs the hardcoded
    # /sbin/ldconfig.real; our /sbin -> usr/bin (required by --init, see below) makes that
    # target /usr/bin/ldconfig.real, which does not exist, so `ldconfig -p` -- and anything
    # that locates a library through it, like idapyswitch finding libpython -- fails. This
    # execs the real binary directly instead. Ordered so Debian's real binary wins where it
    # exists and Arch's plain /usr/bin/ldconfig is the fallback; /limes/sbin is prepended to
    # PATH so this beats the wrapper. It contains only this shim, so leading PATH with it
    # shadows nothing else. A no-op on hosts whose ldconfig already works.
    printf '%s\n' \
        '#!/bin/sh' \
        '# limes: bypass the Debian ldconfig wrapper, whose /sbin/ldconfig.real is' \
        '# unreachable given our /sbin -> usr/bin. Exec the real binary directly.' \
        'for real in /usr/sbin/ldconfig.real /usr/bin/ldconfig; do' \
        '    [ -x "$real" ] && exec "$real" "$@"' \
        'done' \
        'exec /usr/sbin/ldconfig "$@"' \
        > "$root/limes/sbin/ldconfig"; \
    chmod 0755 "$root/limes/sbin/ldconfig"; \
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
    # The cost falls on Debian's ldconfig, whose wrapper `exec`s the now-missing
    # /sbin/ldconfig.real -- handled by the /limes/sbin/ldconfig shim above rather than by
    # bending /sbin, which --init owns. Most other sbin tools are real binaries and work
    # once /usr/sbin is on PATH (below).
    ln -s usr/bin   "$root/bin"; \
    ln -s usr/bin   "$root/sbin"; \
    ln -s usr/lib   "$root/lib"; \
    ln -s usr/lib64 "$root/lib64"; \
    ln -s /run    "$root/var/run"; \
    chmod 1777 "$root/tmp"

FROM scratch
COPY --from=bb /rootfs/ /
# /limes/sbin (the ldconfig shim) leads so it beats the host wrapper; /limes (rescue shell)
# trails so host tools win over the busybox for every other name. The sbin dirs are on PATH
# because the sandbox runs as (mapped) uid 0, for whom admin tools like `ldconfig` and `ip`
# are expected on PATH -- without them a bare `ldconfig` is simply not found.
ENV PATH=/limes/sbin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin:/limes
CMD ["/limes/busybox", "sh"]
