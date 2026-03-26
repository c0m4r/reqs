#!/bin/bash

export RUSTFLAGS="--remap-path-prefix $HOME=/home/build"

cd $(dirname "$0")

VERSION=$(grep -m 1 '^version = ' Cargo.toml | cut -d '"' -f 2)
ARCH=$(uname -m)
case "$ARCH" in
    x86_64)  DEB_ARCH="amd64" ;;
    aarch64) DEB_ARCH="arm64" ;;
    *)       DEB_ARCH="$ARCH" ;;
esac

echo "*** building $VERSION for $ARCH"
cargo clippy --release
cargo build --release

echo "*** building DEB"

# Clean up before starting
rm -rf target/pkg
mkdir -p target/pkg/deb/reqs_${VERSION}_${DEB_ARCH}/usr/bin
mkdir -p target/pkg/deb/reqs_${VERSION}_${DEB_ARCH}/usr/share/man/man1
mkdir -p target/pkg/deb/reqs_${VERSION}_${DEB_ARCH}/usr/share/bash-completion/completions
mkdir -p target/pkg/deb/reqs_${VERSION}_${DEB_ARCH}/DEBIAN

# Copy files
cp target/release/reqs target/pkg/deb/reqs_${VERSION}_${DEB_ARCH}/usr/bin/
cp man/reqs.1 target/pkg/deb/reqs_${VERSION}_${DEB_ARCH}/usr/share/man/man1/
cp completions/reqs.bash target/pkg/deb/reqs_${VERSION}_${DEB_ARCH}/usr/share/bash-completion/completions/reqs

# DEB control file
cat <<EOF > target/pkg/deb/reqs_${VERSION}_${DEB_ARCH}/DEBIAN/control
Package: reqs
Version: $VERSION
Architecture: $DEB_ARCH
Maintainer: c0m4r
Description: Blazing-fast HTTP/HTTPS benchmarking tool
EOF

dpkg-deb --build target/pkg/deb/reqs_${VERSION}_${DEB_ARCH}
mv target/pkg/deb/reqs_${VERSION}_${DEB_ARCH}.deb .

echo "*** building RPM"

# RPM (using rpmbuild)
RPM_ROOT=$PWD/target/pkg/rpm
mkdir -p $RPM_ROOT/{BUILD,RPMS,SOURCES,SPECS,SRPMS}

cat <<EOF > $RPM_ROOT/SPECS/reqs.spec
Name:           reqs
Version:        $VERSION
Release:        1%{?dist}
Summary:        Blazing-fast HTTP/HTTPS benchmarking tool
License:        AGPL-3.0
URL:            https://github.com/c0m4r/reqs

%description
High-performance HTTP/HTTPS load testing tool.

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/bin
mkdir -p %{buildroot}/usr/share/man/man1
mkdir -p %{buildroot}/usr/share/bash-completion/completions
cp %{_sourcedir}/target/release/reqs %{buildroot}/usr/bin/
cp %{_sourcedir}/man/reqs.1 %{buildroot}/usr/share/man/man1/
cp %{_sourcedir}/completions/reqs.bash %{buildroot}/usr/share/bash-completion/completions/reqs

%files
/usr/bin/reqs
/usr/share/man/man1/reqs.1*
/usr/share/bash-completion/completions/reqs

%changelog
EOF

rpmbuild -bb \
    --define "_topdir $RPM_ROOT" \
    --define "_sourcedir $PWD" \
    --define "_buildhost localhost" \
    $RPM_ROOT/SPECS/reqs.spec
find target/pkg/rpm/RPMS -name "*.rpm" -exec mv {} . \;

echo "Artifacts generated: reqs_${VERSION}_${DEB_ARCH}.deb and reqs-${VERSION}-1.*.rpm"
