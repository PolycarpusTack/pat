#!/bin/bash
# Pat Fortress - Distribution Package Creator
# Creates platform-specific packages (deb, rpm, pkg, msi, etc.)

set -e

VERSION=${VERSION:-"2.0.0"}
BUILD_DIR="build"
PACKAGE_DIR="packages"
BINARY_NAME="pat-fortress"

echo "📦 Creating distribution packages for Pat Fortress v${VERSION}"

# Clean and create directories
rm -rf ${PACKAGE_DIR}
mkdir -p ${PACKAGE_DIR}

# Check if binaries exist
if [[ ! -d "${BUILD_DIR}" ]]; then
    echo "❌ Build directory not found. Run ./scripts/build.sh first"
    exit 1
fi

# Create Debian package
create_deb_package() {
    echo "🐧 Creating Debian package..."

    local deb_dir="${PACKAGE_DIR}/deb"
    mkdir -p ${deb_dir}/DEBIAN
    mkdir -p ${deb_dir}/usr/local/bin
    mkdir -p ${deb_dir}/etc/systemd/system
    mkdir -p ${deb_dir}/usr/share/doc/pat-fortress

    # Copy binary
    cp ${BUILD_DIR}/pat-fortress_${VERSION}_linux_amd64 ${deb_dir}/usr/local/bin/pat-fortress
    chmod +x ${deb_dir}/usr/local/bin/pat-fortress

    # Create control file
    cat > ${deb_dir}/DEBIAN/control << EOF
Package: pat-fortress
Version: ${VERSION}
Section: utils
Priority: optional
Architecture: amd64
Depends: libc6
Maintainer: Pat Fortress Team
Description: Email testing platform for developers
 Pat Fortress is a modern MailHog replacement for capturing and
 inspecting emails during development and testing.
 .
 This package provides the Pat Fortress email testing server.
EOF

    # Create systemd service
    cat > ${deb_dir}/etc/systemd/system/pat-fortress.service << EOF
[Unit]
Description=Pat Fortress Email Testing Server
After=network.target

[Service]
Type=simple
User=pat-fortress
Group=pat-fortress
ExecStart=/usr/local/bin/pat-fortress
Restart=always
RestartSec=5
Environment=PAT_SMTP_BIND_ADDR=0.0.0.0:1025
Environment=PAT_HTTP_BIND_ADDR=0.0.0.0:8025

[Install]
WantedBy=multi-user.target
EOF

    # Create postinst script
    cat > ${deb_dir}/DEBIAN/postinst << 'EOF'
#!/bin/bash
# Create user if it doesn't exist
if ! id "pat-fortress" &>/dev/null; then
    useradd --system --shell /bin/false --home-dir /nonexistent pat-fortress
fi

# Reload systemd
systemctl daemon-reload

echo "Pat Fortress installed successfully!"
echo "To start: sudo systemctl start pat-fortress"
echo "To enable on boot: sudo systemctl enable pat-fortress"
EOF

    chmod +x ${deb_dir}/DEBIAN/postinst

    # Create prerm script
    cat > ${deb_dir}/DEBIAN/prerm << 'EOF'
#!/bin/bash
# Stop service if running
systemctl stop pat-fortress 2>/dev/null || true
systemctl disable pat-fortress 2>/dev/null || true
EOF

    chmod +x ${deb_dir}/DEBIAN/prerm

    # Build package
    dpkg-deb --build ${deb_dir} ${PACKAGE_DIR}/pat-fortress_${VERSION}_amd64.deb
    echo "✅ Debian package created: pat-fortress_${VERSION}_amd64.deb"
}

# Create RPM package
create_rpm_package() {
    echo "🎩 Creating RPM package..."

    if ! command -v rpmbuild &> /dev/null; then
        echo "⚠️  rpmbuild not found, skipping RPM package"
        return
    fi

    local rpm_dir="${PACKAGE_DIR}/rpm"
    mkdir -p ${rpm_dir}/{BUILD,BUILDROOT,RPMS,SOURCES,SPECS,SRPMS}

    # Create spec file
    cat > ${rpm_dir}/SPECS/pat-fortress.spec << EOF
Name:           pat-fortress
Version:        ${VERSION}
Release:        1%{?dist}
Summary:        Email testing platform for developers

License:        MIT
URL:            https://github.com/pat-fortress/pat-fortress
Source0:        pat-fortress-${VERSION}.tar.gz

BuildArch:      x86_64
Requires:       systemd

%description
Pat Fortress is a modern MailHog replacement for capturing and
inspecting emails during development and testing.

%prep
%setup -q

%build
# Binary is pre-built

%install
rm -rf %{buildroot}
mkdir -p %{buildroot}/usr/local/bin
mkdir -p %{buildroot}/etc/systemd/system
cp pat-fortress %{buildroot}/usr/local/bin/
cp pat-fortress.service %{buildroot}/etc/systemd/system/

%files
/usr/local/bin/pat-fortress
/etc/systemd/system/pat-fortress.service

%post
systemctl daemon-reload

%preun
systemctl stop pat-fortress 2>/dev/null || true
systemctl disable pat-fortress 2>/dev/null || true

%changelog
* $(date '+%a %b %d %Y') Pat Fortress Team - ${VERSION}-1
- Initial RPM release
EOF

    # Create source archive
    local source_dir="${rpm_dir}/SOURCES/pat-fortress-${VERSION}"
    mkdir -p ${source_dir}
    cp ${BUILD_DIR}/pat-fortress_${VERSION}_linux_amd64 ${source_dir}/pat-fortress
    cp ${PACKAGE_DIR}/deb/etc/systemd/system/pat-fortress.service ${source_dir}/

    cd ${rpm_dir}/SOURCES
    tar czf pat-fortress-${VERSION}.tar.gz pat-fortress-${VERSION}/
    cd - > /dev/null

    # Build RPM
    rpmbuild --define "_topdir ${PWD}/${rpm_dir}" -ba ${rpm_dir}/SPECS/pat-fortress.spec
    cp ${rpm_dir}/RPMS/x86_64/*.rpm ${PACKAGE_DIR}/
    echo "✅ RPM package created"
}

# Create macOS package
create_macos_package() {
    echo "🍎 Creating macOS package..."

    if [[ "$(uname)" != "Darwin" ]]; then
        echo "⚠️  Not on macOS, skipping pkg creation"
        return
    fi

    local pkg_dir="${PACKAGE_DIR}/macos"
    local payload_dir="${pkg_dir}/payload"
    mkdir -p ${payload_dir}/usr/local/bin

    # Copy binary
    cp ${BUILD_DIR}/pat-fortress_${VERSION}_darwin_amd64 ${payload_dir}/usr/local/bin/pat-fortress
    chmod +x ${payload_dir}/usr/local/bin/pat-fortress

    # Create package
    pkgbuild --root ${payload_dir} \
             --identifier com.pat-fortress.pat-fortress \
             --version ${VERSION} \
             --install-location / \
             ${PACKAGE_DIR}/pat-fortress_${VERSION}_darwin_amd64.pkg

    echo "✅ macOS package created: pat-fortress_${VERSION}_darwin_amd64.pkg"
}

# Create Windows installer
create_windows_package() {
    echo "🪟 Creating Windows installer..."

    local win_dir="${PACKAGE_DIR}/windows"
    mkdir -p ${win_dir}

    # Create NSIS installer script
    cat > ${win_dir}/installer.nsi << EOF
!define PRODUCT_NAME "Pat Fortress"
!define PRODUCT_VERSION "${VERSION}"
!define PRODUCT_PUBLISHER "Pat Fortress Team"
!define PRODUCT_WEB_SITE "https://github.com/pat-fortress/pat-fortress"

SetCompressor lzma

!include "MUI2.nsh"

!define MUI_ABORTWARNING
!define MUI_ICON "icon.ico"

!insertmacro MUI_PAGE_WELCOME
!insertmacro MUI_PAGE_LICENSE "license.txt"
!insertmacro MUI_PAGE_DIRECTORY
!insertmacro MUI_PAGE_INSTFILES
!insertmacro MUI_PAGE_FINISH

!insertmacro MUI_UNPAGE_WELCOME
!insertmacro MUI_UNPAGE_CONFIRM
!insertmacro MUI_UNPAGE_INSTFILES

!insertmacro MUI_LANGUAGE "English"

Name "\${PRODUCT_NAME} \${PRODUCT_VERSION}"
OutFile "pat-fortress_\${PRODUCT_VERSION}_windows_amd64_installer.exe"
InstallDir "\$PROGRAMFILES64\\Pat Fortress"
RequestExecutionLevel admin

Section "MainSection" SEC01
  SetOutPath "\$INSTDIR"
  File "pat-fortress.exe"

  ; Add to PATH
  EnVar::SetHKLM
  EnVar::AddValue "PATH" "\$INSTDIR"

  ; Create uninstaller
  WriteUninstaller "\$INSTDIR\\uninstall.exe"

  ; Registry entries
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Pat Fortress" "DisplayName" "\${PRODUCT_NAME}"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Pat Fortress" "UninstallString" "\$INSTDIR\\uninstall.exe"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Pat Fortress" "DisplayVersion" "\${PRODUCT_VERSION}"
  WriteRegStr HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Pat Fortress" "Publisher" "\${PRODUCT_PUBLISHER}"
SectionEnd

Section "Uninstall"
  Delete "\$INSTDIR\\pat-fortress.exe"
  Delete "\$INSTDIR\\uninstall.exe"
  RMDir "\$INSTDIR"

  ; Remove from PATH
  EnVar::SetHKLM
  EnVar::DeleteValue "PATH" "\$INSTDIR"

  DeleteRegKey HKLM "Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\Pat Fortress"
SectionEnd
EOF

    # Copy Windows binary
    cp ${BUILD_DIR}/pat-fortress_${VERSION}_windows_amd64.exe ${win_dir}/pat-fortress.exe

    echo "✅ Windows installer script created (requires NSIS to build)"
}

# Create Homebrew formula
create_homebrew_formula() {
    echo "🍺 Creating Homebrew formula..."

    local formula_dir="${PACKAGE_DIR}/homebrew"
    mkdir -p ${formula_dir}

    # Calculate SHA256 for macOS binary
    local macos_sha256=""
    if [[ -f "${BUILD_DIR}/pat-fortress_${VERSION}_darwin_amd64" ]]; then
        macos_sha256=$(sha256sum "${BUILD_DIR}/pat-fortress_${VERSION}_darwin_amd64" | cut -d' ' -f1)
    fi

    cat > ${formula_dir}/pat-fortress.rb << EOF
class PatFortress < Formula
  desc "Email testing platform for developers"
  homepage "https://github.com/pat-fortress/pat-fortress"
  url "https://github.com/pat-fortress/pat-fortress/releases/download/v${VERSION}/pat-fortress_${VERSION}_darwin_amd64"
  sha256 "${macos_sha256}"
  license "MIT"

  def install
    bin.install "pat-fortress_${VERSION}_darwin_amd64" => "pat-fortress"
  end

  service do
    run [opt_bin/"pat-fortress"]
    keep_alive true
    log_path var/"log/pat-fortress.log"
    error_log_path var/"log/pat-fortress.log"
  end

  test do
    system "#{bin}/pat-fortress", "--version"
  end
end
EOF

    echo "✅ Homebrew formula created: pat-fortress.rb"
}

# Create Docker image
create_docker_package() {
    echo "🐳 Creating Docker image..."

    cat > ${PACKAGE_DIR}/Dockerfile << EOF
FROM alpine:latest

RUN apk --no-cache add ca-certificates tzdata

WORKDIR /root/

COPY pat-fortress_${VERSION}_linux_amd64 /usr/local/bin/pat-fortress
RUN chmod +x /usr/local/bin/pat-fortress

EXPOSE 1025 8025

HEALTHCHECK --interval=30s --timeout=3s --start-period=5s --retries=3 \\
  CMD /usr/local/bin/pat-fortress --version || exit 1

CMD ["/usr/local/bin/pat-fortress"]
EOF

    cp ${BUILD_DIR}/pat-fortress_${VERSION}_linux_amd64 ${PACKAGE_DIR}/

    echo "✅ Dockerfile created"
}

# Main execution
main() {
    echo "🏗️  Creating packages..."

    # Create all packages
    if command -v dpkg-deb &> /dev/null; then
        create_deb_package
    else
        echo "⚠️  dpkg-deb not found, skipping Debian package"
    fi

    create_rpm_package
    create_macos_package
    create_windows_package
    create_homebrew_formula
    create_docker_package

    echo ""
    echo "📋 Package Summary:"
    echo "=================="
    find ${PACKAGE_DIR} -type f -name "*.deb" -o -name "*.rpm" -o -name "*.pkg" -o -name "*.exe" -o -name "*.rb" | while read file; do
        echo "   $(basename "$file")"
    done

    echo ""
    echo "🎉 Package creation complete!"
    echo "📁 Packages are in the '${PACKAGE_DIR}' directory"
}

main "$@"