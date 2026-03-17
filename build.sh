#!/bin/bash
# XUE v1.0 — Build Script  by FIN
set -e

printf '\033[96m\033[1m  ██╗  ██╗██╗   ██╗███████╗\033[0m\n'
printf '\033[96m\033[1m  ╚██╗██╔╝██║   ██║██╔════╝\033[0m\n'
printf '\033[96m\033[1m   ╚███╔╝ ██║   ██║█████╗  \033[0m\n'
printf '\033[96m\033[1m   ██╔██╗ ██║   ██║██╔══╝  \033[0m\n'
printf '\033[96m\033[1m  ██╔╝ ██╗╚██████╔╝███████╗\033[0m\n'
printf '\033[96m\033[1m  ╚═╝  ╚═╝ ╚═════╝ ╚══════╝\033[0m\n'
printf '  \033[96m\033[1m雪  XUE v1.0 — Build Script\033[0m\n'
printf '  \033[93mby 0xWHITEROOM 「0xホワイトルーム」\033[0m\n\n'

# Check Go
if ! command -v go &>/dev/null; then
    printf '\033[91m[-]\033[0m Go not installed!\n\n'
    printf '    wget https://go.dev/dl/go1.21.6.linux-amd64.tar.gz\n'
    printf '    sudo tar -C /usr/local -xzf go1.21.6.linux-amd64.tar.gz\n'
    printf '    export PATH=\$PATH:/usr/local/go/bin\n'
    printf "    echo 'export PATH=\$PATH:/usr/local/go/bin' >> ~/.bashrc\n"
    exit 1
fi
printf '\033[92m[+]\033[0m Go: %s\n' "$(go version)"

# Tidy
printf '\033[96m[*]\033[0m go mod tidy...\n'
go mod tidy

# Build
printf '\033[96m[*]\033[0m Building xue...\n'
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    go build -ldflags="-s -w" -trimpath \
    -o xue ./cmd/xue/

[ -f xue ] || { printf '\033[91m[-]\033[0m Build failed!\n'; exit 1; }
SIZE=$(ls -lh xue | awk '{print $5}')
printf '\033[92m[+]\033[0m Binary: \033[1m%s\033[0m — %s\n' "$SIZE" "$(file xue | cut -d',' -f1-2)"

# .deb packaging
printf '\n\033[96m[*]\033[0m Packaging .deb...\n'

DEB="deb/xue"
rm -rf deb/
mkdir -p "${DEB}/DEBIAN"
mkdir -p "${DEB}/usr/local/bin"
mkdir -p "${DEB}/usr/share/doc/xue"

cp xue "${DEB}/usr/local/bin/xue"
chmod 755 "${DEB}/usr/local/bin/xue"

cat > "${DEB}/DEBIAN/control" << 'CTRL'
Package: xue
Version: 1.0.0
Architecture: amd64
Maintainer: FIN <fin@protonmail.com>
Description: XUE 雪 v1.0 — Subdomain Hunter
 Passive DNS: crt.sh, HackerTarget, AlienVault,
 RapidDNS, Anubis, ThreatCrowd.
 subfinder but deadlier. by FIN 「サイバー守護者」
Depends:
Priority: optional
Section: net
Installed-Size: 4096
CTRL

cat > "${DEB}/DEBIAN/postinst" << 'POST'
#!/bin/bash
printf '\n'
printf '╔═══════════════════════════════════════════════╗\n'
printf '║   雪 XUE v1.0 installed!                        ║\n'
printf '║   xue -d example.com -probe -takeover          ║\n'
printf '╚═══════════════════════════════════════════════╝\n'
printf '\n'
POST
chmod 755 "${DEB}/DEBIAN/postinst"

cat > "${DEB}/DEBIAN/prerm" << 'PRERM'
#!/bin/bash
printf 'Removing XUE...\n'
PRERM
chmod 755 "${DEB}/DEBIAN/prerm"

dpkg-deb --build "${DEB}" xue_1.0.0_amd64.deb
DEB_SIZE=$(ls -lh xue_1.0.0_amd64.deb | awk '{print $5}')
rm -rf deb/

printf '\n\033[92m\033[1m[+]\033[0m .deb: \033[1mxue_1.0.0_amd64.deb\033[0m (%s)\n' "$DEB_SIZE"
printf '\n\033[96m[*]\033[0m Install with:\n'
printf '    \033[1msudo dpkg -i xue_1.0.0_amd64.deb\033[0m\n'
printf '\n\033[96m[*]\033[0m Or move binary manually:\n'
printf '    \033[1msudo mv xue /usr/local/bin/\033[0m\n'
printf '\n\033[92m\033[1m  「雪の準備完了」 BUILD COMPLETE! 💀\033[0m\n\n'
