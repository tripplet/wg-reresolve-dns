pkgname=wg-reresolve-dns
pkgver=2.2.1
pkgrel=1
pkgdesc='Periodically re-resolve DNS of endpoints for Wireguard interfaces'
arch=('x86_64' 'armv7h' 'aarch64')
depends=()
makedepends=(rust)

build() {
  cargo build --release --locked
  strip ../target/release/wg-reresolve-dns
}

package()
{
  cd ${pkgdir}/../..
  install -Dm 755 "target/release/wg-reresolve-dns" -t "${pkgdir}/usr/bin"
  install -Dm 644 "wg-quick-reresolve-dns@.service" -t "${pkgdir}/usr/lib/systemd/system"
  install -Dm 644 "wg-networkd-reresolve-dns@.service" -t "${pkgdir}/usr/lib/systemd/system"
}
