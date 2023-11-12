pkgname=wg-reresolve-dns
pkgver=2.0.2
pkgrel=1
pkgdesc='Periodically re-resolve DNS of endpoints for Wireguard interfaces'
arch=('x86_64' 'armv7h' 'aarch64')
depends=()
makedepends=(rust)

build() {
  cargo +nightly build --release --locked
  strip ../target/release/wg-reresolve-dns
}

package()
{
  cd ${pkgdir}/../..
  install -Dm 755 "target/release/wg-reresolve-dns" -t "${pkgdir}/usr/bin"
  install -Dm 644 "wg-reresolve-dns@.service" -t "${pkgdir}/usr/lib/systemd/system"
}
