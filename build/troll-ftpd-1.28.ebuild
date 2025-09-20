inherit eutils

DESCRIPTION="TrollTech FTP lightweight server"
SRC_URI="ftp://ftp.trolltech.com/freebies/ftpd/${P}.tar.gz"
HOMEPAGE="http://www.trolltech.com/download/freebies.html"

LICENSE="GPL-2"
KEYWORDS="x86"
SLOT="0"

RDEPEND="sys-apps/xinetd"

src_unpack() {
    unpack ${A}
    cd ${S}
    
    epatch ${FILESDIR}/troll-ftpd-1.28.imedia.patch
    epatch ${FILESDIR}/troll-ftpd-1.28.imedia-gcc4.patch
}

src_compile() {

    emake || die "make regular stuff"
    
}

src_install() {
    newsbin ftpd iftpd
    dosbin mkusers
    doman ftpd.8
    doman mkusers.8

    dodir /etc/ftpd
    dodir /etc/xinetd.d
    insinto /etc/xinetd.d
    doins ${FILESDIR}/ftpd
}

pkg_postinst() {

    # Create users/group db files for ls
    /usr/sbin/mkusers
    
    einfo "----------------------------------------------------------------------"
    einfo "Please run /usr/sbin/mkusers as root every you add/remove users/groups"
    einfo "----------------------------------------------------------------------"
    
}