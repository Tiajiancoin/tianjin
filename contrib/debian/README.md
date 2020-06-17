
Debian
====================
This directory contains files used to package tiajiansd/tiajians-qt
for Debian-based Linux systems. If you compile tiajiansd/tiajians-qt yourself, there are some useful files here.

## tiajians: URI support ##


tiajians-qt.desktop  (Gnome / Open Desktop)
To install:

	sudo desktop-file-install tiajians-qt.desktop
	sudo update-desktop-database

If you build yourself, you will either need to modify the paths in
the .desktop file or copy or symlink your tiajians-qt binary to `/usr/bin`
and the `../../share/pixmaps/dash128.png` to `/usr/share/pixmaps`

tiajians-qt.protocol (KDE)

