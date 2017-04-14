# hdhrfs
HDHR FUSE File System

HDHomeRun Tuners capture live broadcast TV. This combination of FUSE filesystem driver and patchset for minidlna to permit indexing of live streams is useful for capturing or live streaming TV. No attempt was made to make this software robust to buffer overflow errors, etc, so use on an unprotected network at your own risk!

hdhrfs.c

Filesystem driver using FUSE. Requires libhdhomerun to build.

gcc -O3 -Wall -D_GNU_SOURCE -D_LARGEFILE_SOURCE -D_FILE_OFFSET_BITS=64 hdhrfs.c -o hdhrfs `pkg-config fuse --cflags --libs` -I. -L. -lhdhomerun


Live Minidlna Patches

Apply patcheset appropriate to your version of minidlna(d) source. Live streams must be in a video format compatible with live streaming (mp4 is a notable format not compatible). These patches also change the name from minidlnad to minidlna for compatibility reasons. Manually doing mv minidlnad.8 minidlna.8 is required for documentation to properly install.
