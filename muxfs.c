#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "ds.h"
#include "muxfs.h"

static void
usage(void)
{
	dprintf(2, "usage: muxfs format [-a checksum_algorithm] "
	    "directory ...\n");
	dprintf(2, "       muxfs mount [-f] mount_point directory ...\n");
	dprintf(2, "       muxfs audit directory ...\n");
	dprintf(2, "       muxfs heal directory ...\n");
	dprintf(2, "       muxfs sync destination source ...\n");
	dprintf(2, "       muxfs version\n");
}

int
main(int argc, char *argv[])
{
	const char *cmd;

	if (muxfs_state_syslog_init())
		exit(-1);
	if (muxfs_dsinit())
		exit(-1);

	if (argc < 2) {
		usage();
		exit(-1);
	}
	cmd = argv[1];

	if (strcmp(cmd, "format") == 0)
		return muxfs_format_main(argc, argv);
	else if (strcmp(cmd, "mount") == 0)
		return muxfs_mount_main(argc, argv);
	else if (strcmp(cmd, "audit") == 0)
		return muxfs_scan_main(MUXFS_SCAN_AUDIT, argc, argv);
	else if (strcmp(cmd, "heal") == 0)
		return muxfs_scan_main(MUXFS_SCAN_HEAL, argc, argv);
	else if (strcmp(cmd, "sync") == 0)
		return muxfs_sync_main(argc, argv);
	else if (strcmp(cmd, "version") == 0) {
		muxfs_version_print();
		exit(0);
	}

	usage();
	exit(-1);
}
