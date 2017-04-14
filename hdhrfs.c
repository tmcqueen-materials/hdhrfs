#define FUSE_USE_VERSION 26
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <fuse.h>
#include "hdhomerun.h"

#define RECV_SIZE (38*VIDEO_DATA_PACKET_SIZE) // current video data packet size is 188*7 = 1316 bytes, so this is 50008 bytes
#define IDEAL_READ_SIZE (RECV_SIZE)           // should be roughly the amount of output expected from TRANSCODE_EXEC_COMMAND for RECV_SIZE amount of input
#define IDEAL_PIPE_SIZE (2*RECV_SIZE)         // must be at least RECV_SIZE or IDEAL_READ_SIZE, whichever is bigger, right now 100016 bytes
#define BUFFER_SIZE (16*IDEAL_PIPE_SIZE)      // output buffer size for multiple readers, right now 1600256 bytes
#define MAX_READERS 256

#define FAKE_SIZE 314			      // size of file, as reported when asked our size
#define KILL_SIG SIGTERM                      // use the kindler, gentler kill to allow other end of pipes to be closed appropriately
#define KILL_WAIT 500000000                   // wait time for the kinder, gentler kill (in nanoseconds, right now 0.5 s)
#define FORCE_KILL_SIG SIGKILL                // harsh kill if nice one didn't do it

#define MAX_WAITS 60
#define TIME_PER_WAIT 500000      // MAX_WAITS*TIME_PER_WAIT is maximum time to wait for available tuner, in microseconds (30 s)
#define FREE_TUNER_DELAY 4        // in units of TIME_PER_WAIT, in case a new reader wants the same channel within some short time (2 s)

#define TIME_PER_RECV 20000	  // in microseconds (20 ms)
#define MAX_RECV_WAITS_NULL 5     // insert null packets and return if not enough data obtained from receiver in 100 ms
#define MAX_RECV_WAITS 500        // restart tuner if no data received for 10 seconds

//#define TRANSCODE_EXEC_COMMAND execl("/usr/bin/ffmpeg", "/usr/bin/ffmpeg", "-v", "0", "-i", "-", "-async", "1", "-ss", "00:00:02", "-threads", "1", "-acodec", "libfdk_aac", "-ac", "2", "-ar", "48000", "-ab", "128k", "-b:v", "10000k", "-vcodec", "libx264", "-preset", "ultrafast", /*"-x264opts", "\"sync-lookahead=0:rc-lookahead=10\"",*/ "-tune", "zerolatency", "-map", "0:0", "-map", "0:1", "-f", "mpegts", /*"matroska",*/ "-", (char *)0);
#define TRANSCODE_EXEC_COMMAND execl("/bin/cat", "/bin/cat", "-", (char *)0);

// NULL packet for return when no data from TRANSCODE_EXEC_COMMAND is available. This should be valid return data in the same format as the
// OUTPUT of TRANSCODE_EXEC_COMMAND. Right now, this is set to be a valid, null, MPEG2-TS transport stream packet
#define NULL_PACKET_SIZE 188      // in bytes
const unsigned char null_packet[NULL_PACKET_SIZE] = {
0x47, 0x1F, 0xFF, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00 };

#define TUNER_MASK(x) ((x) & 0xF) // 0 = no tuner, 1...15 tuner number
#define READER_MASK(x) (((x) & 0x7FFFFF0) >> 4) // 0 = no reader, 1... arbitrary reader number
#define HDHRFS_FH(tuner,reader) (((tuner)&0xF)+(((reader)&0x7FFFFF)<<4))

#define NUM_TUNERS 2
// IP address(s) of hdhr tuners
char *hdhr_tuner[NUM_TUNERS] = {
	"192.168.1.2",
	"192.168.1.2"
	};
int hdhr_tuner_num[NUM_TUNERS] = {
	0,
	1
	};

#define NUM_CHANNELS 14
// Define channel file names and tuner configurations for each;
// These are setup for the Baltimore, MD area in 2014
char *chnl_name[NUM_CHANNELS] = {
	"ABC.38.3.ts",
	"ABC-SD.38.4.ts",
	"CBS.13.1.ts",
	"CW.40.3.ts",
	"FOX.46.3.ts",
	"FOX-ThisTV.46.4.ts",
	"FOX-Country.46.5.ts",
	"MyNetwork.41.3.ts",
	"MyNetwork-Bounce.41.4.ts",
	"NBC.11.3.ts",
	"NBC-SD.11.4.ts",
	"PBS.29.1.ts",
	"PBS-2.29.2.ts",
	"PBS-V-me.29.3.ts"
	};
char *chnl_chnl[NUM_CHANNELS] = {
	"auto:38",
	"auto:38",
	"auto:13",
	"auto:40",
	"auto:46",
	"auto:46",
	"auto:46",
	"auto:41",
	"auto:41",
	"auto:11",
	"auto:11",
	"auto:29",
	"auto:29",
	"auto:29"
	};
char *chnl_prgm[NUM_CHANNELS] = {
	"3",
	"4",
	"1",
	"3",
	"3",
	"4",
	"5",
	"3",
	"4",
/* NBC */
	"3",
	"4",
/* PBS */
	"1",
	"2",
	"3"
	};

pthread_mutex_t hdhr_mutex[NUM_TUNERS]; // mutex protecting *all* of the items below
struct hdhomerun_device_t *hdhr[NUM_TUNERS];

uint8_t *hdhr_raw_buf[NUM_TUNERS];
int hdhr_raw_buf_pos[NUM_TUNERS];
int hdhr_raw_buf_maxpos[NUM_TUNERS];
uint8_t *hdhr_out_buf[NUM_TUNERS];
size_t hdhr_out_buf_start_offset[NUM_TUNERS];
int hdhr_out_buf_maxpos[NUM_TUNERS];
int hdhr_nWaits[NUM_TUNERS];

int hdhr_num_readers[NUM_TUNERS];
uint8_t hdhr_reader_used[NUM_TUNERS][MAX_READERS];
size_t hdhr_reader_offset[NUM_TUNERS][MAX_READERS];

uint8_t hdhr_first_data_returned[NUM_TUNERS];
pid_t hdhr_transcode_pid[NUM_TUNERS];
int hdhr_transcode_pipes[NUM_TUNERS][4];
int hdhr_cur_chnl[NUM_TUNERS];

// end of items protected by hdhr_mutex


// returns 0 on success, non-zero on error
// Caller MUST lock mutex as appropriate
// Caller MUST also allocate buffers and initialize position pointers as desired after this call
int startTuner(int tuner, int chnl) { // command to (re)start a tuner. Does not distrupt reader or memory buffer tuner variables
        sigset_t mask;

        /* setup channel and program */
        if (hdhomerun_device_set_tuner_channel(hdhr[tuner], chnl_chnl[chnl]) != 1) {
            fprintf(stderr, "Could not tune tuner=%i to channel=%s!\n", tuner, chnl_chnl[chnl]);
            return 1;
        }
        if (hdhomerun_device_set_tuner_program(hdhr[tuner], chnl_prgm[chnl]) != 1) {
            fprintf(stderr, "Could not tune tuner=%i to program=%s!\n", tuner, chnl_prgm[chnl]);
            return 2;
        }

        /* prepare to stream data */
        if (hdhomerun_device_stream_start(hdhr[tuner]) != 1) {
            fprintf(stderr, "Error starting stream from tuner=%i!\n", tuner);
            return 3;
        }

        /* At this point, setup pipes and fork off the transcode program.
         */
        if (pipe(&(hdhr_transcode_pipes[tuner][0])) != 0) {
            fprintf(stderr, "Error setting up pipes for tuner=%i!\n", tuner);
            return 4;
        }
        if (pipe(&(hdhr_transcode_pipes[tuner][2])) != 0) {
            fprintf(stderr, "Error setting up pipes for tuner=%i!\n", tuner);
            return 5;
        }
#ifdef F_SETPIPE_SZ
        (void)fcntl(hdhr_transcode_pipes[tuner][0],F_SETPIPE_SZ,IDEAL_PIPE_SIZE);
        (void)fcntl(hdhr_transcode_pipes[tuner][2],F_SETPIPE_SZ,IDEAL_PIPE_SIZE);
#else
#warning "F_SETPIPE_SZ not defined: may have suboptimal performance (was _GNU_SOURCE defined?)"
#endif

        // non-blocking IO on parent side
        if (fcntl(hdhr_transcode_pipes[tuner][1], F_SETFL, O_NONBLOCK) != 0 ||
            fcntl(hdhr_transcode_pipes[tuner][2], F_SETFL, O_NONBLOCK) != 0) {
            fprintf(stderr, "Could not make pipes non-blocking on parent side for tuner=%i!\n", tuner);
            return 6;
        }

        sigemptyset(&mask);
        sigaddset(&mask, SIGCHLD);
        sigprocmask(SIG_BLOCK, &mask, NULL);

        hdhr_transcode_pid[tuner] = fork();
        if (hdhr_transcode_pid[tuner] == 0) { // child process
            sigemptyset(&mask);
            sigaddset(&mask, SIGCHLD);
            sigprocmask(SIG_UNBLOCK, &mask, NULL);
            close(hdhr_transcode_pipes[tuner][1]); // write end of pipe from parent to child
            dup2(hdhr_transcode_pipes[tuner][0],STDIN_FILENO); // change stdin of child to read end of pipe
            close(hdhr_transcode_pipes[tuner][0]);
            close(hdhr_transcode_pipes[tuner][2]); // read end of pipe from child to parent
            dup2(hdhr_transcode_pipes[tuner][3],STDOUT_FILENO); // change stdout of child to write end of pipe
            close(hdhr_transcode_pipes[tuner][3]);
            TRANSCODE_EXEC_COMMAND;
            _exit(ENOSYS);
        } else if (hdhr_transcode_pid[tuner] < 0) { // fork failed
            fprintf(stderr, "Error forking transcoder for tuner=%i!\n", tuner);
            return 7;
        }

        // parent process
        sigemptyset(&mask);
        sigaddset(&mask, SIGPIPE);
        sigaddset(&mask, SIGCHLD);
        sigprocmask(SIG_BLOCK, &mask, NULL);
        close(hdhr_transcode_pipes[tuner][0]); hdhr_transcode_pipes[tuner][0] = 0; // read end of pipe from parent to child
        close(hdhr_transcode_pipes[tuner][3]); hdhr_transcode_pipes[tuner][3] = 0; // write end of pipe from child to parent

        // check pipe sizes
#ifdef F_GETPIPE_SZ
        if (fcntl(hdhr_transcode_pipes[tuner][1], F_GETPIPE_SZ) < RECV_SIZE || fcntl(hdhr_transcode_pipes[tuner][1], F_GETPIPE_SZ) < IDEAL_READ_SIZE ||
            fcntl(hdhr_transcode_pipes[tuner][2], F_GETPIPE_SZ) < RECV_SIZE || fcntl(hdhr_transcode_pipes[tuner][2], F_GETPIPE_SZ) < IDEAL_READ_SIZE) {
            fprintf(stderr, "Pipes are too small for tuner=%i!\n", tuner);
            return 8;
        }
#else
#warning "F_GETPIPE_SZ not defined: if pipe size is less than RECV_SIZE or IDEAL_READ_SIZE, program may fail to function (was _GNU_SOURCE defined?)"
#endif

	hdhr_nWaits[tuner] = 0;
	hdhr_first_data_returned[tuner] = 0;

	return 0;
}

void cleanupTunerConnection(int tuner) { // does *not* destroy tuner, only cleans up in case of error, etc. Calling process MUST lock mutex as appropriate
	int i;
        struct timespec timeout;
        sigset_t mask;
	pid_t pid_tmp;
	if (tuner < 0 || tuner >= NUM_TUNERS) return;

        if (hdhr[tuner] != NULL)
            hdhomerun_device_stream_stop(hdhr[tuner]);

	hdhr_nWaits[tuner] = 0;
	hdhr_first_data_returned[tuner] = 0;

	pid_tmp = hdhr_transcode_pid[tuner];
        if (pid_tmp > 0) {
            kill(pid_tmp, KILL_SIG);
            timeout.tv_sec = 0;
            timeout.tv_nsec = KILL_WAIT;
            (void)sigtimedwait(&mask, NULL, &timeout);
            if (waitpid(pid_tmp, NULL, WNOHANG) <= 0)
                kill(pid_tmp, FORCE_KILL_SIG); // we tried being polite
        }
        hdhr_transcode_pid[tuner] = 0;

	for (i = 0; i < 4; i++) {
	    if (hdhr_transcode_pipes[tuner][i] != 0)
		close(hdhr_transcode_pipes[tuner][i]);
	    hdhr_transcode_pipes[tuner][i] = 0;
	}

	return;
}

void cleanupTunerReadersMemory(int tuner) { // does *not* destroy tuner, only cleans up in case of error, etc. Calling process MUST lock mutex as appropriate
        int i;
        if (tuner < 0 || tuner >= NUM_TUNERS) return;

        if (hdhr_out_buf[tuner] != NULL) free(hdhr_out_buf[tuner]);
        hdhr_out_buf[tuner] = NULL;
        hdhr_out_buf_maxpos[tuner] = 0;
        hdhr_out_buf_start_offset[tuner] = 0;
        if (hdhr_raw_buf[tuner] != NULL) free(hdhr_raw_buf[tuner]);
        hdhr_raw_buf[tuner] = NULL;
        hdhr_raw_buf_pos[tuner] = 0;
        hdhr_raw_buf_maxpos[tuner] = 0;
        hdhr_num_readers[tuner] = 0;
        hdhr_cur_chnl[tuner] = -1;
        for (i = 0; i < MAX_READERS; i++) {
            hdhr_reader_used[tuner][i] = 0;
            hdhr_reader_offset[tuner][i] = 0;
        }

	return;
}

void cleanupTuner(int tuner) { // see notes about mutex locking above!
	cleanupTunerConnection(tuner);
	cleanupTunerReadersMemory(tuner);
	return;
}

void cleanupAndExit(int err) {
	int i;
        sigset_t mask;

        sigemptyset(&mask);
        sigaddset(&mask, SIGCHLD);

	for (i = 0; i < NUM_TUNERS; i++) {
	    cleanupTuner(i);
	    hdhomerun_device_destroy(hdhr[i]);
	    hdhr[i] = NULL;
	}

	exit(err);
}

/* fuse: getattr */
static int hdhrfs_getattr(const char *path, struct stat *stbuf)
{
	int res = -ENOENT, i = 0;

	memset(stbuf, 0, sizeof(struct stat));
	if (strcmp(path, "/") == 0) {
	    stbuf->st_mode = S_IFDIR | 0777;
	    stbuf->st_nlink = 2;
            stbuf->st_atime = time(NULL);
            stbuf->st_mtime = stbuf->st_atime;
            stbuf->st_ctime = stbuf->st_atime;
            stbuf->st_blksize = IDEAL_READ_SIZE;
	    stbuf->st_size = 6;
	    res = 0;
	} else if (strlen(path) > 1) {
	    for (i = 0; i < NUM_CHANNELS && res == -ENOENT; i++) {
		if (strcmp(path+1, chnl_name[i]) == 0) {
		    stbuf->st_mode = S_IFREG | 0444;
		    stbuf->st_nlink = 1;
		    stbuf->st_atime = time(NULL);
		    stbuf->st_mtime = stbuf->st_atime;
		    stbuf->st_ctime = stbuf->st_atime;
		    stbuf->st_blksize = IDEAL_READ_SIZE;
		    stbuf->st_size = FAKE_SIZE;
		    res = 0;
		}
	    }
	}

	return res;
}

/* fuse: readdir */
static int hdhrfs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
			 off_t offset, struct fuse_file_info *fi)
{
	(void) offset;
	(void) fi;
	int i = 0;

	if (strcmp(path, "/") != 0)
		return -ENOENT;

	filler(buf, ".", NULL, 0);
	filler(buf, "..", NULL, 0);
	for (i = 0; i < NUM_CHANNELS; i++)
	    filler(buf, chnl_name[i], NULL, 0);

	return 0;
}

/* fuse: open */
static int hdhrfs_open(const char *path, struct fuse_file_info *fi)
{
	int chnl = -1, i = 0, nWaits, tuner, reader = -1;

	for (i = 0; i < NUM_CHANNELS && strlen(path) > 1 && chnl == -1; i++)
	    if (strcmp(path+1, chnl_name[i]) == 0) chnl = i;

	if (chnl < 0)
		return -ENOENT;

	if ((fi->flags & 3) != O_RDONLY)
		return -EROFS;

	fi->direct_io = 1;
	fi->nonseekable = 1;
	fi->keep_cache = 0;

        /* find available tuner, or one that is tuned to the correct channel */
        for (nWaits = 0; nWaits < MAX_WAITS; nWaits++) {
	    /* correct channel tuner check first */
            for (tuner = 0; tuner < NUM_TUNERS; tuner++)
                if (pthread_mutex_lock(&(hdhr_mutex[tuner])) == 0) {
                    if (hdhr_cur_chnl[tuner] == chnl && hdhr_num_readers[tuner] < MAX_READERS && hdhr_transcode_pid[tuner] > 0) {
			// find reader number
			for (i = 0; i < MAX_READERS && reader < 0; i++) {
			    if (hdhr_reader_used[tuner][i] == 0) {
				reader = i;
			    }
			}
                        goto return_tuner; // tuner already running desired channel
                    } else {
                        pthread_mutex_unlock(&(hdhr_mutex[tuner]));
                    }
                }

	    /* available tuner check second */
            for (tuner = 0; tuner < NUM_TUNERS; tuner++)
                if (pthread_mutex_lock(&(hdhr_mutex[tuner])) == 0) {
		    if (hdhr_num_readers[tuner] == 0 && hdhr_cur_chnl[tuner] < 0 && hdhr_transcode_pid[tuner] == 0) {
			reader = 0;
                        goto program_tuner; // tuner acquired
		    } else {
			pthread_mutex_unlock(&(hdhr_mutex[tuner]));
		    }
		}

            usleep(TIME_PER_WAIT);
        }
        fprintf(stderr, "Could not find an available tuner!\n");
	return -EACCES;

program_tuner:
	if (startTuner(tuner, chnl) != 0) {
	    cleanupTuner(tuner);
            pthread_mutex_unlock(&(hdhr_mutex[tuner]));
            return -EACCES;
        }

	// allocate buffers
	hdhr_raw_buf[tuner] = malloc(BUFFER_SIZE*sizeof(uint8_t));
	hdhr_out_buf[tuner] = malloc(BUFFER_SIZE*sizeof(uint8_t));
	if (!hdhr_raw_buf[tuner] || !hdhr_out_buf[tuner]) {
            fprintf(stderr, "Error allocating buffers for tuner=%i!\n", tuner);
            cleanupTuner(tuner);
            pthread_mutex_unlock(&(hdhr_mutex[tuner]));
            return -EACCES;
        }
	hdhr_raw_buf_pos[tuner] = 0;
	hdhr_raw_buf_maxpos[tuner] = 0;
	hdhr_out_buf_maxpos[tuner] = 0;
	hdhr_out_buf_start_offset[tuner] = 0;
	hdhr_cur_chnl[tuner] = chnl;
        fprintf(stdout, "Channel %i streaming and transcoding from tuner %i.\n", chnl, tuner);

return_tuner:
        fprintf(stdout, "Added reader %i to channel %i streaming and transcoding from tuner %i.\n", reader, chnl, tuner);
	if (reader < 0) {
            fprintf(stderr, "Error in reader number = %i for tuner=%i!\n", reader, tuner);
            cleanupTuner(tuner);
            pthread_mutex_unlock(&(hdhr_mutex[tuner]));
            return -EACCES;
	}
        hdhr_reader_used[tuner][reader] = 1;
        hdhr_reader_offset[tuner][reader] = hdhr_out_buf_start_offset[tuner];
        hdhr_num_readers[tuner] += 1;
	fi->fh = HDHRFS_FH((tuner+1),(reader+1));
	pthread_mutex_unlock(&(hdhr_mutex[tuner]));

	return 0;
}

/* fuse: release (close) */
static int hdhrfs_release(const char *path, struct fuse_file_info *fi)
{
        int tuner, reader, i;
        if (TUNER_MASK(fi->fh) < 1 || TUNER_MASK(fi->fh) > NUM_TUNERS)
                return -ENOENT;
	if (READER_MASK(fi->fh) < 1 || READER_MASK(fi->fh) > MAX_READERS)
		return -ENOENT;
        tuner = TUNER_MASK(fi->fh) - 1;
	reader = READER_MASK(fi->fh) - 1;

        pthread_mutex_lock(&(hdhr_mutex[tuner]));

	if (hdhr_reader_used[tuner][reader] != 0) {
	    hdhr_reader_used[tuner][reader] = 0;
	    hdhr_reader_offset[tuner][reader] = 0;
	    hdhr_num_readers[tuner] -= 1;
	    fprintf(stdout, "Removing reader %i from tuner %i\n", reader, tuner);
	} else {
	    fprintf(stdout, "Reader %i already removed from tuner %i\n", reader, tuner);
	}

	pthread_mutex_unlock(&(hdhr_mutex[tuner]));
	usleep(TIME_PER_WAIT*FREE_TUNER_DELAY);
        pthread_mutex_lock(&(hdhr_mutex[tuner]));

	if (hdhr_num_readers[tuner] <= 0 && hdhr_cur_chnl[tuner] >= 0) {
	    fprintf(stdout, "No readers left on tuner %i, freeing.\n", tuner);
            cleanupTuner(tuner);

	    fprintf(stdout, "Closed tuner %i, states: (%i,%i,%i,%i,%lli,%i,%i,%i,%i,%i,%i)\n", tuner, hdhr_num_readers[tuner],
		hdhr_cur_chnl[tuner], hdhr_raw_buf_pos[tuner], hdhr_raw_buf_maxpos[tuner], hdhr_out_buf_start_offset[tuner],
		hdhr_out_buf_maxpos[tuner], hdhr_transcode_pid[tuner], hdhr_transcode_pipes[tuner][0], hdhr_transcode_pipes[tuner][1],
		hdhr_transcode_pipes[tuner][2], hdhr_transcode_pipes[tuner][3]);
	}

        pthread_mutex_unlock(&(hdhr_mutex[tuner]));

        return 0;
}

/* fuse: read */
static int hdhrfs_read(const char *path, char *buf, size_t size, off_t offset,
		      struct fuse_file_info *fi)
{
	size_t recvSize, packetSize, copy_offset;
	uint8_t *toWrite;
	int tuner = 0, reader = 0, didSomething = 0, counter = 0, chnl = 0;
	int lastWrite = 0;

        if (TUNER_MASK(fi->fh) < 1 || TUNER_MASK(fi->fh) > NUM_TUNERS)
                return -ENOENT;
        if (READER_MASK(fi->fh) < 1 || READER_MASK(fi->fh) > MAX_READERS)
                return -ENOENT;
        tuner = TUNER_MASK(fi->fh) - 1;
        reader = READER_MASK(fi->fh) - 1;

	if (!hdhr_reader_used[reader])
		return -ENOENT;
	if (size > BUFFER_SIZE)
		return -ENOENT;

restart_read:
	counter = 0;
        recvSize = 0;
        toWrite = NULL;
	didSomething = 1;
        while (hdhr_nWaits[tuner] < MAX_RECV_WAITS) {

	    didSomething = 0;

            pthread_mutex_lock(&(hdhr_mutex[tuner]));

	    if (hdhr_reader_offset[tuner][reader]+offset < hdhr_out_buf_start_offset[tuner]) {
		fprintf(stdout, "Warning: Reader %i on tuner %i tried to read at offset %lli+%lli, less than start of buffer at %lli\n",
			reader, tuner, hdhr_reader_offset[tuner][reader], offset, hdhr_out_buf_start_offset[tuner]);
		hdhr_reader_offset[tuner][reader] = hdhr_out_buf_start_offset[tuner] - offset;
	    }

	    copy_offset = hdhr_reader_offset[tuner][reader]+offset-hdhr_out_buf_start_offset[tuner];
	    if (copy_offset > BUFFER_SIZE) {
		fprintf(stdout, "Warning: Reader %i on tuner %i requested starting reading at offset %lli+%lli, outside current range starting at %lli\n",
			reader, tuner, hdhr_reader_offset[tuner][reader], offset, hdhr_out_buf_start_offset[tuner]);
		hdhr_out_buf_start_offset[tuner] = hdhr_reader_offset[tuner][reader]+offset;
		hdhr_out_buf_maxpos[tuner] = 0;
		copy_offset = 0;
	    }

	    if (copy_offset+size > BUFFER_SIZE) { // free up bits for new info
		recvSize = copy_offset+size - BUFFER_SIZE;
		if (hdhr_out_buf_maxpos[tuner]-recvSize > 0) {
		    memmove(hdhr_out_buf[tuner], hdhr_out_buf[tuner]+recvSize, hdhr_out_buf_maxpos[tuner]-recvSize);
		    hdhr_out_buf_maxpos[tuner] -= recvSize;
		} else  {
		    hdhr_out_buf_maxpos[tuner] = 0;
		}
		hdhr_out_buf_start_offset[tuner] += recvSize;
		copy_offset -= recvSize;
	    }

	    /* if available, send more data to transcode process */
	    if (hdhr_raw_buf_pos[tuner] < hdhr_raw_buf_maxpos[tuner]) {
		lastWrite = write(hdhr_transcode_pipes[tuner][1], hdhr_raw_buf[tuner]+hdhr_raw_buf_pos[tuner], hdhr_raw_buf_maxpos[tuner]-hdhr_raw_buf_pos[tuner]);
		if (lastWrite > 0) { hdhr_raw_buf_pos[tuner] += lastWrite; didSomething = 1; }
		else if (lastWrite < 0 && errno != EAGAIN) {
		    // Need to cleanup and restart tuner
		    fprintf(stderr, "Error %i on write to pipe\n", errno);
		    goto read_restart_tuner;
		}
	    }

	    /* shift input buffer bits if required */
	    if (hdhr_raw_buf_maxpos[tuner]+RECV_SIZE > BUFFER_SIZE && hdhr_raw_buf_pos[tuner] >= RECV_SIZE) {
		memmove(hdhr_raw_buf[tuner], hdhr_raw_buf[tuner]+hdhr_raw_buf_pos[tuner], hdhr_raw_buf_maxpos[tuner]-hdhr_raw_buf_pos[tuner]);
		hdhr_raw_buf_maxpos[tuner] -= hdhr_raw_buf_pos[tuner];
		hdhr_raw_buf_pos[tuner] = 0;
	    }

	    /* get more data from tuner, if needed */
	    if (hdhr_raw_buf_maxpos[tuner]+RECV_SIZE <= BUFFER_SIZE) {
                toWrite = hdhomerun_device_stream_recv(hdhr[tuner], RECV_SIZE, &recvSize);
                if (toWrite != NULL && recvSize > 0) {
		    memcpy(hdhr_raw_buf[tuner]+hdhr_raw_buf_maxpos[tuner], toWrite, recvSize);
		    hdhr_raw_buf_maxpos[tuner] += recvSize;
		    didSomething = 1;
	        }
	    }

	    /* get data from transcode process if needed */
	    if (copy_offset+size > hdhr_out_buf_maxpos[tuner] || hdhr_out_buf_maxpos[tuner] < BUFFER_SIZE/2) {
	        lastWrite = read(hdhr_transcode_pipes[tuner][2], hdhr_out_buf[tuner]+hdhr_out_buf_maxpos[tuner], (((BUFFER_SIZE-hdhr_out_buf_maxpos[tuner]) < IDEAL_READ_SIZE) ? (BUFFER_SIZE-hdhr_out_buf_maxpos[tuner]) : (IDEAL_READ_SIZE)));

	        if (lastWrite < 0 && errno != EAGAIN) {
                    fprintf(stderr, "Error %i on read from pipe\n", errno);
		    goto read_restart_tuner;
	        } else if (lastWrite > 0) {
		    hdhr_out_buf_maxpos[tuner] += lastWrite;
		    didSomething = 1;
	        } 

		if (copy_offset+size > hdhr_out_buf_maxpos[tuner] && counter > MAX_RECV_WAITS_NULL && hdhr_first_data_returned[tuner]) {
		    // pad with null packets to keep data flowing
		    packetSize = ((copy_offset+size-hdhr_out_buf_maxpos[tuner]+NULL_PACKET_SIZE-1)/NULL_PACKET_SIZE)*NULL_PACKET_SIZE;
                    if (hdhr_out_buf_maxpos[tuner]+packetSize > BUFFER_SIZE) { // free up bits for new info
                        packetSize = hdhr_out_buf_maxpos[tuner]+packetSize - BUFFER_SIZE;
                        if (hdhr_out_buf_maxpos[tuner]-packetSize > 0) {
                            memmove(hdhr_out_buf[tuner], hdhr_out_buf[tuner]+packetSize, hdhr_out_buf_maxpos[tuner]-packetSize);
                            hdhr_out_buf_maxpos[tuner] -= packetSize;
                        } else  {
                            hdhr_out_buf_maxpos[tuner] = 0;
                        }
                        hdhr_out_buf_start_offset[tuner] += packetSize;
                        copy_offset -= packetSize;
                    }
                    fprintf(stderr, "Inserting %lli of null packets at %lli,%lli,%i\n", packetSize, copy_offset, size, hdhr_out_buf_maxpos[tuner]);
		    while (copy_offset+size > hdhr_out_buf_maxpos[tuner]) {
			memcpy(hdhr_out_buf[tuner]+hdhr_out_buf_maxpos[tuner], null_packet, NULL_PACKET_SIZE);
			hdhr_out_buf_maxpos[tuner] += NULL_PACKET_SIZE;
		    }
		    // but this does not count as doing something for the nWaits
		}

	    }

	    /* update wait counter */
	    if (hdhr_nWaits[tuner] > 50) fprintf(stdout, "(%i,%i,%lli:%lli,%lli,%i): %i,%i,%lli,%i,%i\n", reader, tuner, offset, copy_offset, size, hdhr_nWaits[tuner], hdhr_raw_buf_pos[tuner], hdhr_raw_buf_maxpos[tuner], hdhr_out_buf_start_offset[tuner], hdhr_out_buf_maxpos[tuner], lastWrite);
            if (didSomething)
                hdhr_nWaits[tuner] = 0;
            else
                hdhr_nWaits[tuner] += 1;

	    if (hdhr_nWaits[tuner] > MAX_RECV_WAITS) goto read_restart_tuner;

            /* return data if we have it */
            if (copy_offset+size <= hdhr_out_buf_maxpos[tuner]) {
                memcpy(buf, hdhr_out_buf[tuner]+copy_offset, size);
		hdhr_first_data_returned[tuner] = 1;
                pthread_mutex_unlock(&(hdhr_mutex[tuner]));
                return size;
            }

            /* release mutex and sleep once if we do not */
            pthread_mutex_unlock(&(hdhr_mutex[tuner]));
	    usleep(TIME_PER_RECV);
            counter++;
        }

	/* restart tuner if required */
        pthread_mutex_lock(&(hdhr_mutex[tuner]));
read_restart_tuner:
	chnl = hdhr_cur_chnl[tuner];
	fprintf(stderr, "Restarting tuner %i...", tuner);
	cleanupTunerConnection(tuner);
	counter = 0;
        if (hdhr_first_data_returned[tuner] == 0) {
            fprintf(stdout, "MAX_RECV_WAITS exceeded and no data ever received, returning ETIMEDOUT for reader %i on tuner %i\n", reader, tuner);
            cleanupTuner(tuner);
            pthread_mutex_unlock(&(hdhr_mutex[tuner]));
            return -ETIMEDOUT;
        }
	while (startTuner(tuner, chnl) != 0 && counter < MAX_WAITS) {
	    cleanupTunerConnection(tuner);
	    fprintf(stderr, "Try %i restarting tuner %i...", counter, tuner);
	    counter++;
	    usleep(TIME_PER_WAIT);
	}
	if (counter >= MAX_WAITS) {
	    fprintf(stdout, "MAX_WAITS exceeded, returning ETIMEDOUT for reader %i on tuner %i\n", reader, tuner);
	    cleanupTuner(tuner);
            pthread_mutex_unlock(&(hdhr_mutex[tuner]));
	    return -ETIMEDOUT;
	}
        pthread_mutex_unlock(&(hdhr_mutex[tuner]));

	goto restart_read;
}

/* fuse functions */
static struct fuse_operations hdhrfs_oper = {
	.getattr	= hdhrfs_getattr,
	.readdir	= hdhrfs_readdir,
	.open		= hdhrfs_open,
	.read		= hdhrfs_read,
	.release	= hdhrfs_release,
};

int main(int argc, char *argv[]) {
	int i,j;

	setvbuf(stdout, NULL, _IONBF, 0);
	setvbuf(stderr, NULL, _IONBF, 0);

	/* initialize all common variables */
	for (i = 0; i < NUM_TUNERS; i++) {
		pthread_mutex_init(&(hdhr_mutex[i]), NULL);
		hdhr[i] = NULL;
		hdhr_raw_buf[i] = NULL;
		hdhr_raw_buf_pos[i] = 0;
		hdhr_raw_buf_maxpos[i] = 0;
		hdhr_out_buf[i] = NULL;
		hdhr_out_buf_start_offset[i] = 0;
		hdhr_out_buf_maxpos[i] = 0;

		hdhr_num_readers[i] = 0;
		for (j = 0; j < MAX_READERS; j++) {
		    hdhr_reader_used[i][j] = 0;
		    hdhr_reader_offset[i][j] = 0;
		}

		hdhr_transcode_pid[i] = 0;
		for (j = 0; j < 4; j++)
		    hdhr_transcode_pipes[i][j] = 0;
		hdhr_cur_chnl[i] = -1;
	}

	/* initialize HDHomeRun tuners */
	for (i = 0; i < NUM_TUNERS; i++) {
	    hdhr[i] = hdhomerun_device_create_from_str(hdhr_tuner[i], NULL);
	    if (!hdhr[i]) { fprintf(stderr, "Could not open HDHomeRun Tuner%i: %s!\n", i, hdhr_tuner[i]); cleanupAndExit(1); }
	    if (hdhomerun_device_set_tuner(hdhr[i], hdhr_tuner_num[i]) != 1) {
		fprintf(stderr, "Could not open HDHomeRun Tuner%i: %s (error on setting tuner=%i)\n", i, hdhr_tuner[i], hdhr_tuner_num[i]); cleanupAndExit(1); }
	}

	/* fuse_main */
	i = fuse_main(argc, argv, &hdhrfs_oper, NULL);

	/* Finish */
	cleanupAndExit(i);
	return 0; // never reach here
}
