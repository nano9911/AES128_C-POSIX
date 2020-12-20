# AES128
AES-128 [ECB && CTR] Modes implementation in C/POSIX, multi-threaded using <pthread.h>.

Threads:

read : read state [16 Bytes] from file to buffer1. [Producer]

ecb_encrypt || ecb_decrypt || ctr_encrypt || ctr_decrypt : read state [16 Bytes] from buffer, operate on it, then move it to buffer2 [Producer & Consumer]

write: read state [16 Bytes] from buffer2, write it to the output file [Consumer]

Threads are oganised to work in parallel, producer consumer method, and synchronised using mutex lock.

Still learning, looking for your feedbacks.


-------------------------------------------------------------------------------------------------------

Usage:

To compile: gcc -pthread AES.c -o [output filename/path]

Command line Arguments:

argv[1] = "-ecb" [use ECB mode] || "-ctr" [use CTR mode]

argv[2] = "-e" [Encrypt argv[3]] || "-d" [Decrypt argv[3]]

argv[3] = input file name

argv[4] = "-k"

argv[5] = "r" [Generate Random Key] || key file name

If argv[1] = "-ctr" :
                      argv[6] = "-iv"
                      argv[7] = "r" [Generate random IV] || IV file name
