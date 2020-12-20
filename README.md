# AES128
AES-128 implementation in C/POSIX, multi-threaded using &lt;pthread.h>. Still learning, looking for your feedbacks.

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
