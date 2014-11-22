#include "sx.h"
#include <openssl/x509_vfy.h>
#include "sx/tls-dh.c"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

DH *dh_512 = 0;
DH *dh_1024 = 0;
DH *dh_2048 = 0;
DH *dh_default_512 = 0;
DH *dh_default_1024 = 0;
DH *dh_default_2048 = 0;
time_t ts_dh_512 = 0;
time_t ts_dh_1024 = 0;
time_t ts_dh_2048 = 0;

void readget_dh512() {
    struct stat sb;
    FILE *file;

    if (!dh_default_512) dh_default_512 = get_dh512();
    if (!dh_512) dh_512 = dh_default_512;

    if (stat(CONFIG_DIR "/dh512.pem", &sb) == 0) {
        if (ts_dh_512 != sb.st_mtime) {
            /* timestamp has changed */
            file = fopen(CONFIG_DIR "/dh512.pem", "r");
            if (file) {
                if (dh_512 != dh_default_512) DH_free(dh_512);
                ts_dh_512 = sb.st_mtime;
                dh_512 = PEM_read_DHparams(file, 0, 0, 0);
                fclose(file);
            }
        }
    }

    return;
}

void readget_dh1024() {
    struct stat sb;
    FILE *file;

    if (!dh_default_1024) dh_default_1024 = get_dh1024();
    if (!dh_1024) dh_1024 = dh_default_1024;

    if (stat(CONFIG_DIR "/dh1024.pem", &sb) == 0) {
        if (ts_dh_1024 != sb.st_mtime) {
            /* timestamp has changed */
            file = fopen(CONFIG_DIR "/dh1024.pem", "r");
            if (file) {
                if (dh_1024 != dh_default_1024) DH_free(dh_1024);
                ts_dh_1024 = sb.st_mtime;
                dh_1024 = PEM_read_DHparams(file, 0, 0, 0);
                fclose(file);
            }
        }
    }

    return;
}

void readget_dh2048() {
    struct stat sb;
    FILE *file;

    if (!dh_default_2048) dh_default_2048 = get_dh2048();
    if (!dh_2048) dh_2048 = dh_default_2048;

    if (stat(CONFIG_DIR "/dh2048.pem", &sb) == 0) {
        if (ts_dh_2048 != sb.st_mtime) {
            /* timestamp has changed */
            file = fopen(CONFIG_DIR "/dh2048.pem", "r");
            if (file) {
                if (dh_2048 != dh_default_2048) DH_free(dh_2048);
                ts_dh_2048 = sb.st_mtime;
                dh_2048 = PEM_read_DHparams(file, 0, 0, 0);
                fclose(file);
            }
        }
    }

    return;
}


static DH *sx_ssl_tmp_dh_callback(SSL *ssl, int export, int keylength) {
    if (keylength == 512) {
        readget_dh512();
        return dh_512;
    } else {
        if (keylength == 1024) {
            readget_dh1024();
            return dh_1024;
        } else {
            if (keylength == 2048) {
                readget_dh2048();
                return dh_2048;
            }
        }
    }
    return 0;
}

