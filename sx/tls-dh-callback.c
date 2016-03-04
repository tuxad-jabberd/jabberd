#include "sx.h"
#include <openssl/x509_vfy.h>
#include "sx/tls-dh.c"
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <time.h>

DH *dh_2048 = 0;
DH *dh_default_2048 = 0;
time_t ts_dh_2048 = 0;

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
    readget_dh2048();
    return dh_2048;
}

