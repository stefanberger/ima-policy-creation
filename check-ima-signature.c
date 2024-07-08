#define _XOPEN_SOURCE 500

#include <getopt.h>
#include <stdio.h>
#include <sys/xattr.h>

#include <ftw.h>

#include <openssl/evp.h>

#include "glib.h"

#include "imaevm.h"

#define FLAG_VERBOSE			(1 << 0)
#define FLAG_REPORT_FAILED		(1 << 1)
#define FLAG_REMOVE_BAD_SIGNATURES	(1 << 2)

#define FILETYPE_EXECUTABLE		1
#define FILETYPE_LIBRARY		2
#define FILETYPE_OTHER			3

static struct ntfw_user_params {
    bool fatal_error;
    GRegex *library_regex;
    GThreadPool *pool;
    unsigned int filetype;
    struct public_key_entry *public_keys;
    const char *hash_algo;
    const char *signkey_file;
    const char *signkey_password;
    struct imaevm_ossl_access access_info;
    uint32_t keyid;
    unsigned int flags;
    unsigned int num_threads;

    /* for limiting number of requests in pool */
    GMutex mutex;
    GCond condition;
    unsigned int num_requests;
} ntfw_user_params;

struct pool_process_data {
    struct stat sb;
    char filepath[FILENAME_MAX];
};

/*
 * Thread pool function that checks file signatures and signs files
 */
static void pool_process(gpointer data, gpointer user_data __attribute__((unused)))
{
    unsigned char xattr[MAX_SIGNATURE_SIZE];
    unsigned char hash[MAX_DIGEST_SIZE];
    struct pool_process_data *ppd = data;
    int n, xattrlen, hashlen;
    bool signit = true;

    g_mutex_lock(&ntfw_user_params.mutex);
    /* have main thread produce more requests */
    if (--ntfw_user_params.num_requests == 2 * ntfw_user_params.num_threads)
        g_cond_signal(&ntfw_user_params.condition);
    g_mutex_unlock(&ntfw_user_params.mutex);

    xattrlen = lgetxattr(ppd->filepath, "security.ima",
                         xattr, sizeof(xattr));
    if (xattrlen > (int)sizeof(struct signature_v2_hdr)) {
        n = ima_verify_signature2(ntfw_user_params.public_keys,
                                  ppd->filepath,
                                  xattr, xattrlen,
                                  NULL, 0);
        if (n == 0) {
            signit = false;
        }
        if (signit && !ntfw_user_params.signkey_file &&
            (ntfw_user_params.flags & FLAG_REMOVE_BAD_SIGNATURES)) {
            /*
             * supposed to sign it but no signing key is available, so remove
             * the xattr with the bad signature if that's what the user wants
             */
            lremovexattr(ppd->filepath, "security.ima");
        }
    }

    if (signit) {
        if (ntfw_user_params.flags & FLAG_VERBOSE) {
            xattrlen = lgetxattr(ppd->filepath, "security.selinux",
                                 xattr, sizeof(xattr));
            if (xattrlen <= 0)
                xattrlen = 1;
            fprintf(stderr, "BAD: %s : %*s\n", ppd->filepath, xattrlen - 1, xattr);
        }

        if (ntfw_user_params.signkey_file) {
            hashlen = ima_calc_hash2(ppd->filepath,
                                     ntfw_user_params.hash_algo,
                                     hash);
            if (hashlen <= 1) {
                /* fatal error */
                fprintf(stderr, "Failed to calculate hash for %s\n", ppd->filepath);
                ntfw_user_params.fatal_error = true;
                goto out;
            }
            xattrlen = imaevm_signhash(ntfw_user_params.hash_algo,
                                       hash, hashlen,
                                       ntfw_user_params.signkey_file,
                                       ntfw_user_params.signkey_password,
                                       xattr + 1,
                                       0,
                                       &ntfw_user_params.access_info,
                                       ntfw_user_params.keyid);
            if (xattrlen <= 1) {
                /* fatal error */
                fprintf(stderr, "Failed to sign %s\n", ppd->filepath);
                ntfw_user_params.fatal_error = true;
                goto out;
            }
            xattr[0] = EVM_IMA_XATTR_DIGSIG;
            n = lsetxattr(ppd->filepath, "security.ima",
                          xattr, xattrlen + 1, 0);
            if (n < 0) {
                bool fatal = errno != EOPNOTSUPP;
                fprintf(stderr, "Failed to write xattr to %s: %s%s\n",
                        ppd->filepath, strerror(errno),
                        fatal ? " (fatal)" : " (non fatal)");
                if (fatal) {
                    ntfw_user_params.fatal_error = true;
                    goto out;
                }
            }
        } else {
            if ((ntfw_user_params.flags & FLAG_REPORT_FAILED)) {
                /* if there's no key just print the selinux label */
                xattrlen = lgetxattr(ppd->filepath, "security.selinux",
                                     xattr, sizeof(xattr));
                if (xattrlen >= 1)
                    printf("%*s\n", xattrlen - 1, xattr);
            }
        }
    }

out:
    g_free(ppd);
}

static int ntfw_process(const char *fpath, const struct stat *sb,
                        int tflag, struct FTW *ftwbuf __attribute__((unused)))
{
    struct pool_process_data *data;

    if (tflag == FTW_NS) {
        fprintf(stderr, "stat failed on %s\n", fpath);
        ntfw_user_params.fatal_error = true;
    }

    if (ntfw_user_params.fatal_error)
        return -1;

    /* skip everything else */
    if (tflag != FTW_F || !S_ISREG(sb->st_mode))
        return 0;

    /*
     * Skip directories where containers are store since we have special
     * rules for BPRM_CHECK and MMAP_CHECK in the main script.
     */
    switch (ntfw_user_params.filetype) {
    case FILETYPE_EXECUTABLE:
    case FILETYPE_LIBRARY:
        if (g_str_has_prefix(fpath, "/var/lib/containers/") ||
            g_str_has_prefix(fpath, "/var/lib/docker/"))
            return 0;
    }

    /* skip files not matching filetype */
    switch (ntfw_user_params.filetype) {
    case FILETYPE_EXECUTABLE:
        if ((sb->st_mode & 0111) == 0)
            return 0;
        break;
    case FILETYPE_LIBRARY:
        if ((sb->st_mode & 0111) == 0)
            return 0;
        if (!g_regex_match(ntfw_user_params.library_regex,
                           fpath, 0, NULL))
            return 0;
        //fprintf(stderr, "lib: %s\n", fpath);
        break;
    }

    data = g_malloc(sizeof(struct pool_process_data));
    data->sb = *sb;
    g_strlcpy(&data->filepath[0], fpath, sizeof(data->filepath));

    g_thread_pool_push(ntfw_user_params.pool, data, NULL);

    /* limit number of requests in queue */
    g_mutex_lock(&ntfw_user_params.mutex);
    if (++ntfw_user_params.num_requests == 4 * ntfw_user_params.num_threads)
        g_cond_wait(&ntfw_user_params.condition, &ntfw_user_params.mutex);
    g_mutex_unlock(&ntfw_user_params.mutex);

    return 0;
}

static const struct option opts[] =  {
     {"hashalgo", 1, 0, 'a'},
     {"filetype", 1, 0, 'f'},
     {"pass", 1, 0, 'p'},
     {"key", 1, 0, 'k'},
     {"remove-bad-signatures", 0, 0, 'r'},
     {"verbose", 0, 0, 'v'},
     {"dir", 1, 0, 'D'},
     {"report-failed", 0, 0, 'R'},
     {"signkey", 1, 0, 'S'},
     {"keyid", 1, 0, 144},
     {"keyid-from-cert", 1, 0, 145},
     {}
};

int main(int argc, char *argv[])
{
    unsigned long keyid;
    const char *keyfile = NULL;
    const char *filetype = NULL;
    const char *dir = NULL;
    int n, c, lind;
    EVP_MD *md;
    char *eptr;

    /* keep library quiet */
    imaevm_params.verbose = 0;

    ntfw_user_params.hash_algo = "sha256";

    while (1) {
        c = getopt_long(argc, argv, "a:f:p:k:S:D:vR", opts, &lind);
        if (c == -1)
            break;

        switch (c) {
        case 'a':
            ntfw_user_params.hash_algo = optarg;
            break;
        case 'f':
            filetype = optarg;
            break;
        case 'p':
            ntfw_user_params.signkey_password = optarg;
            break;
        case 'r':
            ntfw_user_params.flags |= FLAG_REMOVE_BAD_SIGNATURES;
            break;
        case 'k':
            keyfile = optarg;
            break;
        case 'v':
            ntfw_user_params.flags |= FLAG_VERBOSE;
            break;
        case 'D':
            dir = optarg;
            break;
        case 'R':
            ntfw_user_params.flags |= FLAG_REPORT_FAILED;
            break;
        case 'S':
            ntfw_user_params.signkey_file = optarg;
            break;
        case 144:
            errno = 0;
            keyid = strtoul(optarg, &eptr, 16);
            /*
             * ULONG_MAX is error from strtoul(3),
             * UINT_MAX is `imaevm_params.keyid' maximum value,
             * 0 is reserved for keyid being unset.
             */
            if (errno || (size_t)(eptr - optarg) != strlen(optarg) ||
                keyid == ULONG_MAX || keyid > UINT_MAX ||
                keyid == 0) {
                    fprintf(stderr, "Invalid keyid value.\n");
                    exit(1);
            }
            ntfw_user_params.keyid = keyid;
            break;
        case 145:
            ntfw_user_params.keyid = imaevm_read_keyid(optarg);
            if (ntfw_user_params.keyid == 0) {
                fprintf(stderr, "Error reading keyid.\n");
                exit(1);
            }
            break;
        }
    }

    md = EVP_MD_fetch(NULL, ntfw_user_params.hash_algo, NULL);
    if (!md) {
        fprintf(stderr, "Could not get access to hash '%s'.\n",
                ntfw_user_params.hash_algo);
        exit(1);
    }
    EVP_MD_free(md);

    if (!keyfile) {
        fprintf(stderr, "Missing --key option.\n");
        exit(1);
    }

    if (!dir) {
        fprintf(stderr, "Missing --dir option.\n");
        exit (1);
    }

    if (filetype == NULL || !strcmp(filetype, "other")) {
        ntfw_user_params.filetype = FILETYPE_OTHER;
    } else if (!strcmp(filetype, "library")) {
        ntfw_user_params.filetype = FILETYPE_LIBRARY;
        ntfw_user_params.library_regex = g_regex_new (".*\\.so.*", G_REGEX_DEFAULT,
                                                      G_REGEX_MATCH_DEFAULT, NULL);
    } else if (!strcmp(filetype, "executable")) {
        ntfw_user_params.filetype = FILETYPE_EXECUTABLE;
    } else {
        fprintf(stderr, "Unsupported filetype '%s'.\n", filetype);
        exit(1);
    }

    n = imaevm_init_public_keys(keyfile, &ntfw_user_params.public_keys);
    if (n < 0) {
         fprintf(stderr, "Failed loading public keys.\n");
         exit(1);
    }

    g_mutex_init(&ntfw_user_params.mutex);
    g_cond_init(&ntfw_user_params.condition);

    ntfw_user_params.num_threads = g_get_num_processors() * 2;

    ntfw_user_params.pool = g_thread_pool_new(pool_process,
                                              NULL,
                                              ntfw_user_params.num_threads,
                                              FALSE,
                                              NULL);

    nftw(dir, ntfw_process, 200, FTW_PHYS);

    g_thread_pool_free(ntfw_user_params.pool, FALSE, TRUE);

    imaevm_free_public_keys(ntfw_user_params.public_keys);

    return ntfw_user_params.fatal_error;
}
