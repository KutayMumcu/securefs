#define FUSE_USE_VERSION 31
#define BACKEND_DIR "/tmp/securefs_backend"
#include <fuse3/fuse.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <termios.h>

unsigned char aes_key[32];  // 256 bit key

#define KEY_SIZE 32  // 32 byte for AES-256
#define IV_SIZE 16   // AES block size

void get_backend_path(const char *path, char *fullpath) {
    snprintf(fullpath, 512, "%s%s.sec", BACKEND_DIR, path);
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext);
int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext);

static unsigned char key[KEY_SIZE] = "01234567890123456789012345678901";
static unsigned char iv[IV_SIZE] = "0123456789012345";

static const char *backing_file = "/tmp/securefs_storage.txt";

static int securefs_getattr(const char *path, struct stat *stbuf, struct fuse_file_info *fi) {
    memset(stbuf, 0, sizeof(struct stat));

    if (strcmp(path, "/") == 0) {
        stbuf->st_mode = S_IFDIR | 0755;
        stbuf->st_nlink = 2;
        return 0;
    }

    char fullpath[512];
    get_backend_path(path, fullpath);
    if (access(fullpath, F_OK) == -1)
        return -ENOENT;

    stbuf->st_mode = S_IFREG | 0644;
    stbuf->st_nlink = 1;
    stbuf->st_size = 1024;

    return 0;
}

static int securefs_open(const char *path, struct fuse_file_info *fi) {
    char fullpath[512];
    get_backend_path(path, fullpath);

    if (access(fullpath, F_OK) == -1)
        return -ENOENT;

    return 0;
}

static int securefs_read(const char *path, char *buf, size_t size, off_t offset,
    struct fuse_file_info *fi) {
    
    char fullpath[512];
    get_backend_path(path, fullpath);
    printf("Trying to open: %s\n", fullpath);

    FILE *fp = fopen(fullpath, "rb");
    if (!fp) return -ENOENT;

    unsigned char ciphertext[4096];
    int read_bytes = fread(ciphertext, 1, sizeof(ciphertext), fp);
    fclose(fp);

    unsigned char plaintext[4096];
    int decrypted_len = decrypt(ciphertext, read_bytes, plaintext);

    if (offset >= decrypted_len)
        return 0;

    size_t to_copy = (offset + size > decrypted_len) ? (decrypted_len - offset) : size;
    memcpy(buf, plaintext + offset, to_copy);
    return to_copy;
}

static int securefs_write(const char *path, const char *buf, size_t size,
    off_t offset, struct fuse_file_info *fi) {
    char fullpath[512];
    get_backend_path(path, fullpath);

    FILE *fp = fopen(fullpath, "wb");
    if (!fp)
        return -EIO;

    unsigned char ciphertext[4096];
    int ciphertext_len = encrypt((unsigned char*)buf, size, ciphertext);

    fwrite(ciphertext, 1, ciphertext_len, fp);
    fclose(fp);

    return size;
}

static int securefs_readdir(const char *path, void *buf, fuse_fill_dir_t filler,
    off_t offset, struct fuse_file_info *fi,
    enum fuse_readdir_flags flags) {
    DIR *dp;
    struct dirent *de;

    dp = opendir(BACKEND_DIR);
    if (dp == NULL)
        return -ENOENT;

    filler(buf, ".", NULL, 0, 0);
    filler(buf, "..", NULL, 0, 0);

    while ((de = readdir(dp)) != NULL) {
        if (strstr(de->d_name, ".sec")) {
            char name[256];
            strncpy(name, de->d_name, strlen(de->d_name) - 4);
            name[strlen(de->d_name) - 4] = '\0';
            filler(buf, name, NULL, 0, 0);
        }
    }

    closedir(dp);
    return 0;
}

static int securefs_create(const char *path, mode_t mode, struct fuse_file_info *fi) {
    char fullpath[512];
    get_backend_path(path, fullpath);

    FILE *fp = fopen(fullpath, "wb");
    if (!fp)
        return -EIO;
    fclose(fp);

    return 0;
}

static int securefs_unlink(const char *path) {
    char fullpath[512];
    get_backend_path(path, fullpath);
    return unlink(fullpath);
}

int encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *ciphertext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16] = "1234567890123456";

    int len, ciphertext_len;

    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv);
    EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len);
    ciphertext_len = len;

    EVP_EncryptFinal_ex(ctx, ciphertext + len, &len);
    ciphertext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return ciphertext_len;
}

int decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *plaintext) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    unsigned char iv[16] = "1234567890123456";

    int len, plaintext_len;

    EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, aes_key, iv);
    EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len);
    plaintext_len = len;

    EVP_DecryptFinal_ex(ctx, plaintext + len, &len);
    plaintext_len += len;

    EVP_CIPHER_CTX_free(ctx);
    return plaintext_len;
}

static struct fuse_operations securefs_oper = {
    .getattr = securefs_getattr,
    .readdir = securefs_readdir,
    .open = securefs_open,
    .read = securefs_read,
    .write = securefs_write,
    .create = securefs_create,
    .unlink = securefs_unlink,
};

void get_password_and_derive_key() {
    char password[128];
    printf("Enter your Password: ");
    fflush(stdout);

    struct termios oldt, newt;
    tcgetattr(STDIN_FILENO, &oldt);
    newt = oldt;
    newt.c_lflag &= ~ECHO;
    tcsetattr(STDIN_FILENO, TCSANOW, &newt);
    fgets(password, sizeof(password), stdin);
    tcsetattr(STDIN_FILENO, TCSANOW, &oldt);
    printf("\n");

    password[strcspn(password, "\n")] = 0;

    unsigned char salt[8] = "e0eb3621661ceddd"; //Salt is constant for this project
    if (!PKCS5_PBKDF2_HMAC(password, strlen(password), salt, sizeof(salt),
                           10000, EVP_sha256(), sizeof(aes_key), aes_key)) {
        fprintf(stderr, "PBKDF2 error\n");
        exit(1);
    }
}

int main(int argc, char *argv[]) {

    mkdir(BACKEND_DIR, 0700);

    if (argc != 2) {
        fprintf(stderr, "Usage: %s <mountpoint>\n", argv[0]);
        return 1;
    }

    get_password_and_derive_key();

    return fuse_main(argc, argv, &securefs_oper, NULL);
}