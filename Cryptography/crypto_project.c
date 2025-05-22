/**
 * Implementation of:
 *   - TEA (Tiny Encryption Algorithm) - Symmetric
 *   - ChaCha20 - Symmetric
 *   - RSA - Asymmetric
 * Modified to handle large files (including 4GB+) using streaming encryption
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

#define CHUNK_SIZE (1024 * 1024)  // 1MB chunks for streaming

// Function to get file size
size_t get_file_size(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (file == NULL) {
        return 0;
    }
    
    fseek(file, 0, SEEK_END);
    size_t size = ftell(file);
    fclose(file);
    
    return size;
}

// Function to print progress
void print_progress(size_t processed, size_t total) {
    if (total > 0) {
        double percent = (double)processed / total * 100.0;
        printf("\rProgress: %.1f%% (%zu / %zu bytes)", percent, processed, total);
        fflush(stdout);
    }
}

// Function to print a byte array as hex (limited for large data)
void print_hex(const char* label, const uint8_t* data, size_t len) {
    printf("%s: ", label);
    size_t print_len = (len < 32) ? len : 32;
    for (size_t i = 0; i < print_len; i++) {
        printf("%02x", data[i]);
    }
    if (len > 32) printf("... (showing first 32 bytes of %zu total)", len);
    printf("\n");
}

/* TEA (Tiny Encryption Algorithm) Implementation */

// TEA encryption function
void tea_encrypt(uint32_t v[2], const uint32_t key[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t sum = 0;
    uint32_t delta = 0x9E3779B9;
    
    for (int i = 0; i < 32; i++) {
        sum += delta;
        v0 += ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
        v1 += ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
    }
    
    v[0] = v0;
    v[1] = v1;
}

// TEA decryption function
void tea_decrypt(uint32_t v[2], const uint32_t key[4]) {
    uint32_t v0 = v[0], v1 = v[1];
    uint32_t delta = 0x9E3779B9;
    uint32_t sum = delta * 32;
    
    for (int i = 0; i < 32; i++) {
        v1 -= ((v0 << 4) + key[2]) ^ (v0 + sum) ^ ((v0 >> 5) + key[3]);
        v0 -= ((v1 << 4) + key[0]) ^ (v1 + sum) ^ ((v1 >> 5) + key[1]);
        sum -= delta;
    }
    
    v[0] = v0;
    v[1] = v1;
}

// Streaming TEA encryption
int tea_encrypt_file_stream(const char* input_filename, const char* output_filename, const uint32_t key[4]) {
    FILE* input = fopen(input_filename, "rb");
    FILE* output = fopen(output_filename, "wb");
    
    if (!input || !output) {
        printf("Error: Could not open files for TEA streaming encryption\n");
        if (input) fclose(input);
        if (output) fclose(output);
        return 0;
    }
    
    size_t total_size = get_file_size(input_filename);
    size_t total_processed = 0;
    uint8_t buffer[8];
    size_t bytes_read;
    
    printf("TEA encrypting file: %s (%zu bytes)\n", input_filename, total_size);
    
    while ((bytes_read = fread(buffer, 1, 8, input)) > 0) {
        // Pad the last block
        if (bytes_read < 8) {
            memset(buffer + bytes_read, 0, 8 - bytes_read);
        }
        
        // Encrypt the 8-byte block
        uint32_t block[2];
        memcpy(block, buffer, 8);
        tea_encrypt(block, key);
        
        // Write encrypted block
        fwrite(block, 1, 8, output);
        
        total_processed += bytes_read;
        
        // Show progress every MB
        if (total_processed % (1024 * 1024) == 0 || bytes_read < 8) {
            print_progress(total_processed, total_size);
        }
    }
    
    fclose(input);
    fclose(output);
    
    printf("\nTEA encryption completed: %zu bytes processed\n", total_processed);
    return 1;
}

// Streaming TEA decryption
int tea_decrypt_file_stream(const char* input_filename, const char* output_filename, const uint32_t key[4]) {
    FILE* input = fopen(input_filename, "rb");
    FILE* output = fopen(output_filename, "wb");
    
    if (!input || !output) {
        printf("Error: Could not open files for TEA streaming decryption\n");
        if (input) fclose(input);
        if (output) fclose(output);
        return 0;
    }
    
    size_t total_size = get_file_size(input_filename);
    size_t total_processed = 0;
    uint32_t block[2];
    
    printf("TEA decrypting file: %s (%zu bytes)\n", input_filename, total_size);
    
    while (fread(block, sizeof(uint32_t), 2, input) == 2) {
        // Decrypt the 8-byte block
        tea_decrypt(block, key);
        
        // Write decrypted block
        fwrite(block, 1, 8, output);
        
        total_processed += 8;
        
        // Show progress every MB
        if (total_processed % (1024 * 1024) == 0) {
            print_progress(total_processed, total_size);
        }
    }
    
    fclose(input);
    fclose(output);
    
    printf("\nTEA decryption completed: %zu bytes processed\n", total_processed);
    return 1;
}

/*  ChaCha20 Implementation  */

// ChaCha20 quarter round function
static inline void chacha20_quarter_round(uint32_t* a, uint32_t* b, uint32_t* c, uint32_t* d) {
    *a += *b; *d ^= *a; *d = (*d << 16) | (*d >> 16);
    *c += *d; *b ^= *c; *b = (*b << 12) | (*b >> 20);
    *a += *b; *d ^= *a; *d = (*d << 8) | (*d >> 24);
    *c += *d; *b ^= *c; *b = (*b << 7) | (*b >> 25);
}

// ChaCha20 block function
void chacha20_block(uint32_t* output, const uint32_t* input) {
    uint32_t x[16];
    int i;
    
    for (i = 0; i < 16; i++) {
        x[i] = input[i];
    }
    
    for (i = 0; i < 10; i++) {
        // Column rounds
        chacha20_quarter_round(&x[0], &x[4], &x[8], &x[12]);
        chacha20_quarter_round(&x[1], &x[5], &x[9], &x[13]);
        chacha20_quarter_round(&x[2], &x[6], &x[10], &x[14]);
        chacha20_quarter_round(&x[3], &x[7], &x[11], &x[15]);
        
        // Diagonal rounds
        chacha20_quarter_round(&x[0], &x[5], &x[10], &x[15]);
        chacha20_quarter_round(&x[1], &x[6], &x[11], &x[12]);
        chacha20_quarter_round(&x[2], &x[7], &x[8], &x[13]);
        chacha20_quarter_round(&x[3], &x[4], &x[9], &x[14]);
    }
    
    for (i = 0; i < 16; i++) {
        output[i] = x[i] + input[i];
    }
}

// Initialize ChaCha20 state
void chacha20_init(uint32_t state[16], const uint8_t key[32], const uint8_t nonce[12], uint32_t counter) {
    // Constants "expand 32-byte k"
    state[0] = 0x61707865;
    state[1] = 0x3320646e;
    state[2] = 0x79622d32;
    state[3] = 0x6b206574;
    
    // Key (8 words = 32 bytes)
    for (int i = 0; i < 8; i++) {
        state[4 + i] = ((uint32_t)key[4*i]) |
                       ((uint32_t)key[4*i+1] << 8) |
                       ((uint32_t)key[4*i+2] << 16) |
                       ((uint32_t)key[4*i+3] << 24);
    }
    
    // Counter (1 word = 4 bytes)
    state[12] = counter;
    
    // Nonce (3 words = 12 bytes)
    for (int i = 0; i < 3; i++) {
        state[13 + i] = ((uint32_t)nonce[4*i]) |
                        ((uint32_t)nonce[4*i+1] << 8) |
                        ((uint32_t)nonce[4*i+2] << 16) |
                        ((uint32_t)nonce[4*i+3] << 24);
    }
}

// Streaming ChaCha20 encryption/decryption
int chacha20_encrypt_file_stream(const char* input_filename, const char* output_filename,
                                const uint8_t key[32], const uint8_t nonce[12], uint32_t initial_counter) {
    FILE* input = fopen(input_filename, "rb");
    FILE* output = fopen(output_filename, "wb");
    
    if (!input || !output) {
        printf("Error: Could not open files for ChaCha20 streaming encryption\n");
        if (input) fclose(input);
        if (output) fclose(output);
        return 0;
    }
    
    size_t total_size = get_file_size(input_filename);
    size_t total_processed = 0;
    uint32_t counter = initial_counter;
    
    uint8_t* buffer = (uint8_t*)malloc(CHUNK_SIZE);
    if (!buffer) {
        printf("Error: Could not allocate buffer for ChaCha20 streaming\n");
        fclose(input);
        fclose(output);
        return 0;
    }
    
    printf("ChaCha20 encrypting file: %s (%zu bytes)\n", input_filename, total_size);
    
    size_t bytes_read;
    while ((bytes_read = fread(buffer, 1, CHUNK_SIZE, input)) > 0) {
        uint8_t* output_buffer = (uint8_t*)malloc(bytes_read);
        if (!output_buffer) {
            printf("Error: Could not allocate output buffer\n");
            free(buffer);
            fclose(input);
            fclose(output);
            return 0;
        }
        
        // Process the chunk
        for (size_t i = 0; i < bytes_read; i += 64) {
            uint32_t state[16];
            uint32_t block[16];
            uint8_t keystream[64];
            
            chacha20_init(state, key, nonce, counter);
            chacha20_block(block, state);
            
            // Convert block to bytes (little-endian)
            for (int j = 0; j < 16; j++) {
                keystream[4*j] = block[j] & 0xFF;
                keystream[4*j+1] = (block[j] >> 8) & 0xFF;
                keystream[4*j+2] = (block[j] >> 16) & 0xFF;
                keystream[4*j+3] = (block[j] >> 24) & 0xFF;
            }
            
            // XOR with input data
            size_t chunk_size = (i + 64 <= bytes_read) ? 64 : (bytes_read - i);
            for (size_t j = 0; j < chunk_size; j++) {
                output_buffer[i + j] = buffer[i + j] ^ keystream[j];
            }
            
            counter++;
        }
        
        fwrite(output_buffer, 1, bytes_read, output);
        free(output_buffer);
        
        total_processed += bytes_read;
        print_progress(total_processed, total_size);
    }
    
    free(buffer);
    fclose(input);
    fclose(output);
    
    printf("\nChaCha20 encryption completed: %zu bytes processed\n", total_processed);
    return 1;
}

/*  RSA Implementation  */

// Simple GCD function for RSA
uint64_t gcd(uint64_t a, uint64_t b) {
    uint64_t temp;
    while (b != 0) {
        temp = b;
        b = a % b;
        a = temp;
    }
    return a;
}

// Extended Euclidean Algorithm to find modular multiplicative inverse
int64_t mod_inverse(int64_t a, int64_t m) {
    int64_t m0 = m, t, q;
    int64_t x0 = 0, x1 = 1;
    
    if (m == 1) return 0;
    
    while (a > 1) {
        q = a / m;
        t = m;
        m = a % m;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    
    if (x1 < 0)
        x1 += m0;
    
    return x1;
}

// Fast modular exponentiation (a^b mod n)
uint64_t mod_pow(uint64_t base, uint64_t exponent, uint64_t modulus) {
    if (modulus == 1) return 0;
    
    uint64_t result = 1;
    base = base % modulus;
    
    while (exponent > 0) {
        if (exponent & 1)
            result = (result * base) % modulus;
        
        exponent >>= 1;
        base = (base * base) % modulus;
    }
    
    return result;
}

// Generate RSA key pair
void rsa_generate_keys(uint64_t* n, uint64_t* e, uint64_t* d, uint64_t p, uint64_t q) {
    *n = p * q;
    uint64_t phi = (p - 1) * (q - 1);
    
    *e = 65537;
    if (gcd(*e, phi) != 1) {
        for (*e = 3; *e < phi; (*e) += 2) {
            if (gcd(*e, phi) == 1)
                break;
        }
    }
    
    *d = mod_inverse(*e, phi);
}

// RSA encryption: c = m^e mod n
uint64_t rsa_encrypt(uint64_t message, uint64_t e, uint64_t n) {
    return mod_pow(message, e, n);
}

// RSA decryption: m = c^d mod n
uint64_t rsa_decrypt(uint64_t ciphertext, uint64_t d, uint64_t n) {
    return mod_pow(ciphertext, d, n);
}

// RSA Hybrid Encryption: Encrypt TEA key with RSA, then use TEA for file data
int rsa_hybrid_encrypt_file_stream(const char* input_filename, const char* key_filename, 
                                  const char* data_filename, uint64_t e, uint64_t n) {
    // Generate a random TEA key
    uint32_t tea_key[4];
    srand((unsigned int)time(NULL));
    for (int i = 0; i < 4; i++) {
        tea_key[i] = (uint32_t)rand() ^ ((uint32_t)rand() << 16);
    }
    
    printf("\nRSA Hybrid Encryption:\n");
    printf("Generated TEA key: %08x %08x %08x %08x\n", 
           tea_key[0], tea_key[1], tea_key[2], tea_key[3]);
    
    // Encrypt the TEA key with RSA
    uint64_t encrypted_key[4];
    for (int i = 0; i < 4; i++) {
        encrypted_key[i] = rsa_encrypt((uint64_t)tea_key[i], e, n);
    }
    
    // Save encrypted key to file
    FILE* key_file = fopen(key_filename, "wb");
    if (key_file) {
        fwrite(encrypted_key, sizeof(uint64_t), 4, key_file);
        fclose(key_file);
        printf("Encrypted key saved to: %s\n", key_filename);
    }
    
    // Encrypt the file data with TEA
    printf("Encrypting file data with TEA...\n");
    return tea_encrypt_file_stream(input_filename, data_filename, tea_key);
}

// RSA Hybrid Decryption
int rsa_hybrid_decrypt_file_stream(const char* key_filename, const char* data_filename,
                                  const char* output_filename, uint64_t d, uint64_t n) {
    // Read and decrypt the TEA key
    FILE* key_file = fopen(key_filename, "rb");
    if (!key_file) {
        printf("Error: Could not open key file %s\n", key_filename);
        return 0;
    }
    
    uint64_t encrypted_key[4];
    if (fread(encrypted_key, sizeof(uint64_t), 4, key_file) != 4) {
        printf("Error: Could not read encrypted key\n");
        fclose(key_file);
        return 0;
    }
    fclose(key_file);
    
    // Decrypt the TEA key with RSA
    uint32_t tea_key[4];
    for (int i = 0; i < 4; i++) {
        tea_key[i] = (uint32_t)rsa_decrypt(encrypted_key[i], d, n);
    }
    
    printf("\nRSA Hybrid Decryption:\n");
    printf("Decrypted TEA key: %08x %08x %08x %08x\n", 
           tea_key[0], tea_key[1], tea_key[2], tea_key[3]);
    
    // Decrypt the file data with TEA
    printf("Decrypting file data with TEA...\n");
    return tea_decrypt_file_stream(data_filename, output_filename, tea_key);
}

/* Main Function */

int main() {
    const char* input_file = "this.txt";
    
    // Check if input file exists
    size_t file_size = get_file_size(input_file);
    if (file_size == 0) {
        printf("Error: File '%s' not found or empty.\n", input_file);
        printf("Please create a file named 'this.txt' in the same directory.\n");
        return 1;
    }
    
    printf("=== Large File Encryption Demo ===\n");
    printf("Input file: %s\n", input_file);
    printf("File size: %zu bytes (%.2f MB, %.3f GB)\n\n", 
           file_size, (double)file_size / (1024*1024), (double)file_size / (1024*1024*1024));
    
    /* TEA Demo */
    printf("===== TEA (Tiny Encryption Algorithm) =====\n");
    uint32_t tea_key[4] = {0x01234567, 0x89ABCDEF, 0xFEDCBA98, 0x76543210};
    
    if (tea_encrypt_file_stream(input_file, "this_tea_encrypted.bin", tea_key)) {
        if (tea_decrypt_file_stream("this_tea_encrypted.bin", "this_tea_decrypted.txt", tea_key)) {
            printf("TEA encryption/decryption completed successfully!\n");
        }
    }
    printf("\n");
    
    /* ChaCha20 Demo */
    printf("===== ChaCha20 =====\n");
    uint8_t chacha_key[32] = {
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f
    };
    uint8_t chacha_nonce[12] = {
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x4a, 0x00, 0x00, 0x00, 0x00
    };
    
    if (chacha20_encrypt_file_stream(input_file, "this_chacha20_encrypted.bin", 
                                    chacha_key, chacha_nonce, 1)) {
        if (chacha20_encrypt_file_stream("this_chacha20_encrypted.bin", "this_chacha20_decrypted.txt",
                                        chacha_key, chacha_nonce, 1)) {
            printf("ChaCha20 encryption/decryption completed successfully!\n");
        }
    }
    printf("\n");
    
    /* RSA Hybrid Demo */
    printf("===== RSA Hybrid Encryption =====\n");
    uint64_t p = 1009, q = 1013;
    uint64_t n, e, d;
    
    rsa_generate_keys(&n, &e, &d, p, q);
    printf("RSA Keys - Public (n=%llu, e=%llu), Private (d=%llu)\n", n, e, d);
    
    if (rsa_hybrid_encrypt_file_stream(input_file, "this_rsa_key.bin", 
                                      "this_rsa_data.bin", e, n)) {
        if (rsa_hybrid_decrypt_file_stream("this_rsa_key.bin", "this_rsa_data.bin",
                                          "this_rsa_decrypted.txt", d, n)) {
            printf("RSA hybrid encryption/decryption completed successfully!\n");
        }
    }
    
    printf("\n=== Encryption Complete ===\n");
    printf("Check the generated files:\n");
    printf("- TEA: this_tea_encrypted.bin -> this_tea_decrypted.txt\n");
    printf("- ChaCha20: this_chacha20_encrypted.bin -> this_chacha20_decrypted.txt\n");
    printf("- RSA: this_rsa_key.bin + this_rsa_data.bin -> this_rsa_decrypted.txt\n");
    
    return 0;
}