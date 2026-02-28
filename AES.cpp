#include <iostream>
#include <vector>
#include <cstdint>

using namespace std;

// Round constants (Used in Key Expansion)
const uint8_t Rcon[11] = {
    0x00, 0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1b, 0x36
};

// GF(2^8) multiplication helpers
uint8_t mul2(uint8_t x) {
    return (x << 1) ^ (((x >> 7) & 1) * 0x1b);
}

uint8_t mul3(uint8_t x) {
    return mul2(x) ^ x;
}

// ---------------------------------------------------------
//secure S-box implementation without lookup tables
// ---------------------------------------------------------
uint8_t gf_inverse(uint8_t a) {
    //Calculate multiplicative inverse in GF(2^8) using exponentiation by squaring
    uint8_t p = a;
    for (int i = 0; i < 6; i++) p = (p * p) ^ a;
    return p * p;
}

void subBytesSecure(uint8_t state[16]) {
    for (int i = 0; i < 16; i++) {
        uint8_t x = state[i];
        
        // 1. calculera multiplicativ invers i GF(2^8)
        uint8_t inv = (x == 0) ? 0 : gf_inverse(x);
        
        // 2. applice affine transformation
        uint8_t b = inv;
        b = (b << 1) | (b >> 7);
        b ^= inv;
        b = (b << 1) | (b >> 7);
        b ^= inv;
        b = (b << 1) | (b >> 7);
        b ^= inv;
        b = (b << 1) | (b >> 7);
        b ^= inv;
        b ^= 0x63;
        
        state[i] = b;
    }
}

// Key expansion
void keyExpansion(const uint8_t* key, uint8_t roundKeys[176]) {
    for (int i = 0; i < 16; i++) {
        roundKeys[i] = key[i];
    }
    
    for (int i = 4; i < 44; i++) {
        uint8_t temp[4];
        for (int j = 0; j < 4; j++) {
            temp[j] = roundKeys[(i-1)*4 + j];
        }
        
        if (i % 4 == 0) {
            // RotWord
            uint8_t t = temp[0];
            temp[0] = temp[1];
            temp[1] = temp[2];
            temp[2] = temp[3];
            temp[3] = t;
            
            // SubWord 
            for (int j = 0; j < 4; j++) {
                uint8_t inv = (temp[j] == 0) ? 0 : gf_inverse(temp[j]);
                uint8_t b = inv;
                b = (b << 1) | (b >> 7); b ^= inv;
                b = (b << 1) | (b >> 7); b ^= inv;
                b = (b << 1) | (b >> 7); b ^= inv;
                b = (b << 1) | (b >> 7); b ^= inv;
                b ^= 0x63;
                temp[j] = b;
            }
            
            // XOR with Rcon
            temp[0] ^= Rcon[i/4];
        }
        
        for (int j = 0; j < 4; j++) {
            roundKeys[i*4 + j] = roundKeys[(i-4)*4 + j] ^ temp[j];
        }
    }
}

// ShiftRows
void shiftRows(uint8_t state[16]) {
    uint8_t temp[16];
    for (int i = 0; i < 16; i++) temp[i] = state[i]; 
    
    state[1] = temp[5];
    state[5] = temp[9];
    state[9] = temp[13];
    state[13] = temp[1];
    
    state[2] = temp[10];
    state[6] = temp[14];
    state[10] = temp[2];
    state[14] = temp[6];
    
    state[3] = temp[15];
    state[7] = temp[3];
    state[11] = temp[7];
    state[15] = temp[11];
}

// MixColumns
void mixColumns(uint8_t state[16]) { 
    uint8_t temp[16];
    for (int i = 0; i < 16; i++) temp[i] = state[i];
    
    for (int c = 0; c < 4; c++) { 
        state[c*4 + 0] = mul2(temp[c*4 + 0]) ^ mul3(temp[c*4 + 1]) ^ temp[c*4 + 2] ^ temp[c*4 + 3];
        state[c*4 + 1] = temp[c*4 + 0] ^ mul2(temp[c*4 + 1]) ^ mul3(temp[c*4 + 2]) ^ temp[c*4 + 3];
        state[c*4 + 2] = temp[c*4 + 0] ^ temp[c*4 + 1] ^ mul2(temp[c*4 + 2]) ^ mul3(temp[c*4 + 3]);
        state[c*4 + 3] = mul3(temp[c*4 + 0]) ^ temp[c*4 + 1] ^ temp[c*4 + 2] ^ mul2(temp[c*4 + 3]);
    }
}

// AddRoundKey
void addRoundKey(uint8_t state[16], const uint8_t* roundKey) { 
    for (int i = 0; i < 16; i++) {
        state[i] ^= roundKey[i];
    }
}

// AES encryption
void aesEncrypt(const uint8_t* input, const uint8_t* key, uint8_t* output) {
    uint8_t state[16];
    uint8_t roundKeys[176];
    
    for (int i = 0; i < 16; i++) {
        state[i] = input[i];
    }
    
    keyExpansion(key, roundKeys);
    
    addRoundKey(state, roundKeys);
    
    for (int round = 1; round < 10; round++) {
        subBytesSecure(state); 
        shiftRows(state);
        mixColumns(state);
        addRoundKey(state, roundKeys + round * 16); 
    }
    
    subBytesSecure(state); 
    shiftRows(state);
    addRoundKey(state, roundKeys + 160);
    
    for (int i = 0; i < 16; i++) {
        output[i] = state[i];
    }
}

int main() {
    uint8_t key[16] = {0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c};
    uint8_t block[16] = {0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d, 0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34};
    uint8_t output[16];
    
    cout << "Encrypting..." << endl;
    aesEncrypt(block, key, output);
    
    cout << "Result (hex): ";
    for (int i = 0; i < 16; i++) {
        printf("%02x ", output[i]);
    }
    cout << endl;
    
    return 0;
}