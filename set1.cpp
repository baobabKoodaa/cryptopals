#include <iostream>
#include <iomanip>
#include <string>
#include <vector>
#include "set1.h"
#include <algorithm>
#include <tuple>
#include <sstream>
#include <string>
#include <fstream>
#include <cstring>
#include <unordered_map>

using std::cout;
using std::string;
using std::vector;

int hex_char_to_int(char input) {
    // https://stackoverflow.com/a/17261928/4490400
    if(input >= '0' && input <= '9')
        return input - '0';
    if(input >= 'A' && input <= 'F')
        return input - 'A' + 10;
    if(input >= 'a' && input <= 'f')
        return input - 'a' + 10;
    throw std::invalid_argument("Invalid input string");
}

vector<unsigned char> hex_to_bytes(string hex) {
    vector<unsigned char> bytes = {};
    int n = hex.size();
    if (n%2 != 0) {
        throw std::invalid_argument("Hex string length not divisible by 2 - should it be padded by zeros to the left?");
    }
    for (int i=0; i<n; i+=2) {
        unsigned char byte = (hex_char_to_int(hex[i])*16 + hex_char_to_int(hex[i+1]));
        //cout << hex[i] << hex[i+1] << " " << (int)byte << std::endl;
        bytes.push_back(byte);
    }
    return bytes;
}

vector<unsigned char> str_to_bytes(string str) {
    vector<unsigned char> bytes = {};
    for (int i=0; i<str.size(); i++) bytes.push_back(str[i]);
    return bytes;
}

char nibble_to_hex_char(int v) {
    if (v <= 9) return '0'+v;
    if (v <= 15) return 'a'+v-10;
    throw std::invalid_argument("Invalid input to nibble_to_hex_char, v=" + std::to_string(v));
}

string byte_to_hex(int v) {
    int a = (v & 240) >> 4;
    int b = (v & 15);
    string s = "";
    s += nibble_to_hex_char(a);
    s += nibble_to_hex_char(b);
    return s;
}

string bytes_to_hex(vector<unsigned char> bytes) {
    string s = "";
    for (int i=0; i<bytes.size(); i++) s += byte_to_hex(bytes[i]);
    return s;
}

char int_to_b64_char(int v) {
    if (v <= 25) return 'A'+v;
    if (v <= 51) return 'a'+v-26;
    if (v <= 61) return '0'+v-52;
    if (v == 62) return '+';
    if (v == 63) return '/';
    throw std::invalid_argument("More than 6 bits given to int_to_b64_char!");
}

int b64_char_to_int(unsigned char c) {
    if (c == '=') return -1; // padding
    if (c == '/') return 63;
    if (c == '+') return 62;
    if (c >= 'A' && c <= 'Z') return c-'A';
    if (c >= 'a' && c <= 'z') return c-'a'+26;
    if (c >= '0' && c <= '9') return c-'0'+52;
    throw std::invalid_argument("Invalid char given to b64_char_to_int");
}

vector<unsigned char> bytes_to_base64(vector<unsigned char> bytes) {
    vector<unsigned char> str = {};
    long bits = 8*bytes.size();
    for (long i=0; i<bits; i+=6) {
        int start_byte = bytes[i/8];
        int index_for_start_bit = i%8;
        int v = start_byte;
        if (index_for_start_bit == 0) v = (v >> 2);
        if (index_for_start_bit == 1) v = ((v&127) >> 1);
        if (index_for_start_bit == 2) v = (v&63);
        if (index_for_start_bit == 3) v = ((v&31) << 1);
        if (index_for_start_bit == 4) v = ((v&15) << 2);
        if (index_for_start_bit == 5) v = ((v&7) << 3);
        if (index_for_start_bit == 6) v = ((v&3) << 4);
        if (index_for_start_bit == 7) v = ((v&1) << 5);

        if (index_for_start_bit >= 3) {
            // need some bits from the next byte as well
            if (i+6 < bits) {
                int end_byte = bytes[i/8+1];
                if (index_for_start_bit == 3) v ^= ((end_byte&128) >> 7);
                if (index_for_start_bit == 4) v ^= ((end_byte&192) >> 6);
                if (index_for_start_bit == 5) v ^= ((end_byte&224) >> 5);
                if (index_for_start_bit == 6) v ^= ((end_byte&240) >> 4);
                if (index_for_start_bit == 7) v ^= ((end_byte&248) >> 3);
            } // else no more bytes available, it is as if we had padded with zeros to the right

        }
        //cout << v << int_to_b64_char(v) << std::endl;
        str.push_back(int_to_b64_char(v));
    }
    // padding in case bytes size not divisible by 3
    if (bytes.size() % 3 >= 1) str.push_back('=');
    if (bytes.size() % 3 == 1) str.push_back('=');
    return str;
}

vector<unsigned char> base64_to_bytes(vector<unsigned char> b64) {
    vector<unsigned char> bytes = {};
    long bits = 6*b64.size();
    for (long i=0; i<bits; i+=8) {
        unsigned char first_char = b64[i/6];
        unsigned char second_char = b64[i/6+1];
        if (second_char == '=') break; // padding
        int first = b64_char_to_int(first_char);
        int second = b64_char_to_int(second_char);
        int index_for_start_bit = i%6;
        int v = first;
        if (index_for_start_bit == 0) {
            v <<= 2;
            v ^= (second >> 4);
        }
        if (index_for_start_bit == 2) {
            v <<= 4;
            v ^= (second >> 2);
        }
        if (index_for_start_bit == 4) {
            v <<= 6;
            v ^= second;
        }
        bytes.push_back(v);
    }
    return bytes;
}

vector<unsigned char> repeating_key_xor(vector<unsigned char> input, vector<unsigned char> key) {
    vector<unsigned char> output = {};
    int j=0;
    for (int i=0; i<input.size(); i++) {
        output.push_back(input[i] ^ key[j]);
        j += 1;
        j %= key.size();
    }
    return output;
}

string repeating_key_xor(string input, string key) {
    vector<unsigned char> input_vec(input.begin(), input.end());
    vector<unsigned char> key_vec(key.begin(), key.end());
    vector<unsigned char> xorred_bytes = repeating_key_xor(input_vec, key_vec);
    return bytes_to_hex(xorred_bytes);
}

long long english_score(vector<unsigned char> input) {
    long long score = 0;
    std::string common_chars = "ETAOIN SHRDLU etaoin shrdlu";
    for (unsigned char c : input) {
        if (common_chars.find(c) != std::string::npos) score += 10000;
        else if (c >= ' ' && c <= '}') score += 1;
        else score -= 10000;
    }
    return score;
}

void print(vector<unsigned char> chars) {
    for (unsigned char c : chars) {
        if (c == '\n' || c == '\r') continue;
        cout << c;
    }
    cout << std::endl;
}

bool sort_by_second(std::pair<vector<unsigned char>, long long> a, std::pair<vector<unsigned char>, long long> b) {
    return a.second < b.second;
}

void challenge1() {
    string input1 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    vector<unsigned char> bytes = hex_to_bytes(input1);

    //test conversion from hex to bytes to hex
    string input1again = bytes_to_hex(bytes);
    if (input1 != input1again) {
        cout << "Problem with hex conversion detected! " << input1again << std::endl;
    }

    // challenge 1: convert bytes to base64 and print
    vector<unsigned char> b64 = bytes_to_base64(bytes);
    string b64str = std::string(b64.begin(), b64.end());
    if (b64str == "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t") {
        cout << "Challenge 1 ok" << std::endl;
    } else {
        cout << "Error on challenge 1" << std::endl;
    }
}

void challenge2() {
    // challenge 2: xor two hex string inputs
    string input1 = "1c0111001f010100061a024b53535009181c";
    string input2 = "686974207468652062756c6c277320657965";
    vector<unsigned char> b1 = hex_to_bytes(input1);
    vector<unsigned char> b2 = hex_to_bytes(input2);
    vector<unsigned char> res = {};
    for (int i=0; i<b1.size(); i++) {
        res.push_back(b1[i] ^ b2[i]);
    }
    if (bytes_to_hex(res) == "746865206b696420646f6e277420706c6179") {
        cout << "Challenge 2 ok" << std::endl;
    } else {
        cout << "Error on challenge 2" << std::endl;
    }
}

vector<unsigned char> break_single_character_xor(vector<unsigned char> cipher_text_bytes) {
    unsigned char i = 0;
    vector<std::tuple<long long, vector<unsigned char>, vector<unsigned char>>> options = {};
    do {
        vector<unsigned char> key = { i };
        vector<unsigned char> plain_text_bytes = repeating_key_xor(cipher_text_bytes, key);
        long long score = english_score(plain_text_bytes);
        std::tuple<long long, vector<unsigned char>, vector<unsigned char>> tuple = std::make_tuple(score, key, plain_text_bytes);
        options.push_back(tuple);
    } while (++i);
    std::sort(options.begin(), options.end());

    // Uncomment this to print everything
    //for (std::tuple<long long, vector<unsigned char>, vector<unsigned char>> option : options) {
    //    cout << std::get<0>(option) << " :: ";
    //    print(std::get<2>(option));
    //}

    return std::get<1>(options[options.size()-1]);
}

void challenge3(string cipher_text_hex) {
    // challenge 3: single-byte XOR cipher
    vector<unsigned char> cipher_text_bytes = hex_to_bytes(cipher_text_hex);
    vector<unsigned char> recovered_key = break_single_character_xor(cipher_text_bytes);
    vector<unsigned char> recovered_plain_text = repeating_key_xor(cipher_text_bytes, recovered_key);

    cout << "Challenge 3 plain-text: ";
    print(recovered_plain_text);
}

void challenge4() {
    // challenge 4: find which line in 4.txt has been encrypted with single-character xor
    vector<std::pair<vector<unsigned char>, int>> cipher_texts = {};

    // read cipher_texts from file
    int row = 0;
    std::ifstream infile("../inputs/4.txt");
    std::string line;
    while (std::getline(infile, line)) {
        vector<unsigned char> cipher_text_bytes = hex_to_bytes(line);
        std::pair<vector<unsigned char>, int> pair = std::make_pair(cipher_text_bytes, row);
        cipher_texts.push_back(pair);
        row += 1;
    }

    // for each cipher_text try each possible byte to xor with, score english
    vector<std::tuple<long long, vector<unsigned char>, int>> options = {};
    for (std::pair<vector<unsigned char>, int> pair : cipher_texts) {
        unsigned char i = 0;
        do {
            vector<unsigned char> key = { i };
            vector<unsigned char> cipher_text = pair.first;
            int row = pair.second;
            vector<unsigned char> plain_text_bytes = repeating_key_xor(cipher_text, key);
            long long score = english_score(plain_text_bytes);
            std::tuple<long long, vector<unsigned char>, int> triplet = std::make_tuple(score, plain_text_bytes, row);
            options.push_back(triplet);
        } while (++i);
    }
    std::sort(options.begin(), options.end());

    cout << "Challenge 4 plain-text: ";
    print(std::get<1>(options[options.size()-1]));
}

void challenge5() {
    string plain = "Burning 'em, if you ain't quick and nimble\nI go crazy when I hear a cymbal";
    string key = "ICE";
    string cipher = repeating_key_xor(plain, key);
    if (cipher == "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f") {
        cout << "Challenge 5 ok" << std::endl;
    } else {
        cout << "Challenge 5 error" << std::endl;
    }
}

long hamming(vector<unsigned char> t1, vector<unsigned char> t2) {
    if (t1.size() != t2.size()) {
        throw std::invalid_argument("Hamming distance not implemented for different sized vectors");
    }
    long count = 0;
    for (int i=0; i<t1.size(); i++) {
        unsigned char a = t1[i];
        unsigned char b = t2[i];
        for (unsigned char mask=1; mask!=0; mask<<=1) {
            if ((mask&a)!=(mask&b)) count++;
        }
    }
    return count;
}

void challenge6() {
    // first verify that hamming distance works correctly
    string t1 = "this is a test";
    string t2 = "wokka wokka!!!";
    long expected_hamming = 37;
    long actual_hamming = hamming(str_to_bytes(t1), str_to_bytes(t2));
    if (expected_hamming != actual_hamming) {
        cout << "Problem with Hamming distance " << actual_hamming << std::endl;
    }

    // Read Base64-encoded ciphertext file
    vector<unsigned char> b64 = {};
    std::ifstream f("../inputs/6.txt");
    std::string line;
    while (std::getline(f, line)) {
        for (unsigned char c : line) {
            b64.push_back(c);
        }
    }

    // Test that b64->bytes->b64 conversion works
    vector<unsigned char> bytes = base64_to_bytes(b64);
    vector<unsigned char> b64again = bytes_to_base64(bytes);
    if (b64 != b64again) {
        cout << "Error with base64 conversion!" << std::endl;
        cout << std::string(b64.begin(), b64.end()) << std::endl;
        cout << std::string(b64again.begin(), b64again.end()) << std::endl;
    }

    // Use hamming distance to discover probable key size
    for (int key_size=1; key_size <=40; key_size++) {
        vector<unsigned char> block1 = {};
        vector<unsigned char> block2 = {};
        for (int i = 0; i < key_size; i++) {
            block1.push_back(bytes[i]);
            block2.push_back(bytes[key_size + i]);
        }
        double ed = hamming(block1, block2) * 1.0 / key_size;
        //cout << "Key_size " << key_size << " hamming " << ed << std::endl;
    }


    // Recover the key 1 character at a time
    vector<unsigned char> recovered_key = {};
    int key_size = 29; // Found this by brute forcing all key sizes. Surprisingly its hamming distance wasn't that low?
    for (int i=0; i<key_size; i++) {
        // First, create transposed blocks (e.g. first block is first byte of every key_sized block)
        vector<unsigned char> transposed = {};
        for (int j=i; j<bytes.size(); j+=key_size) {
            transposed.push_back(bytes[j]);
        }
        // Next recover the character that was used to xor all the characters in this transposed block
        vector<unsigned char> recovered_character = break_single_character_xor(transposed);
        // Reconstruct the key by adding 1 character of key_size at a time
        for (unsigned char c : recovered_character) recovered_key.push_back(c);
    }

    // Decrypt cipher_text using the recovered key
    vector<unsigned char> plain_text = repeating_key_xor(bytes, recovered_key);
    cout << "Challenge 6 plain-text: ";
    print(plain_text);
}

vector<unsigned char> aes_decrypt(vector<unsigned char> cipher_block, vector<unsigned char> key_bytes) {
    //KeyExpansion
    //AddRoundKey
    for (int round=10; round>0; round--) {
        //InvShiftRows(state)
        //InvSubBytes(state)
        //AddRoundKey(round, state, roundKey)
        //InvMixColumns(state)
    }

    int round = 0;
    //invShiftRows(state)
    //InvSubBytes(state)
    //AddRoundKey(round, state, roundKey)

    return cipher_block;
}

// split cipher_bytes into 128-bit blocks, decrypt each byte with key using AES with 128-bit key
vector<unsigned char> aes_ecb_decrypt(vector<unsigned char> cipher_bytes, vector<unsigned char> key_bytes) {
    int BLOCK_SIZE = 16;
    vector<unsigned char> plain_bytes = {};
    for (int i=0; i<cipher_bytes.size(); i+=BLOCK_SIZE) {

        // create block
        vector<unsigned char> cipher_block = {};
        for (int j=i; j<i+BLOCK_SIZE; j++) {
            cipher_block.push_back(cipher_bytes[j]);
        }

        // decrypt block
        vector<unsigned char> plain_block = aes_decrypt(cipher_block, key_bytes);

        // append to plain_bytes
        for (int i=0; i<plain_block.size(); i++) {
            plain_bytes.push_back(plain_block[i]);
        }
    }
    return plain_bytes;
}

void challenge7() {
    // Read Base64-encoded ciphertext file
    vector<unsigned char> b64 = {};
    std::ifstream f("../inputs/7.txt");
    std::string line;
    while (std::getline(f, line)) {
        for (unsigned char c : line) {
            b64.push_back(c);
        }
    }
    vector<unsigned char> cipher_bytes = base64_to_bytes(b64);
    vector<unsigned char> key_bytes = str_to_bytes("YELLOW SUBMARINE");
    vector<unsigned char> plain_bytes = aes_ecb_decrypt(cipher_bytes, key_bytes);
    print(cipher_bytes);
    print(plain_bytes);
}

void challenge8() {
    // challenge 8: find which line in 8.txt has been encrypted with ECB
    int best_count = 0;
    int ecb_index = 0;
    int index = 0;
    string ecb_line = "";

    std::ifstream f("../inputs/8.txt");
    std::string line;
    while (std::getline(f, line)) {
        std::unordered_map<string, int> map;
        for (int i=0; i<line.length(); i+=32) {
            string block = line.substr(i, 32);
            map[block]++;
            if (map[block] > best_count) {
                ecb_index = index;
                best_count = map[block];
                ecb_line = line;
            }
        }
        index += 1;
    }

    cout << "Challenge 8 index for ECB ciphertext: " << ecb_index << std::endl;
}

int set1_prints() {
    challenge1();
    challenge2();
    challenge3("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    challenge4();
    challenge5();
    challenge6();
    challenge7();
    challenge8();
    cout << "Set 1 end" << std::endl;
    return 0;
}