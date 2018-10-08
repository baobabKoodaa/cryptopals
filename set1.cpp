#include <iostream>
#include <string>
#include <vector>
#include "set1.h"
#include <algorithm>
#include <tuple>
#include <sstream>
#include <string>
#include <fstream>

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

vector<char> bytes_to_base64(vector<unsigned char> bytes) {
    vector<char> str = {};
    int bits = 8*bytes.size();
    for (int i=0; i<bits; i+=6) {
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
    return str;
}

vector<unsigned char> xor_against_single_byte(vector<unsigned char> input, unsigned char c) {
    vector<unsigned char> output = {};
    for (int i=0; i<input.size(); i++) {
        output.push_back(input[i] ^ c);
    }
    return output;
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
    vector<char> b64 = bytes_to_base64(bytes);
    string b64str = std::string(b64.begin(), b64.end());
    cout << b64str << std::endl;
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
    cout << bytes_to_hex(res) << std::endl;
    if (bytes_to_hex(res) == "746865206b696420646f6e277420706c6179") {
        cout << "Challenge 2 ok" << std::endl;
    } else {
        cout << "Error on challenge 2" << std::endl;
    }
}

void challenge3(string cipher_text_hex) {
    // challenge 3: single-byte XOR cipher
    vector<unsigned char> cipher_text_bytes = hex_to_bytes(cipher_text_hex);
    cout << "Challenge 3 cipher-text: ";
    print(cipher_text_bytes);
    unsigned char i = 0;
    vector<std::pair<vector<unsigned char>, long long>> options = {};
    do {
        vector<unsigned char> plain_text_bytes = xor_against_single_byte(cipher_text_bytes, i);
        long long score = english_score(plain_text_bytes);
        std::pair<vector<unsigned char>, long long> pair = std::make_pair(plain_text_bytes, score);
        options.push_back(pair);
    } while (++i);
    std::sort(options.begin(), options.end(), sort_by_second);

    // Uncomment this to print everything
    // for (std::pair<vector<unsigned char>, long long> option : options) {
    //    cout << option.second << " :: ";
    //    print(option.first);
    //}

    cout << "Challenge 3 plain-text: ";
    print(options[options.size()-1].first);
}

void challenge4() {
    // challenge 4: find which line in 4.txt has been encrypted with single-character xor
    vector<std::pair<vector<unsigned char>, int>> cipher_texts = {};

    // read cipher_texts from file
    int row = 0;
    std::ifstream infile("../4.txt");
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
            vector<unsigned char> cipher_text = pair.first;
            int row = pair.second;
            vector<unsigned char> plain_text_bytes = xor_against_single_byte(cipher_text, i);
            long long score = english_score(plain_text_bytes);
            std::tuple<long long, vector<unsigned char>, int> triplet = std::make_tuple(score, plain_text_bytes, row);
            options.push_back(triplet);
        } while (++i);
    }
    std::sort(options.begin(), options.end());

    cout << "Challenge 4 plain-text: ";
    print(std::get<1>(options[options.size()-1]));
}

void challenge8() {
    // challenge 8: find which line in 8.txt has been encrypted with ECB
    int best_count = 0;
    int ecb_index = 0;
    int index = 0;
    string ecb_line = "";
    std::ifstream infile("../8.txt");
    std::string line;
    while (std::getline(infile, line)) {
        vector<unsigned char> bytes = hex_to_bytes(line);
        int count[256];
        for (int i=0; i<256; i++) count[i] = 0;
        for (int i=0; i<bytes.size(); i++) count[bytes[i]]++;
        for (int i=0; i<256; i++) {
            if (count[i] > best_count) {
                ecb_index = index;
                best_count = count[i];
                ecb_line = line;
            }
        }
        index += 1;
    }
    cout << "Challenge 4 index for ECB ciphertext: " << ecb_index << std::endl;
    //cout << ecb_line << std::endl;
}

int set1_prints() {
    challenge1();
    challenge2();
    challenge3("1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736");
    challenge4();
    challenge8();
    cout << "Set 1 end" << std::endl;
    return 0;
}