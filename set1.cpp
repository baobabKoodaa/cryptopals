#include <iostream>
#include <string>
#include <vector>
#include "set1.h"

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
        cout << v << int_to_b64_char(v) << std::endl;
        str.push_back(int_to_b64_char(v));
    }
    return str;
}

int set1_prints() {
    string input1 = "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d";
    vector<unsigned char> bytes = hex_to_bytes(input1);
    vector<char> b64 = bytes_to_base64(bytes);
    cout << std::string(b64.begin(), b64.end()) << std::endl;
    cout << "Set 1 end" << std::endl;
    return 0;
}