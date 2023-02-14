#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <ctype.h>
#include <string.h>

/* getline: read a line into s, return length */
int getline(char *s, int lim) {
    int c, i; // great for debugging

    for (i = 0; i < lim-1 && (c = getchar()) != EOF && c != '\n'; i++) {
        if (isblank(c)) {
            i--;
            continue;
        }
        if ((c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'f') || (c >= '0' && c <= '9')) {
            s[i] = c;
        }
        else {
            printf("Error: TLV must be an even number of hexadecimal digits\n");
            return -1;
        }
    }
    s[i] = '\0';
    return i;
}

bool tag_encode(char* tag, bool first_byte, bool *constructed) {
    int decimalTag = (int)strtol(tag, NULL, 16);

    if (first_byte) { // of the tag
        // Get the 6th bit
        if (decimalTag & 0x20) {
            *constructed = true;
        }
        // Get the first 5 bits
        if ((decimalTag & 0x1F) == 0x1F) {
            return true;
        }
        return false;
    }

    // Table 36, check the last bit
    if (decimalTag >= 0x80) {
        return true;
    }
    return false;
}

int length_encode(char* length, bool *length_of_length) {
    int decimalLength = (int)strtol(length, NULL, 16);
    // check bit8
    if (decimalLength < 0x80 || *length_of_length) {
        return decimalLength;    
    }
    
    *length_of_length = true;
    // get bits from 1 to 7
    return decimalLength & 0x7F;
}

// tlv will be moved 2 places left, after every print of tag, length or value
void parse_tlv(char* tlv) {
    // base case
    if (tlv[0] == '\0') {
        return;
    }

    // rec case
    char current[3]; // current for the tags, lengths and values, stores a byte
    memcpy(current, tlv, 2);
    bool first = true;
    bool constructed_object = false;
    printf("Tag: %s", current);

    // Loot till tag_encode return false, i.e the tag's last byte
    while (tag_encode(current, first, &constructed_object)) {
        tlv += 2;
        memcpy(current, tlv, 2);
        printf("%s", current);
        first = false;
    }
    if (constructed_object) {
        printf(" Template");
    }
    printf("\n");

    tlv += 2;
    memcpy(current, tlv, 2);
    first = true;
    // Get the length and move tvl two places left, if length is not length of length
    bool length_of_length = false;
    int length = length_encode(current, &length_of_length);
    if (length_of_length) {
        // add to length the values of the next bytes in the tlv, counter times or previous length
        printf("Length of lenght field: %i\n", length);
        // length is the bytes of the length field, so multiply length by 2 and get the bytes
        int bytes = length * 2;
        char length_field[bytes+1];
        tlv += 2;
        memcpy(length_field, tlv, bytes);
        tlv += bytes - 2;  // so I can continue like normal
        length = length_encode(length_field, &length_of_length);
    }
    printf("Length: %i\n", length);

    // Go inside the constructed object if it is
    if (constructed_object) {
        parse_tlv(tlv+2);
        return;
    }
    tlv += 2;
    memcpy(current, tlv, 2);

    // Print the values of the current package
    printf("Value: ");
    for (int i = 0; i < length; i++) {
        if (strlen(current) < 2) {
            printf("Error: Short Value, expected length %i, got %i", length, i);
            return;
        }
        printf("%s ", current);
        tlv += 2;
        memcpy(current, tlv, 2);
    }
    printf("\n\n");
    parse_tlv(tlv);
}

// TLVs
// 9F 02 06 00 00 00 00 10 00
// 61 1F 4F 08 A0 00 00 00 25 01 05 01 50 10 50 65 72 73 6F 6E 61 6C 20 41 63 63 6F 75 6E 74 87 01 01
// 61 1E 4F 07 A0 00 00 00 29 10 10 50 10 50 65 72 73 6F 6E 61 6C 20 41 63 63 6F 75 6E 74 87 01 02
// 77 1E 9F 27 01 80 9F 36 02 02 13 9F 26 08 2D F3 83 3C 61 85 5B EA 9F 10 07 06 84 23 00 31 02 08 
// 77 22 82 02 78 00 94 1C 10 01 04 00 10 05 05 00 08 06 06 01 08 07 07 01 08 08 09 01 08 0A 0A 00 08 01 04 00
// 9F 02 82 02 03 01 02 03 04 05
int main(void) {
    char tlv[200];
    printf("Enter TLV: ");
    // Get the tlv
    int len = getline(tlv, 200);
    if (len == 0) {
        printf("Empty TLV\n");
        return 1;
    }
    else if (len == -1) {
        printf("Error: Invalid TLV\n");
        return 1;
    }
    else if (len % 2 != 0 || len < 6) {
        printf("Error: TLV must be an even number of hexadecimal digits\n");
        printf("Error: Invalid TLV\n");
        return 1;
    }
    
    parse_tlv(tlv);
    return 0;
}
