#ifndef ASKWAM_BEACON_MIN_H
#define ASKWAM_BEACON_MIN_H

#include <windows.h>

typedef struct datap {
    char *original;
    char *buffer;
    int length;
    int size;
} datap;

DECLSPEC_IMPORT void BeaconDataParse(datap *parser, char *buffer, int size);
DECLSPEC_IMPORT int BeaconDataInt(datap *parser);
DECLSPEC_IMPORT char *BeaconDataExtract(datap *parser, int *size);
DECLSPEC_IMPORT void BeaconPrintf(int type, const char *format, ...);

#define CALLBACK_OUTPUT 0x00
#define CALLBACK_ERROR  0x0d

#endif
