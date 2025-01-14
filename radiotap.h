#ifndef _RADIOTAP_H_
#define _RADIOTAP_H_

#include <cstdint>

#pragma pack(push, 1)
typedef struct _RADIOTAP {
        u_int8_t        it_version;     /* set to 0 */
        u_int8_t        it_pad;
        u_int16_t       it_len;         /* entire length */
        u_int32_t       it_present;     /* fields present */
        u_int8_t        it_flags;
        u_int8_t        it_datarate;
        u_int16_t       it_channel_frequency;
        u_int16_t       it_channel_flags;
        int8_t          it_antenna_signal1;
        u_int8_t        it_antenna1;
        u_int16_t       it_rxflags;
        int8_t          it_antenna_signal2;
        u_int8_t        it_antenna2;
} RADIOTAP, *PRADIOTAP;
#pragma pack(pop)

#endif