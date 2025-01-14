#ifndef _AP_H_
#define _AP_H_

#include <cstdint>
#include <string>
#include "mac.h"
#include "Dot11.h"

constexpr uint16_t OPN = 0x0001;
constexpr uint16_t WEP = 0x0002;
constexpr uint16_t WPA = 0x0004;
constexpr uint16_t WPA2 = 0x0008;

class AP
{
public:
    Mac bssid;
    int pwr = -1;
    uint beacons = 0;
    uint8_t channel = 0;
    uint16_t enc = 0;
    std::string essid;

    void ParseDot11TaggedParameter(Dot11TaggedParam* pTaggedParam, uint8_t* pPacketEnd);

    AP() {}
    AP(Mac _bssid)
    {
        this->bssid = _bssid;
    }
};

#endif