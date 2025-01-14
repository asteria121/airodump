#include "AP.h"
#include "Dot11.h"

void AP::ParseDot11TaggedParameter(Dot11TaggedParam* pTaggedParam, uint8_t* pPacketEnd)
{
    // Loop until packet end
    while ((uint8_t*)pTaggedParam < pPacketEnd)
    {
        switch (pTaggedParam->num)
        {
        case TAGNUM_DSPARAMS:
            this->channel = pTaggedParam->data;
            break;
        case TAGNUM_SSID:
            this->essid = pTaggedParam->GetSSID();
            break;
        case TAGNUM_RSN:
            this->enc &= ~(WEP | WPA);
            this->enc |= WPA2;
            break;
        }

        // add 2(tag type, length) + dataLen to parse next param
        uintptr_t tmp = (uintptr_t)pTaggedParam;
        tmp += pTaggedParam->len;
        tmp += 2;
        pTaggedParam = (Dot11TaggedParam*)tmp;
    }
}