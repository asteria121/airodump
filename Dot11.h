#ifndef _DOT11_H_
#define _DOT11_H_

#include "mac.h"

// Types
constexpr uint8_t TYPE_MGT = 0b00;
constexpr uint8_t TYPE_CTRL = 0b01;
constexpr uint8_t TYPE_DATA = 0b10;

// SubTypes
constexpr uint8_t SUBTYPE_ASSO_REQUEST = 0x00;
constexpr uint8_t SUBTYPE_ASSO_RESPONSE = 0x01;
constexpr uint8_t SUBTYPE_REASSO_REQUEST = 0x02;
constexpr uint8_t SUBTYPE_REASSO_RESPONSE = 0x03;
constexpr uint8_t SUBTYPE_PROBE_REQUEST = 0x04;
constexpr uint8_t SUBTYPE_PROBE_RESPONSE = 0x05;
constexpr uint8_t SUBTYPE_BEACON = 0x08;
constexpr uint8_t SUBTYPE_DEASSOCIATE = 0x0a;
constexpr uint8_t SUBTYPE_AUTH = 0x0b;
constexpr uint8_t SUBTYPE_DEAUTH = 0x0c;

#pragma pack(push, 1)
class Dot11Frame
{
public:
	uint8_t version: 2;
	uint8_t type: 2;
	uint8_t subtype: 4;
	uint8_t flags;
	uint16_t duration;
	Mac receiverAddress;

	inline uint8_t getTypeSubtype()
    {
		return (this->version << 6) + (this->type << 4) + this->subtype;
	}
};

class Dot11MgtFrame : public Dot11Frame
{
public:
	Mac transmiterAddress;
	Mac bssid;
	uint16_t fragNum: 4;
	uint16_t seqNum: 12;
};

class Dot11BeaconFrame: public Dot11MgtFrame
{
public:
	uint64_t timeStamp;
	uint16_t beaconInterval;
	uint16_t capabilitiesInfo;
};
#pragma pack(pop)

// Tag Num
constexpr uint8_t TAGNUM_SSID = 0;
constexpr uint8_t TAGNUM_RATES = 1;
constexpr uint8_t TAGNUM_FHPARAMS = 2;
constexpr uint8_t TAGNUM_DSPARAMS = 3;
constexpr uint8_t TAGNUM_CFPARAMS = 4;
constexpr uint8_t TAGNUM_TIM = 5;
constexpr uint8_t TAGNUM_IBSSPARAMS = 6;
constexpr uint8_t TAGNUM_COUNTRY = 7;
constexpr uint8_t TAGNUM_EDCAPARAMS = 12;
constexpr uint8_t TAGNUM_CHALLENGE = 16;
constexpr uint8_t TAGNUM_PWRCNSTR = 32;
constexpr uint8_t TAGNUM_PWRCAP = 33;
constexpr uint8_t TAGNUM_TPCREQUEST = 34;
constexpr uint8_t TAGNUM_TPCRESPONSE = 35;
constexpr uint8_t TAGNUM_SUPPCHAIN = 36;
constexpr uint8_t TAGNUM_CHAINSWIT_CHANN = 37;
constexpr uint8_t TAGNUM_MEASREQUEST = 38;
constexpr uint8_t TAGNUM_MEASRESPONSE = 39;
constexpr uint8_t TAGNUM_QUIET = 40;
constexpr uint8_t TAGNUM_IBSSDFS = 41;
constexpr uint8_t TAGNUM_ERP = 42;
constexpr uint8_t TAGNUM_HTCAP = 45;
constexpr uint8_t TAGNUM_QOS_CAP = 46;
constexpr uint8_t TAGNUM_RSN = 48;
constexpr uint8_t TAGNUM_XRATES = 50;
constexpr uint8_t TAGNUM_TIE = 56;
constexpr uint8_t TAGNUM_HTINFO = 61;
constexpr uint8_t TAGNUM_MMIE = 76;
constexpr uint8_t TAGNUM_TPC = 150;
constexpr uint8_t TAGNUM_CCKM = 156;
constexpr uint8_t TAGNUM_VENDOR = 221;

#pragma pack(push, 1)
class Dot11TaggedParam
{
public:
	uint8_t num;
	uint8_t len;
	uint8_t data;

	uint8_t GetSpeed()
	{
		uint8_t speed = *(&data + len - 1);
		return (speed & 0x7F) / 2;
	}

	std::string GetSSID()
	{
		return std::string(&data, &data + len);
	}
};
#pragma pack(pop)

#endif