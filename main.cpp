#include <stdio.h>
#include <pcap.h>
#include <thread>
#include <mutex>
#include <chrono>
#include <map>

#include "Dot11.h"
#include "radiotap.h"
#include "AP.h"

std::map<Mac, AP> apList;
std::mutex mtx;

constexpr int CMD_SIZE = 32;

void PrintAPList(char* device)
{
	int currentChannel = 1;
	char cmd[CMD_SIZE];

	while (true)
	{
		system("clear");

		std::lock_guard<std::mutex> lock(mtx);
		printf("\nCurrent Channel: %d ]\n\n", currentChannel);

		printf("BSSID\t\t\tPWR\tBEACONS\tCH\tENC\tESSID\n\n");
		for (auto it = apList.begin(); it != apList.end(); ++it)
		{
			std::string bssid = (std::string)it->first;
			std::string encMethod;
			if (it->second.enc & OPN)
				encMethod = "OPN";
			else if (it->second.enc & WEP)
				encMethod = "WEP";
			else if (it->second.enc & WPA)
				encMethod = "WPA";
			else if (it->second.enc & WPA2)
				encMethod = "WPA2";
			else
				encMethod = "";

			printf("%s\t", bssid.c_str());
			printf("%d\t", it->second.pwr);
			printf("%d\t", it->second.beacons);
			printf("%d\t", it->second.channel);
			printf("%s\t", encMethod.c_str());
			// TODO: Sometimes print weird essid
			printf("%s\n", it->second.essid.c_str());
    	}

		std::this_thread::sleep_for(std::chrono::milliseconds(200));
		std::snprintf(cmd, CMD_SIZE, "iw dev %s set channel %d", device, currentChannel);
		int res = system(cmd);
		if (res == 0)
		{
			currentChannel++;

			// TODO: Why cannot switch to channel 14?
			if (currentChannel > 13)
				currentChannel = 1;
		}
	}
}

AP& GetAPInfo(Mac bssid)
{
	// If bssid is not found on map, make new one
	if (apList.find(bssid) == apList.end())
	{
		AP apInfo(bssid);
		apList[bssid] = apInfo;
	}

	return apList[bssid];
}

int main(int argc, char* argv[])
{
	if (argc != 2)
	{
		printf("syntax : airodump <interface>\n");
		printf("sample : airodump mon0\n");
		return -1;
	}

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcapDevice = pcap_open_live(argv[1], BUFSIZ, 1, 1000, errbuf);
	if (pcapDevice == NULL)
	{
		printf("Can't open device %s: %s\n", argv[1], errbuf);
		return -1;
	}

	// Start print thread
	std::thread thrd(PrintAPList, argv[1]);

	while (true)
	{
		struct pcap_pkthdr* header;
    	const u_char* pPacket;
    	int res = pcap_next_ex(pcapDevice, &header, &pPacket);
		// When no packet received
    	if (res == 0)
			continue;
		
		// When error
    	if (res == -1 || res == -2)
			break;

		PRADIOTAP pRadioTap = (PRADIOTAP)pPacket;
		Dot11Frame* pFrame = (Dot11Frame*)(pPacket + pRadioTap->it_len);

		// Only parse DATA & MANAGEMENT
		if (pFrame->type == TYPE_CTRL)
			continue;
		
		std::lock_guard<std::mutex> lock(mtx);

		uint8_t subType = pFrame->getTypeSubtype();
		if (subType == SUBTYPE_BEACON || subType == SUBTYPE_PROBE_RESPONSE)
		{
			Dot11BeaconFrame* pBeaconFrame = (Dot11BeaconFrame*)pFrame;

			// Add new or get AP Information
			AP& apInfo = GetAPInfo(pBeaconFrame->bssid);
			apInfo.beacons++;

			// Get antenna signal from RadioTap hdr
			apInfo.pwr = pRadioTap->it_antenna_signal1;

			// Parse dynamic dot11taggedparameter
			Dot11TaggedParam* pTaggedParm = (Dot11TaggedParam*)((uintptr_t)pBeaconFrame + sizeof(Dot11BeaconFrame));
			apInfo.ParseDot11TaggedParameter(pTaggedParm, ((uint8_t*)pPacket + header->caplen));
		}
	}

	pcap_close(pcapDevice);

	return 0;
}
