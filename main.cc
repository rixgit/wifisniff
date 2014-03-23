/**
 * Simple 802.11 Management Frame Sniffer for Reservoir Labs C++ code sample
 * 
 * Requires appropriate permissions and RFMON Capable wireless card
 * 
 * Library Dependencies 
 *   - LibPCAP - Version 1.3.0-1
 *   - Boost - Version 1.49.0.1
 * 
 * Rick Correa, rcorrea@gmail.com
 *
 * TODO: 
 *   Use OS RadioTap libraries to pull RSSI out.  Sorta messy since Linux and BSD 
 *       differ according to the docs (http://www.radiotap.org/Radiotap)
 *   Use Internal <ieee80211.h> and <ieee80211_radiotap.h> to aid in unpacking 
 *       packed portion of the radiotap header
 *   Check that dev is a valid device before open handle or SIGSEV HAPPENS
 *   Check appropriate permissions and prompt before exit
 * 
 **/

#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


//To Get RadioTap Headers
#include <pcap.h>


//Using Boost just for format function
#include <boost/format.hpp>


// Basic 802.11 Limits
#define BUFSIZE 65535    //Standard Packet Size
#define WLAN_ADDR_LEN 6  //MAC Address is 6 bytes
#define SSID_MAX_LEN 33      //I thought it was 32, but doc states 33.


//Frame Control Constants
#define FC_MGMT 0
#define FC_CTRL 1
#define FC_DATA 2


//Control Management Tags
#define CMT_SSID 0
#define CMT_DATA_RATES 1
#define CMT_FHCS 2
#define CMT_DSS  3
#define CMT_CFP  4
#define CMT_TIM  5
#define CMT_IBSS 6
#define CMT_COUNTRY 7


//From radiotap.org - http://www.radiotap.org/defined-fields
struct radiotap_header {
  u_int8_t        it_version;     
  u_int8_t        it_pad;
  u_int16_t       it_len;         
  u_int32_t       it_present;     
};


//From 80211 Pocket Reference Guide
struct dot11_header {
  u_int16_t        proto:2;
  u_int16_t        type:2;
  u_int16_t        s_type:2;
  u_int16_t        to_DS:1;
  u_int16_t        from_DS:1;
  u_int16_t        more_Frag:1;
  u_int16_t        retry:1;
  u_int16_t        power_Mgt:1;
  u_int16_t        more_Data:1;
  u_int16_t        priv:1;
  u_int16_t        strict:1;
  u_int16_t        duration;
  u_char           dest_addr[WLAN_ADDR_LEN];
  u_char           bssid_addr[WLAN_ADDR_LEN];  
  u_char           src_addr[WLAN_ADDR_LEN];
  u_int16_t        frag_Num:4;
  u_int16_t        seq_Num:12;
};


//From 80211 Pocket Reference Guide
struct dot11_mgmt_frame {
  u_char           elem_id;
  u_char           len;
  u_char           ssid[SSID_MAX_LEN];
};


using namespace std;
using boost::format;


//Global Error Buffer for PCAP.
char * ERR_BUFF[PCAP_ERRBUF_SIZE];


void ERR_HANDLER(const char * msg) {
  //Add clean-up logic if needed including error handling
  cerr << msg << endl;

#ifdef DEBUG
      cerr << "---Library Specific Message [" << ERR_BUFF << "]" << endl;
#endif
  abort ();
}


pcap_t * openHandle(char *dev) {
  pcap_t *handle;
  handle = pcap_open_live(dev, BUFSIZE, 1, 1000, *ERR_BUFF);

  if (handle==NULL) {
    ERR_HANDLER("openHandle::Unable to open handle");
  }
  return handle;
}


void checkRadioType(pcap_t * handle) {
  switch( pcap_datalink(handle)) {
    case DLT_IEEE802_11_RADIO:
      break;
    case DLT_IEEE802_11:
      ERR_HANDLER("checkRadioType::Interface is not in RFMON Mode");
    default:
      ERR_HANDLER("checkRadioType::Unknown Interface Type");
    }
    
    return;
}


void ssid_logger(u_char *args, const struct pcap_pkthdr *header, const u_char *packet) {
  struct radiotap_header * rt_hdr;
  struct dot11_header * dot11_hdr;
  struct dot11_mgmt_frame * dot11_frame;

  rt_hdr=(struct radiotap_header *) packet;
  dot11_hdr=(struct dot11_header *) (packet + rt_hdr->it_len);

  char ssid[SSID_MAX_LEN];
  bzero(ssid, SSID_MAX_LEN);
  int ssid_len = 0;
  
  //We're only concerned about management frames because they contain SSIDs 
  if(dot11_hdr->type == FC_MGMT) {
    dot11_frame=(struct dot11_mgmt_frame *) (packet + rt_hdr->it_len + sizeof(dot11_header));

    if (dot11_frame->elem_id == CMT_SSID) {

      ssid_len = dot11_frame->len;

      cout << format("Size of SSID: %2d ") %ssid_len;

      if (ssid_len <= SSID_MAX_LEN) {
	strncpy((char *) ssid, (const char *) dot11_frame->ssid, ssid_len);
     
	cout << format("  Current SSID [%s]\n") %ssid;
      }
    }
  }
}


int sniffWL(char * dev) {
  pcap_t * handle;
  //const u_char *packet;		
  //struct pcap_pkthdr c_header;

  //TODO: Check that dev is a valid device before open handle or SIGSEV HAPPENS
  handle  = openHandle(dev);

  if (handle==NULL) {
    ERR_HANDLER("sniffWL::Bad Interface");
  }

  checkRadioType(handle);

  pcap_loop(handle, -1, ssid_logger, NULL);

  return 0;
}


int main(int argc, char *argv[]) {
  char *dev;

  if(argc != 2) {
      cout << format("\nUsage:  \n%s <wlan_if>\n" \
		     "   Where <wlan_if> is a valid wireless interface "\
		     "set-up in RFMON mode\n\n") %argv[0];
      return 1;
    }

  dev = argv[1];
  if (dev==NULL) {
    ERR_HANDLER("main::Bad interface");  
  }

  cout << dev << endl;

  sniffWL(dev);
  return 0;  
}
