#include <argp.h>
#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <stdbool.h>
#include <stdio.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <unistd.h>

#define FROM "eno1"
#define TO "34:97:f6:38:e0:f6"
#define SEND_ETHER_TYP 0x88f7

#define MAX_ETHERNET_FRAME_SIZE 1514
#define MAX_ETHERNET_DATA_SIZE 1500

#define ETHERNET_HEADER_SIZE 14
#define ETHERNET_DST_ADDR_OFFSET 0
#define ETHERNET_SRC_ADDR_OFFSET 6
#define ETHERNET_TYPE_OFFSET 12
#define ETHERNET_DATA_OFFSET 14

#define MAC_BYTES 6
/* Helpers to access gPTP messages. */
#define GPTP_HDR(pkt) gptp_get_hdr(pkt)
#define GPTP_ANNOUNCE(pkt) ((struct gptp_announce *)gptp_data(pkt))
#define GPTP_SIGNALING(pkt) ((struct gptp_signaling *)gptp_data(pkt))
#define GPTP_SYNC(pkt) ((struct gptp_sync *)gptp_data(pkt))
#define GPTP_FOLLOW_UP(pkt) ((struct gptp_follow_up *)gptp_data(pkt))
#define GPTP_DELAY_REQ(pkt) \
	((struct gptp_delay_req *)gptp_data(pkt))
#define GPTP_PDELAY_REQ(pkt) \
	((struct gptp_pdelay_req *)gptp_data(pkt))
#define GPTP_PDELAY_RESP(pkt) \
	((struct gptp_pdelay_resp *)gptp_data(pkt))
#define GPTP_PDELAY_RESP_FOLLOWUP(pkt) \
	((struct gptp_pdelay_resp_follow_up *)gptp_data(pkt))

/* Field values. */
#define GPTP_TRANSPORT_802_1_AS 0x1
#define GPTP_VERSION 0x2

/* Message Lengths. */
#define GPTP_PACKET_LEN(pkt) net_pkt_get_len(pkt)
#define GPTP_VALID_LEN(pkt, len) \
	(len > (NET_ETH_MINIMAL_FRAME_SIZE - GPTP_L2_HDR_LEN(pkt)))
#define GPTP_L2_HDR_LEN(pkt) \
	((long)GPTP_HDR(pkt) - (long)NET_ETH_HDR(pkt))

#define GPTP_SYNC_LEN \
	(sizeof(struct gptp_hdr) + sizeof(struct gptp_sync))
#define GPTP_FOLLOW_UP_LEN \
	(sizeof(struct gptp_hdr) + sizeof(struct gptp_follow_up))
#define GPTP_PDELAY_REQ_LEN \
	(sizeof(struct gptp_hdr) + sizeof(struct gptp_pdelay_req))
#define GPTP_PDELAY_RESP_LEN \
	(sizeof(struct gptp_hdr) + sizeof(struct gptp_pdelay_resp))
#define GPTP_PDELAY_RESP_FUP_LEN \
	(sizeof(struct gptp_hdr) + sizeof(struct gptp_pdelay_resp_follow_up))
#define GPTP_SIGNALING_LEN \
	(sizeof(struct gptp_hdr) + sizeof(struct gptp_signaling))

/* For the Announce message, the TLV is variable length. The len field
 * indicates the length of the TLV not accounting for tlvType and lengthField
 * which are 4 bytes.
 */
#define GPTP_ANNOUNCE_LEN(pkt) \
	(sizeof(struct gptp_hdr) + sizeof(struct gptp_announce) \
	 + ntohs(GPTP_ANNOUNCE(pkt)->tlv.len) \
	 - sizeof(struct gptp_path_trace_tlv) + 4)

#define GPTP_CHECK_LEN(pkt, len) \
	((GPTP_PACKET_LEN(pkt) != len) && (GPTP_VALID_LEN(pkt, len)))
#define GPTP_ANNOUNCE_CHECK_LEN(pkt) \
	((GPTP_PACKET_LEN(pkt) != GPTP_ANNOUNCE_LEN(pkt)) && \
	 (GPTP_VALID_LEN(pkt, GPTP_ANNOUNCE_LEN(pkt))))
#define BIT(n)  (1UL << (n))
/* Header Flags. Byte 0. */
#define GPTP_FLAG_ALT_MASTER        BIT(0)
#define GPTP_FLAG_TWO_STEP          BIT(1)
#define GPTP_FLAG_UNICAST           BIT(2)
#define GPTP_FLAG_PROFILE_SPECIFIC1 BIT(5)
#define GPTP_FLAG_PROFILE_SPECIFIC2 BIT(6)

/* Header Flags. Byte 1. */
#define GPTP_FLAG_LEAP61            BIT(0)
#define GPTP_FLAG_LEAP59            BIT(1)
#define GPTP_FLAG_CUR_UTC_OFF_VALID BIT(2)
#define GPTP_FLAG_PTP_TIMESCALE     BIT(3)
#define GPTP_FLAG_TIME_TRACEABLE    BIT(4)
#define GPTP_FLAG_FREQ_TRACEABLE    BIT(5)

/* Signaling Interval Flags. */
#define GPTP_FLAG_COMPUTE_NEIGHBOR_RATE_RATIO 0x1
#define GPTP_FLAG_COMPUTE_NEIGHBOR_PROP_DELAY 0x2

/* Signaling Interval Values. */
#define GPTP_ITV_KEEP               -128
#define GPTP_ITV_SET_TO_INIT        126
#define GPTP_ITV_STOP               127

/* Control. Only set for header compatibility with v1. */
#define GPTP_SYNC_CONTROL_VALUE     0x0
#define GPTP_FUP_CONTROL_VALUE      0x2
#define GPTP_OTHER_CONTROL_VALUE    0x5

/* Other default values. */
#define GPTP_RESP_LOG_MSG_ITV           0x7F
#define GPTP_ANNOUNCE_MSG_PATH_SEQ_TYPE htons(0x8)

/* Organization Id used for TLV. */
#define GPTP_FUP_TLV_ORG_ID_BYTE_0  0x00
#define GPTP_FUP_TLV_ORG_ID_BYTE_1  0x80
#define GPTP_FUP_TLV_ORG_ID_BYTE_2  0xC2
#define GPTP_FUP_TLV_ORG_SUB_TYPE   0x01
#define GPTP_SYNC_MESSAGE                0x00
#define GPTP_DELAY_REQ_MESSAGE           0x01
#define GPTP_PATH_DELAY_REQ_MESSAGE      0x02
#define GPTP_PATH_DELAY_RESP_MESSAGE     0x03
#define GPTP_FOLLOWUP_MESSAGE            0x08
#define GPTP_DELAY_RESP_MESSAGE          0x09
#define GPTP_PATH_DELAY_FOLLOWUP_MESSAGE 0x0a
#define GPTP_ANNOUNCE_MESSAGE            0x0b
#define GPTP_SIGNALING_MESSAGE           0x0c
#define GPTP_MANAGEMENT_MESSAGE          0x0d

#define GPTP_IS_EVENT_MSG(msg_type)      (!((msg_type) & BIT(3)))

#define GPTP_CLOCK_ID_LEN                8

#ifndef __packed
#define __packed        __attribute__((__packed__))
#endif

/** @endcond */

/**
 * @brief Port Identity.
 */
struct gptp_port_identity {
	/** Clock identity of the port. */
	uint8_t clk_id[GPTP_CLOCK_ID_LEN];

	/** Number of the port. */
	uint16_t port_number;
} __packed;

struct gptp_flags {
	union {
		/** Byte access. */
		uint8_t octets[2];

		/** Whole field access. */
		uint16_t all;
	};
} __packed;

struct gptp_hdr {
	/** Type of the message. */
	uint8_t message_type:4;

	/** Transport specific, always 1. */
	uint8_t transport_specific:4;

	/** Version of the PTP, always 2. */
	uint8_t ptp_version:4;

	/** Reserved field. */
	uint8_t reserved0:4;

	/** Total length of the message from the header to the last TLV. */
	uint16_t message_length;

	/** Domain number, always 0. */
	uint8_t domain_number;

	/** Reserved field. */
	uint8_t reserved1;

	/** Message flags. */
	struct gptp_flags flags;

	/** Correction Field. The content depends of the message type. */
	int64_t correction_field;

	/** Reserved field. */
	uint32_t reserved2;

	/** Port Identity of the sender. */
	struct gptp_port_identity port_id;

	/** Sequence Id. */
	uint16_t sequence_id;

	/** Control value. Sync: 0, Follow-up: 2, Others: 5. */
	uint8_t control;

	/** Message Interval in Log2 for Sync and Announce messages. */
	int8_t log_msg_interval;
} __packed;

struct gptp_sync {
	/** Reserved field. This field is used for PTPv2, unused in gPTP. */
    struct gptp_hdr *hdr;
	uint8_t reserved[10];
} __packed;

    struct gptp_hdr hdr;
    struct gptp_sync gptpSync;
	
void gptp_prepare_sync(struct gptp_hdr *hdr, struct gptp_sync *gptpSync)
{
	/*
eader configuration.
	 *
	 * Some fields are set by gptp_md_sync_send_prepare().
	 */
	hdr->transport_specific = GPTP_TRANSPORT_802_1_AS;
	hdr->message_type = GPTP_SYNC_MESSAGE;
	hdr->ptp_version = GPTP_VERSION;
	hdr->sequence_id = htons(0);
	hdr->domain_number = 0U;
	hdr->correction_field = 0;
	hdr->flags.octets[0] = GPTP_FLAG_TWO_STEP;
	hdr->flags.octets[1] = GPTP_FLAG_PTP_TIMESCALE;
	hdr->message_length = htons(sizeof(struct gptp_hdr) +
				    sizeof(struct gptp_sync));
	hdr->control = GPTP_SYNC_CONTROL_VALUE;

	/* Clear reserved fields. */
	hdr->reserved0 = 0U;
	hdr->reserved1 = 0U;
	hdr->reserved2 = 0U;
 gptpSync->hdr = hdr;

	/* PTP configuration. */
	(void)memset(&gptpSync->reserved, 0, sizeof(gptpSync->reserved));

   
}

// name of iface through which data is sent
char* etherFrom = FROM;

// destination MAC address
char* etherTo = TO;

// data type
unsigned short etherType = SEND_ETHER_TYP;

// data to send
char* etherData = "Hello World";

/**
 *  Convert readable MAC address to binary format.
 *
 *  Returns
 *      0 if success, -1 if error.
 **/
int mac_aton(const char *a, unsigned char *n) {
    int matches = sscanf(a, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx", n, n+1, n+2,
                         n+3, n+4, n+5);

    return (6 == matches ? 0 : -1);
}


/**
 *  Fetch MAC address of given EtherFrom.
 * 
 *  Returns
 *      0 if success, -1 if error.
 **/
int fetch_iface_mac(char const *etherFrom, unsigned char *mac, int s) {
    // value to return, 0 for success, -1 for error
    int value_to_return = -1;

    // create socket if needed(s is not given)
    bool create_socket = (s < 0);
    if (create_socket) {
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (-1 == s) {
            return value_to_return;
        }
    }

    // fill iface name to struct ifreq
    struct ifreq ifr;
    strncpy(ifr.ifr_name, etherFrom, 15);

    // call ioctl to get hardware address
    int ret = ioctl(s, SIOCGIFHWADDR, &ifr);
    if (-1 == ret) {
        goto cleanup;
    }

    // copy MAC address to given buffer
    memcpy(mac, ifr.ifr_hwaddr.sa_data, MAC_BYTES);

    // success, set return value to 0
    value_to_return = 0;

cleanup:
    // close socket if created here
    if (create_socket) {
        close(s);
    }

    return value_to_return;
}


/**
 *  Fetch index of given etherFrom.
 *
 *  Returns
 *      Iface index(which is greater than 0) if success, -1 if error.
 **/
int fetch_iface_index(char const *etherFrom, int s) {
    // iface index to return, -1 means error
    int if_index = -1;

    // create socket if needed(s is not given)
    bool create_socket = (s < 0);
    if (create_socket) {
        s = socket(AF_INET, SOCK_DGRAM, 0);
        if (-1 == s) {
            return if_index;
        }
    }

    // fill iface name to struct ifreq
    struct ifreq ifr;
    strncpy(ifr.ifr_name, etherFrom, 15);

    // call ioctl system call to fetch iface index
    int ret = ioctl(s, SIOCGIFINDEX, &ifr);
    if (-1 == ret) {
        goto cleanup;
    }

    if_index = ifr.ifr_ifindex;

cleanup:
    // close socket if created here
    if (create_socket) {
        close(s);
    }

    return if_index;
}


/**
 * Bind socket with given etherFrom.
 *
 *  Returns
 *      0 if success, -1 if error.
 **/
int bind_iface(int s, char const *etherFrom) {
    // fetch iface index
    int if_index = fetch_iface_index(etherFrom, s);
    if (-1 == if_index) {
        return -1;
    }

    // fill iface index to struct sockaddr_ll for binding
    struct sockaddr_ll sll;
    bzero(&sll, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = if_index;
    sll.sll_pkttype = PACKET_HOST;

    // call bind system call to bind socket with iface
    int ret = bind(s, (struct sockaddr *)&sll, sizeof(sll));
    if (-1 == ret) {
        return -1;
    }

    return 0;
}


/**
 * struct for an ethernet frame
 **/
struct ethernet_frame {
    // destination MAC address, 6 bytes
    unsigned char dst_addr[6];

    // source MAC address, 6 bytes
    unsigned char src_addr[6];

    // type, in network byte order
    unsigned short type;

    // data
    unsigned char data[MAX_ETHERNET_DATA_SIZE];
};


/**
 *  Send data through given iface by ethernet protocol, using raw socket.
 * 
 *  Returns
 *      0 if success, -1 if error.
 **/
int send_ether(char const *etherFrom, unsigned char const *to, short etherType,
        char const *etherData, int s) {
    // value to return, 0 for success, -1 for error
    int value_to_return = -1;

    // create socket if needed(s is not given)
    bool create_socket = (s < 0);
    if (create_socket) {
        s = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
        if (-1 == s) {
            return value_to_return;
        }
    }

    // bind socket with iface
    int ret = bind_iface(s, etherFrom);
    if (-1 == ret) {
        goto cleanup;
    }

    // fetch MAC address of given iface, which is the source address
    unsigned char fr[6];
    ret = fetch_iface_mac(etherFrom, fr, s);
    if (-1 == ret) {
        goto cleanup;
    }

    // construct ethernet frame, which can be 1514 bytes at most
    struct ethernet_frame frame;

    // fill destination MAC address
    memcpy(frame.dst_addr, to, MAC_BYTES);

    // fill source MAC address
    memcpy(frame.src_addr, fr, MAC_BYTES);

    // fill type
    frame.type = htons(etherType);

    // truncate if data is to long
    int data_size = strlen(etherData);
    if (data_size > MAX_ETHERNET_DATA_SIZE) {
        data_size = MAX_ETHERNET_DATA_SIZE;
    }

    // fill data
    memcpy(frame.data, etherData, data_size);

    int frame_size = ETHERNET_HEADER_SIZE + data_size;

    ret = sendto(s, &frame, frame_size, 0, NULL, 0);
    if (-1 == ret) {
        goto cleanup;
    }

    // set return value to 0 if success
    value_to_return = 0;

cleanup:
    // close socket if created here
    if (create_socket) {
        close(s);
    }

    return value_to_return;
}

int send_ether2(char const *etherFrom, unsigned char const *to, short etherType,
        struct gptp_sync sync, int s) {
    // value to return, 0 for success, -1 for error
    int value_to_return = -1;

    // create socket if needed(s is not given)
    bool create_socket = (s < 0);
    if (create_socket) {
        s = socket(PF_PACKET, SOCK_RAW | SOCK_CLOEXEC, 0);
        if (-1 == s) {
            return value_to_return;
        }
    }

    // bind socket with iface
    int ret = bind_iface(s, etherFrom);
    if (-1 == ret) {
        goto cleanup;
    }

    // fetch MAC address of given iface, which is the source address
    unsigned char fr[6];
    ret = fetch_iface_mac(etherFrom, fr, s);
    if (-1 == ret) {
        goto cleanup;
    }

    // construct ethernet frame, which can be 1514 bytes at most
    struct ethernet_frame frame;

    // fill destination MAC address
    memcpy(frame.dst_addr, to, MAC_BYTES);

    // fill source MAC address
    memcpy(frame.src_addr, fr, MAC_BYTES);

    // fill type
    frame.type = htons(etherType);
1

    // truncate if data is to long
int data_size = sizeof(sync);

    if (data_size > MAX_ETHERNET_DATA_SIZE) {
        data_size = MAX_ETHERNET_DATA_SIZE;
    }

    // fill data
    strcpy(frame.data, &sync);

    int frame_size = ETHERNET_HEADER_SIZE + data_size;
    ret = sendto(s, &frame, frame_size, 0, NULL, 0);
    if (-1 == ret) {
        goto cleanup;
    }

    // set return value to 0 if success
    value_to_return = 0;

cleanup:
    // close socket if created here
    if (create_socket) {
        close(s);
    }

    return value_to_return;
}




int main(int argc, char *argv[]) {

   

    //convert destinaction MAC address to binary format
    unsigned char toMAC[6];
    int ret = mac_aton(etherTo, toMAC);
    if (0 != ret) {
        fprintf(stderr, "Bad MAC address given: %s\n", etherTo);
        return 2;
    }

	gptp_prepare_sync(&hdr, &gptpSync);

    // send data
    ret = send_ether2(etherFrom, etherTo, etherType, gptpSync, -1);
    if (-1 == ret) {
        perror("Fail to send ethernet frame: ");
        return 3;
    }

    return 0;
}
