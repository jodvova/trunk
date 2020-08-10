
#include <tins/tins.h>
#include <tins/memory_helpers.h>
#include <tins/utils/checksum_utils.h>

#include <iostream>
#include <chrono>
#include <thread>

using namespace Tins;
using std::memset;
using Tins::Memory::OutputMemoryStream;

static const char* igmp_join_ip = "224.0.0.22";
static const HWAddress<6> igmp_join_mac("01:00:5e:00:00:16");

// static const char* igmp_leave_group = "224.0.0.2";
static const HWAddress<6> igmp_leave_mac("01:00:5e:00:00:02");

class TINS_API IGMP : public PDU {
public:

    typedef IPv4Address address_type;

    enum Flags {
        MEMBERSHIP_QUERY = 0x11,
        IGMPv1_REPORT = 0x12,
        IGMPv2_REPORT = 0x16,
        IGMPv3_REPORT = 0x22,
        LEAVE_GROUP = 0x17
    };

    enum RecordType
    {
        MODE_IS_INCLUDE = 1,
        MODE_IS_EXCLUDE = 2,
        CHANGE_TO_INCLUDE_MODE = 3,
        CHANGE_TO_EXCLUDE_MODE = 4,
        ALLOW_NEW_SOURCES = 5,
        BLOCK_OLD_SOURCES = 6
    };

    IGMP()
    {
        memset(&header_, 0, sizeof(igmpv3_header));
    }

    IGMP(std::initializer_list<std::pair<RecordType, address_type>> groups)
    {
        memset(&header_, 0, sizeof(igmpv3_header));
        header_.type = IGMPv3_REPORT;

        uint32_t i = 0;
        for (auto kv: groups)
        {
            header_.records[i].type = kv.first;
            header_.records[i].ip = kv.second;
            ++i;
        }
        header_.no_records = htons(i);
    }

    PDUType pdu_type() const { return PDU::IGMP; }

    uint32_t header_size() const
    {
        return sizeof(igmpv3_header);
    }

    IGMP* clone() const { return new IGMP(*this); }

private:

    TINS_BEGIN_PACK
    struct igmpv3_header {
        uint16_t type : 8;
        uint16_t : 8;
        uint16_t check;
        uint32_t : 16;
        uint32_t no_records : 16;

        // record
        struct record
        {
            uint8_t type;
            uint8_t aux_len;
            uint16_t no_sources;
            uint32_t ip;
        };
        record records[1];

    } TINS_END_PACK;

    void write_serialization(uint8_t* buffer, uint32_t total_sz)
    {
        OutputMemoryStream stream(buffer, total_sz);
        // Write the header using checksum 0
        header_.check = 0;
        stream.write(header_);
        
        // Calculate checksum and write them on the serialized header
        header_.check = ~Utils::sum_range(buffer, buffer + total_sz);
        memcpy(buffer + 2, &header_.check, sizeof(uint16_t));
    }

    igmpv3_header header_;
};

int main()
{
    NetworkInterface iface("eth0"); 
    PacketSender sender;

    for (int i = 0; i < 10; ++i)
    {
        EthernetII pkt = EthernetII(igmp_join_mac, iface.hw_address()) / IP(igmp_join_ip, "192.168.1.11") 
            / IGMP({{IGMP::RecordType::CHANGE_TO_EXCLUDE_MODE, "224.1.1.1"}});
        pkt.rfind_pdu<IP>().flags(IP::DONT_FRAGMENT);
        pkt.rfind_pdu<IP>().tos(0xc0);
        sender.send(pkt, iface);

        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    std::cout << "test" << std::endl;
    return 0;
}