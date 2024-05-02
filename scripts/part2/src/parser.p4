#include "headers.p4"

#define ETHERTYPE_AES_TOY 0x9999
#define TYPE_PROBE 0x812

parser MyParser(
    packet_in             packet,
    out   my_headers_t    hdr,
    inout my_metadata_t   meta,
    inout standard_metadata_t standard_metadata)
{
    state start {
        packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType) {
           ETHERTYPE_AES_TOY    : parse_aes;
           TYPE_PROBE           : parse_dh_probe;
           default              : accept;
        }
    }

    state parse_aes {
        packet.extract(hdr.aes_inout);
        transition accept;
    }

    state parse_dh_probe {
        packet.extract(hdr.dh_probe.next);
        transition accept;
    }
}
