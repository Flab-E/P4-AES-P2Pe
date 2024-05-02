// Max entries into the register
#define MAX_KEYS 8

// useful for DH
typedef bit<256> keys_t;
typedef bit<48> macAddr_t;

register<keys_t>(MAX_KEYS) register_pub_keys;
register<keys_t>(MAX_KEYS) register_priv_keys;
register<keys_t>(MAX_KEYS) register_secret_keys;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16> etherType;
}

header ipv4_t {
    bit<4>    version;
    bit<4>    ihl;
    bit<8>    diffserv;
    bit<16>   totalLen;
    bit<16>   identification;
    bit<3>    flags;
    bit<13>   fragOffset;
    bit<8>    ttl;
    bit<8>    protocol;
    bit<16>   hdrChecksum;
    macAddr_t srcAddr;
    macAddr_t dstAddr;
}

header tcp_t{
    bit<16> srcPort;
    bit<16> dstPort;
    bit<32> seqNo;
    bit<32> ackNo;
    bit<4>  dataOffset;
    bit<4>  res;
    bit<1>  cwr;
    bit<1>  ece;
    bit<1>  urg;
    bit<1>  ack;
    bit<1>  psh;
    bit<1>  rst;
    bit<1>  syn;
    bit<1>  fin;
    bit<16> window;
    bit<16> checksum;
    bit<16> urgentPtr;
}

// The data added to the probe by each switch at each hop.
header dh_probe_t {
    bit<256>   public_key;
    // Trere is no need for 8 bytes but header requires multiple of 8 bits.
    bit<8>     flag;  // 0x00 = msg1 / 0x01 = msg2 / 0x02 = msg3 / 0x03 = msg4
}

// We perform one block of AES.
// To perform multiple block using modes like CBC/CTR, etc., simply XOR a counter/IV with value before starting AES.
header aes_inout_t {
    bit<128> value;
}

struct my_headers_t {
    ethernet_t            ethernet;
    aes_inout_t           aes_inout;
    dh_probe_t[MAX_KEYS]  dh_probe;
}

header aes_meta_t {
    // internal state, 4 rows
    bit<32> r0;
    bit<32> r1;
    bit<32> r2;
    bit<32> r3;
    // temporary accumulator, for XOR-ing the result of many LUTs
    bit<32> t0;
    bit<32> t1;
    bit<32> t2;
    bit<32> t3;

    keys_t  reg_pub_key;
    keys_t  reg_priv_key;
    keys_t  reg_secret_key;

    // expanded keys
    bit<128> expandkey_r0;
    bit<128> expandkey_r1;
    bit<128> expandkey_r2;
    bit<128> expandkey_r3;
    bit<128> expandkey_r4;
    bit<128> expandkey_r5;
    bit<128> expandkey_r6;
    bit<128> expandkey_r7;
    bit<128> expandkey_r8;
    bit<128> expandkey_r9;
    bit<128> expandkey_r10;
    bit<128> expandkey_r11;
    bit<128> expandkey_r12;
    bit<128> expandkey_r13;
    bit<128> expandkey_r14;

    // decrypt expanded keys
    bit<128> inv_expandkey_r0;
    bit<128> inv_expandkey_r1;
    bit<128> inv_expandkey_r2;
    bit<128> inv_expandkey_r3;
    bit<128> inv_expandkey_r4;
    bit<128> inv_expandkey_r5;
    bit<128> inv_expandkey_r6;
    bit<128> inv_expandkey_r7;
    bit<128> inv_expandkey_r8;
    bit<128> inv_expandkey_r9;
    bit<128> inv_expandkey_r10;
    bit<128> inv_expandkey_r11;
    bit<128> inv_expandkey_r12;
    bit<128> inv_expandkey_r13;
    bit<128> inv_expandkey_r14;
}

header dh_meta_t {
    bit<256> secrect;
    bit<256> pu;
}
struct my_metadata_t {
    aes_meta_t aes;
    dh_meta_t[MAX_KEYS] dh;
}