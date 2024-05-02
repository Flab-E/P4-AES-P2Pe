control MyDeparser(
    packet_out      packet,
    in my_headers_t hdr)
{

    apply {
        packet.emit(hdr.ethernet);
        packet.emit(hdr.dh_probe);
        packet.emit(hdr.aes_inout);
    }
}