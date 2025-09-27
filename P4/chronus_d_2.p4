/* -*- P4_16 -*- */
#include<core.p4>
#if __TARGET_TOFINO__ == 2
#include<t2na.p4>
#else
#include<tna.p4>
#endif

#define CNUM 4096
#define BNUM 2048

#define OUTTIME 10000

const bit<16> TYPE_IPV4 = 0x800;

/*************************************************************************
*********************** H E A D E R S  ***********************************
*************************************************************************/

typedef bit<9>  egressSpec_t;
typedef bit<48> macAddr_t;
typedef bit<32> ip4Addr_t;

header ethernet_t {
    macAddr_t dstAddr;
    macAddr_t srcAddr;
    bit<16>   etherType;
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
    ip4Addr_t srcAddr;
    ip4Addr_t dstAddr;
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

struct egress_headers_t {}
struct egress_metadata_t {}

header my_record_h {
	bit<32> index;
	bit<32> sketch_index;
	bit<16> rtt_inc;
	bit<32> reg_time;
	bit<16> fp;
	bit<16> time_diff;
	bit<8>  resubmit_tag;
	bit<8> min_row;
	bit<32> min_reg_cnt;
}

struct metadata{
	bit<32> reg_cnt;
	bit<32> reg_diff;
	bit<8>  enter_sketch;
	bit<8> src1_tag;
	bit<8> dst1_tag;
	bit<8> term1;
	bit<8> flag;
	bit<8> flag2;
	bit<8> src2_tag;
	bit<8> dst2_tag;
	bit<8> term2;

	bit<16> time_diff2;

    bit<16> rng;
    bit<32> cond;
}

struct headers {
    ethernet_t   ethernet;
    ipv4_t       ipv4;
    tcp_t        tcp;
	my_record_h myrecord;
}

/*************************************************************************
*********************** P A R S E R  ***********************************
*************************************************************************/

parser MyParser(packet_in packet,
                out headers hdr,
                out metadata meta,
                out ingress_intrinsic_metadata_t ig_intr_md) {

    state start {
		packet.extract(ig_intr_md);
		packet.advance(PORT_METADATA_SIZE);
		transition parse_ethernet;
    }
	
	state parse_ethernet {
		packet.extract(hdr.ethernet);
        transition select(hdr.ethernet.etherType){
            TYPE_IPV4: parse_ipv4;
            default: accept;
        }
	}
	
    state parse_ipv4 {
        packet.extract(hdr.ipv4);
        transition select(hdr.ipv4.protocol)
        {
            (bit<8>) 6 : parse_tcp;
            default : accept;
        }
    }

	state parse_tcp {
		packet.extract(hdr.tcp);
		transition select(ig_intr_md.resubmit_flag) {
			0: parse_origin;
			1: parse_resubmit;
		}
	}

	state parse_origin {
		hdr.myrecord.setValid();
		hdr.myrecord.rtt_inc = 0;
		transition accept;
	}
	
	state parse_resubmit {
		packet.extract(hdr.myrecord);
		transition accept;
	}
}

/*************************************************************************
**************  I N G R E S S   P R O C E S S I N G   *******************
*************************************************************************/

control MyIngress(inout headers hdr,
                  inout metadata meta,
                  in ingress_intrinsic_metadata_t ig_intr_md,
				  in ingress_intrinsic_metadata_from_parser_t ig_prsr_md,
				  inout ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md,
				  inout ingress_intrinsic_metadata_for_tm_t ig_tm_md
					) {
					
	CRCPolynomial<bit<32>>(coeff=0x04C11DB7,reversed=true, msb=false, extended=false, init=0xFFFFFFFF, xor=0xFFFFFFFF) crc_stage1;
	Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc_stage1) hash_stage1;	
	CRCPolynomial<bit<32>>(coeff=0xF23D4780,reversed=true, msb=false, extended=false, init=0xFFFFFFFF, xor=0xFFFFFFFF) crc_stage2;
	Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc_stage2) hash_stage2;	
	Register<bit<16>, bit<32>>(CNUM) stage1_FP;
	Register<bit<32>, bit<32>>(CNUM) stage1_ACK;
	Register<bit<32>, bit<32>>(CNUM) stage1_time; // Can be processed into uint32 by calculating time-start
	
	action ac_get_fingerprint() {
		hdr.myrecord.fp = (bit<16>) hash_stage1.get({hdr.ipv4.srcAddr, hdr.ipv4.dstAddr})[15:0];
	}
	
	table tb_get_fingerprint {
		actions = {
			ac_get_fingerprint;
		}
		size = 1;
		default_action = ac_get_fingerprint;
	}
	
	action ac_get_index() {
		hdr.myrecord.index = (bit<32>) hash_stage2.get({hdr.ipv4.srcAddr, hdr.ipv4.dstAddr})[11:0];
	}
	
	table tb_get_index{
		actions = {
			ac_get_index;
		}
		size = 1;
		const default_action = ac_get_index;
	}
	
	RegisterAction<bit<16>, bit<32>, bit<16>>(stage1_FP) stage1_FP_update_value = {
		void apply(inout bit<16> register_data, out bit<16> result) {
			if (register_data == 0) {
				register_data = hdr.myrecord.fp;
				result = 0x0;
			} else {
				if (register_data == hdr.myrecord.fp) {
					result = 0x0;
				} else {
					result = 0x1; // resubmit
				}
			}
		}
	};
	
	action ac_stage1_FP_update() {
		meta.flag = (bit<8>) stage1_FP_update_value.execute(hdr.myrecord.index);
	}
	
	table tb_stage1_FP_update {
		actions = {
			ac_stage1_FP_update;
		}
		size = 1;
		const default_action = ac_stage1_FP_update;
	}
	
	RegisterAction<bit<32>, bit<32>, bit<32>>(stage1_ACK) stage1_ACK_update_value = {
		void apply(inout bit<32> register_data, out bit<32> result) {
			if (register_data == hdr.tcp.seqNo) {
				result = 0x1;
			} else {
				result = 0x2;
			}
			register_data = hdr.tcp.ackNo;
		}
	};
	
	action ac_stage1_ACK_update() {
		meta.flag2 = (bit<8>) stage1_ACK_update_value.execute(hdr.myrecord.index);
	}
	
	action ac_set_resubmit_tag () {
		hdr.myrecord.resubmit_tag = 1;
	}

	table tb_stage1_ACK_update {
		key = {
			meta.flag : exact;
		}
		actions = {
			ac_stage1_ACK_update;
			ac_set_resubmit_tag;
			NoAction;
		}
		size = 8;
		const default_action = NoAction;
		const entries = {
			0 : ac_stage1_ACK_update;
			1 : ac_set_resubmit_tag;
		}
	}
	
	RegisterAction<bit<32>, bit<32>, bit<32>>(stage1_time) stage1_time_update_value = {
		void apply(inout bit<32> register_data, out bit<32> result) {
			result = register_data;
			if (meta.flag == 0) {
				register_data = ig_prsr_md.global_tstamp[31:0];
			} else {
				register_data = register_data;
			}
		}
	};
	
	action ac_stage1_time_update() {
		hdr.myrecord.reg_time = stage1_time_update_value.execute(hdr.myrecord.index);
	}
	
	table tb_stage1_time_update {
		actions = {
			ac_stage1_time_update;
		}
		size = 1;
		const default_action = ac_stage1_time_update;
	}
	
	action ac_get_time_diff() {
		hdr.myrecord.time_diff = (bit<16>) (ig_prsr_md.global_tstamp[31:0] - hdr.myrecord.reg_time);
	}

	table tb_get_time_diff {
		actions = {
			ac_get_time_diff;
		}
		size = 1;
		const default_action = ac_get_time_diff;
	}

	action ac_get_rtt_inc() {
		hdr.myrecord.rtt_inc = hdr.myrecord.time_diff;
	}

	action ac_set_rtt_zero() {
		hdr.myrecord.rtt_inc = 0;
	}

	table tb_get_rtt_inc {
		key = {
			hdr.myrecord.time_diff : range;
		}
		actions = {
			ac_get_rtt_inc;
			ac_set_rtt_zero;
			NoAction;
		}
		size = 8;
		const default_action = ac_set_rtt_zero;
		const entries = {
			OUTTIME..65535 : ac_get_rtt_inc;
		}
	}

	CRCPolynomial<bit<32>>(coeff=0x8164DDC2,reversed=true, msb=false, extended=false, init=0xFFFFFFFF, xor=0xFFFFFFFF) crc_stage3;
	Hash<bit<32>>(HashAlgorithm_t.CUSTOM, crc_stage3) hash_stage3;
	
	action ac_get_sketch_index() {
		hdr.myrecord.sketch_index = (bit<32>) hash_stage3.get({hdr.ipv4.srcAddr, hdr.ipv4.dstAddr})[10:0];
	}
	
	table tb_get_sketch_index{
		actions = {
			ac_get_sketch_index;
		}
		size = 1;
		const default_action = ac_get_sketch_index;
	}


	Register<bit<32>, bit<32>>(BNUM) stage2_src1;
	Register<bit<32>, bit<32>>(BNUM) stage2_dst1;
	Register<bit<32>, bit<32>>(BNUM) stage2_cnt1;
	
	RegisterAction<bit<32>, bit<32>, bit<32>>(stage2_src1) stage2_src1_read = {
		void apply(inout bit<32> register_data, out bit<32> result) {
			if (hdr.ipv4.srcAddr == register_data) {
				result = 0x1;
			} else {
				result = 0x0;
			}
		}
	};
	
	action ac_stage2_src1_read() {
		meta.src1_tag = (bit<8>) stage2_src1_read.execute(hdr.myrecord.sketch_index);
	}
	
	table tb_stage2_src1_read {
		actions = {
			ac_stage2_src1_read;
		}
		size = 1;
		const default_action = ac_stage2_src1_read;
	}
	
	RegisterAction<bit<32>, bit<32>, bit<32>>(stage2_dst1) stage2_dst1_read = {
		void apply(inout bit<32> register_data, out bit<32> result) {
			if (hdr.ipv4.dstAddr == register_data) {
				result = 0x1;
			} else {
				result = 0x0;
			}
		}
	};
	
	action ac_stage2_dst1_read() {
		meta.dst1_tag = (bit<8>) stage2_dst1_read.execute(hdr.myrecord.sketch_index);
	}
	
	table tb_stage2_dst1_read {
		actions = {
			ac_stage2_dst1_read;
		}
		size = 1;
		const default_action = ac_stage2_dst1_read;
	}
	
	action ac_set_term1() {
		meta.term1 = 0x1;
	}
	
	table tb_set_term1 {
		key = {
			meta.src1_tag : exact;
			meta.dst1_tag : exact;
		}
		actions = {
			ac_set_term1;
			NoAction;
		}
		const default_action = NoAction;
		const entries = {
			(1, 1) : ac_set_term1;
		}
	}
	
	RegisterAction<bit<32>, bit<32>, bit<32>>(stage2_cnt1) stage2_cnt1_read = {
		void apply(inout bit<32> register_data, out bit<32> result) {
			result = register_data;
			if (meta.term1 == 1) {
				register_data = register_data + (bit<32>)hdr.myrecord.rtt_inc;
			}
		}
	};
	
	action ac_stage2_cnt1_read() {
		hdr.myrecord.min_reg_cnt = stage2_cnt1_read.execute(hdr.myrecord.sketch_index);
	}
	
	table tb_stage2_cnt1_read {
		actions = {
			ac_stage2_cnt1_read;
		}
		size = 1;
		const default_action = ac_stage2_cnt1_read;
	}

	action ac_set_min_row() {
		hdr.myrecord.min_row = 1;
	}

	table tb_set_min_row {
		actions = {
			ac_set_min_row;
		}
		size = 1;
		const default_action = ac_set_min_row;
	}

	Register<bit<32>, bit<32>>(BNUM) stage2_src2;
	Register<bit<32>, bit<32>>(BNUM) stage2_dst2;
	Register<bit<32>, bit<32>>(BNUM) stage2_cnt2;
	
	RegisterAction<bit<32>, bit<32>, bit<32>>(stage2_src2) stage2_src2_read = {
		void apply(inout bit<32> register_data, out bit<32> result) {
			if (hdr.ipv4.srcAddr == register_data) {
				result = 0x1;
			} else {
				result = 0x0;
			}
		}
	};
	
	action ac_stage2_src2_read() {
		meta.src2_tag = (bit<8>) stage2_src2_read.execute(hdr.myrecord.sketch_index);
	}
	
	table tb_stage2_src2_read {
		actions = {
			ac_stage2_src2_read;
		}
		size = 1;
		const default_action = ac_stage2_src2_read;
	}
	
	RegisterAction<bit<32>, bit<32>, bit<32>>(stage2_dst2) stage2_dst2_read = {
		void apply(inout bit<32> register_data, out bit<32> result) {
			if (hdr.ipv4.dstAddr == register_data) {
				result = 0x1;
			} else {
				result = 0x0;
			}
		}
	};
	
	action ac_stage2_dst2_read() {
		meta.dst2_tag = (bit<8>) stage2_dst2_read.execute(hdr.myrecord.sketch_index);
	}
	
	table tb_stage2_dst2_read {
		actions = {
			ac_stage2_dst2_read;
		}
		size = 1;
		const default_action = ac_stage2_dst2_read;
	}
	
	action ac_set_term2() {
		meta.term2 = 0x1;
	}
	
	table tb_set_term2 {
		key = {
			meta.src2_tag : exact;
			meta.dst2_tag : exact;
		}
		actions = {
			ac_set_term2;
			NoAction;
		}
		const default_action = NoAction;
		const entries = {
			(1, 1) : ac_set_term2;
		}
	}
	
	RegisterAction<bit<32>, bit<32>, bit<32>>(stage2_cnt2) stage2_cnt2_read = {
		void apply(inout bit<32> register_data, out bit<32> result) {
			result = register_data;
			if (meta.term2 == 1) {
				register_data = register_data + (bit<32>) hdr.myrecord.rtt_inc;
			}
		}
	};
	
	action ac_stage2_cnt2_read() {
		meta.reg_cnt = (bit<32>) stage2_cnt2_read.execute(hdr.myrecord.sketch_index);
	}
	
	table tb_stage2_cnt2_read {
		actions = {
			ac_stage2_cnt2_read;
		}
		size = 1;
		const default_action = ac_stage2_cnt2_read;
	}

	action ac_cal_reg_diff() {
		meta.reg_diff = meta.reg_cnt - hdr.myrecord.min_reg_cnt;
	}

	table tb_cal_reg_diff {
		actions = {
			ac_cal_reg_diff;
		}
		size = 1;
		const default_action = ac_cal_reg_diff;
	}

	action ac_set_min_row2() {
		hdr.myrecord.min_row = 1;
	}

	table tb_set_min_row2 {
		key = {
			meta.term2 : exact;
			meta.reg_diff : ternary;
		}
		actions = {
			ac_set_min_row2;
			NoAction;
		}
		size = 16;
		const default_action = NoAction;
		const entries = {
			(0, 0x80000000 &&& 0x80000000) : ac_set_min_row2;
		}
	}

	action ac_set_resubmit_tag_2() {
		hdr.myrecord.resubmit_tag = 2;
	}

	table tb_set_resubmit_tag2 {
		key = {
			meta.term2 : exact;
		}
		actions = {
			ac_set_resubmit_tag_2;
			NoAction;
		}
		size = 8;
		const default_action = NoAction;
		const entries = {
			0 : ac_set_resubmit_tag_2;
		}
	}

	/*************************RESUBMIT************************/

	action ac_cal_time_diff_resubmit() {
		meta.time_diff2 = (bit<16>) (ig_prsr_md.global_tstamp[31:0] - hdr.myrecord.reg_time);
	}

	table tb_cal_time_diff_resubmit {
		actions = {
			ac_cal_time_diff_resubmit;
		}
		size = 1;
		const default_action = ac_cal_time_diff_resubmit;
	}

	RegisterAction<bit<16>, bit<32>, bit<16>>(stage1_FP) stage1_FP_write = {
		void apply(inout bit<16> register_data, out bit<16> result) {
			register_data = hdr.myrecord.fp;
		}
	};

	action ac_stage1_FP_write() {
		stage1_FP_write.execute(hdr.myrecord.index);
	}

	table tb_stage1_FP_write {
		key = {
			meta.time_diff2 : range;
		}
		actions = {
			ac_stage1_FP_write;
			NoAction;
		}
		size = 8;
		const default_action = NoAction;
		const entries = {
			OUTTIME..65535 : ac_stage1_FP_write;
		}
	}

	RegisterAction<bit<32>, bit<32>, bit<32>>(stage1_ACK) stage1_ACK_write = {
		void apply(inout bit<32> register_data, out bit<32> result) {
			register_data = hdr.tcp.ackNo;
		}
	};

	action ac_stage1_ACK_write() {
		stage1_ACK_write.execute(hdr.myrecord.index);
	}

	table tb_stage1_ACK_write {
		key = {
			meta.time_diff2 : range;
		}
		actions = {
			ac_stage1_ACK_write;
			NoAction;
		}
		size = 8;
		const default_action = NoAction;
		const entries = {
			OUTTIME..65535 : ac_stage1_ACK_write;
		}
	}

	RegisterAction<bit<32>, bit<32>, bit<32>>(stage1_time) stage1_time_write = {
		void apply(inout bit<32> register_data, out bit<32> result) {
			register_data = ig_prsr_md.global_tstamp[31:0];
		}
	};

	action ac_stage1_time_write() {
		stage1_time_write.execute(hdr.myrecord.index);
	}

	table tb_stage1_time_write {
		key = {
			meta.time_diff2 : range;
		}
		actions = {
			ac_stage1_time_write;
			NoAction;
		}
		size = 8;
		const default_action = NoAction;
		const entries = {
			OUTTIME..65535 : ac_stage1_time_write;
		}
	}

	Random<bit<16>>() random_generator;

	action generate_random_number(){
		meta.rng = random_generator.get();
	}

	table random_number_table{
		actions = {
			generate_random_number;
		}
		size = 1;
		const default_action = generate_random_number();
	}

	Register<bit<32>,bit<1>>(1) num_32;

	MathUnit<bit<32>>(true,0,9,{68,73,78,85,93,102,113,128,0,0,0,0,0,0,0,0}) prog_64K_div_mu;

	RegisterAction<bit<32>,bit<1>,bit<32>>(num_32) prog_64K_div_x = {
		void apply(inout bit<32> register_data, out bit<32> mau_value){
			register_data = prog_64K_div_mu.execute(hdr.myrecord.min_reg_cnt);
            mau_value = register_data;
		}
	};
	
	action calc_cond_pre(){
		meta.cond = prog_64K_div_x.execute(0);
	}

	table calc_cond_table_pre{
		actions = {
			calc_cond_pre;
		}
		size = 1;
		const default_action = calc_cond_pre();
	}

	action calc_cond(){
		meta.cond = (bit<32>)meta.rng - meta.cond;
	}

	table calc_cond_table{
		actions = {
			calc_cond;
		}
		size = 1;
		const default_action = calc_cond();
	}

	RegisterAction<bit<32>, bit<32>, bit<32>>(stage2_cnt1) stage2_cnt1_update = {
		void apply(inout bit<32> register_data, out bit<32> result) {
			register_data = register_data + (bit<32>)hdr.myrecord.rtt_inc;
		}
	};

	action ac_stage2_cnt1_update() {
		stage2_cnt1_update.execute(hdr.myrecord.sketch_index);
	}

	table tb_stage2_cnt1_update {
        key = {
            hdr.myrecord.min_row : exact;
        }
		actions = {
			ac_stage2_cnt1_update;
            NoAction;
		}
		size = 8;
		const default_action = NoAction;
        const entries = {
            1 : ac_stage2_cnt1_update;
        }
	}

	RegisterAction<bit<32>, bit<32>, bit<32>>(stage2_src1) stage2_src1_write = {
		void apply(inout bit<32> register_data, out bit<32> result) {
			register_data = hdr.ipv4.srcAddr;
		}
	};

	action ac_stage2_src1_write() {
		stage2_src1_write.execute(hdr.myrecord.sketch_index);
	}

	table tb_stage2_src1_write {
        key = {
            meta.cond : ternary;
            hdr.myrecord.min_row : exact;
        }
		actions = {
			ac_stage2_src1_write;
            NoAction;
		}
		size = 16;
		const default_action = NoAction;
        const entries = {
            (0x00000000 &&& 0xFFFF0000, 1) : ac_stage2_src1_write;
        }
	}

	RegisterAction<bit<32>, bit<32>, bit<32>>(stage2_dst1) stage2_dst1_write = {
		void apply(inout bit<32> register_data, out bit<32> result) {
			register_data = hdr.ipv4.dstAddr;
		}
	};

	action ac_stage2_dst1_write() {
		stage2_dst1_write.execute(hdr.myrecord.sketch_index);
	}

	table tb_stage2_dst1_write {
        key = {
            meta.cond : ternary;
            hdr.myrecord.min_row : exact;
        }
		actions = {
			ac_stage2_dst1_write;
            NoAction;
		}
		size = 16;
		const default_action = NoAction;
        const entries = {
            (0x00000000 &&& 0xFFFF0000, 1) : ac_stage2_dst1_write;
        }
	}

    RegisterAction<bit<32>, bit<32>, bit<32>>(stage2_cnt2) stage2_cnt2_update = {
		void apply(inout bit<32> register_data, out bit<32> result) {
			register_data = register_data + (bit<32>)hdr.myrecord.rtt_inc;
		}
	};

	action ac_stage2_cnt2_update() {
		stage2_cnt2_update.execute(hdr.myrecord.sketch_index);
	}

	table tb_stage2_cnt2_update {
        key = {
            meta.cond : ternary;
            hdr.myrecord.min_row : exact;
        }
		actions = {
			ac_stage2_cnt2_update;
            NoAction;
		}
		size = 8;
		const default_action = NoAction;
        const entries = {
            (0x00000000 &&& 0xFFFF0000, 2) : ac_stage2_cnt2_update;
        }
	}

    RegisterAction<bit<32>, bit<32>, bit<32>>(stage2_src2) stage2_src2_write = {
		void apply(inout bit<32> register_data, out bit<32> result) {
			register_data = hdr.ipv4.srcAddr;
		}
	};

	action ac_stage2_src2_write() {
		stage2_src2_write.execute(hdr.myrecord.sketch_index);
	}

	table tb_stage2_src2_write {
        key = {
            meta.cond : ternary;
            hdr.myrecord.min_row : exact;
        }
		actions = {
			ac_stage2_src2_write;
            NoAction;
		}
		size = 16;
		const default_action = NoAction;
        const entries = {
            (0x00000000 &&& 0xFFFF0000, 2) : ac_stage2_src2_write;
        }
	}

	RegisterAction<bit<32>, bit<32>, bit<32>>(stage2_dst2) stage2_dst2_write = {
		void apply(inout bit<32> register_data, out bit<32> result) {
			register_data = hdr.ipv4.dstAddr;
		}
	};

	action ac_stage2_dst2_write() {
		stage2_dst2_write.execute(hdr.myrecord.sketch_index);
	}

	table tb_stage2_dst2_write {
        key = {
            meta.cond : ternary;
            hdr.myrecord.min_row : exact;
        }
		actions = {
			ac_stage2_dst2_write;
            NoAction;
		}
		size = 16;
		const default_action = NoAction;
        const entries = {
            (0x00000000 &&& 0xFFFF0000, 2) : ac_stage2_dst2_write;
        }
	}

	/*
		Basic forwarding
	*/
    action drop() {
        ig_dprsr_md.drop_ctl = 1;
    }
	
    action ipv4_forward(egressSpec_t port) {
	    ig_tm_md.ucast_egress_port = port;
    }
	
	@pragma stage 0
    table ipv4_lpm {
        key = {
		    hdr.ipv4.dstAddr: lpm;
        }

        actions = {
            ipv4_forward;
            drop;
            NoAction;
        }

        size = 32;

        default_action = NoAction();
    }

    apply {
		if (hdr.ipv4.isValid()){
			if (ig_intr_md.resubmit_flag == 0) {
				tb_get_fingerprint.apply();
				tb_get_index.apply();
				tb_get_sketch_index.apply();
				tb_stage1_FP_update.apply();
				tb_stage1_ACK_update.apply();
				tb_stage1_time_update.apply();
				tb_set_min_row.apply();
				if (hdr.myrecord.resubmit_tag == 0) {
					tb_get_time_diff.apply();
					tb_get_rtt_inc.apply();
					if (hdr.myrecord.rtt_inc != 0) {
						tb_stage2_src1_read.apply();
						tb_stage2_dst1_read.apply();
						tb_set_term1.apply();
						tb_stage2_cnt1_read.apply();
						if (meta.term1 == 0) {
							tb_stage2_src2_read.apply();
							tb_stage2_dst2_read.apply();
							tb_set_term2.apply();
							tb_stage2_cnt2_read.apply();
							tb_cal_reg_diff.apply();
							tb_set_min_row2.apply();
							tb_set_resubmit_tag2.apply();
						}
					}
				}
			} else {
				if (hdr.myrecord.resubmit_tag == 1) {
					tb_cal_time_diff_resubmit.apply();
					tb_stage1_FP_write.apply();
					tb_stage1_ACK_write.apply();
					tb_stage1_time_write.apply();
				} else {
                    random_number_table.apply();
                    calc_cond_table_pre.apply();
    				calc_cond_table.apply();
                    tb_stage2_cnt1_update.apply();
                    tb_stage2_cnt2_update.apply();
                    tb_stage2_src1_write.apply();
					tb_stage2_dst1_write.apply();
				}
                hdr.myrecord.resubmit_tag = 0;
			}
			ipv4_lpm.apply();
		}
	}
}

control IngressDeparser(packet_out packet,
	inout headers hdr,
	in metadata meta,
	in ingress_intrinsic_metadata_for_deparser_t ig_dprsr_md)
{
    Resubmit() resubmit;
	apply{
        if(hdr.myrecord.resubmit_tag == 1) {
			resubmit.emit();
		}
        if(hdr.myrecord.resubmit_tag == 2) {
			resubmit.emit();
		}
		packet.emit(hdr);
	}
}
/*************************************************************************
****************  E G R E S S   P R O C E S S I N G   *******************
*************************************************************************/
parser EgressParser(packet_in packet,
	out egress_headers_t hdr,
	out egress_metadata_t meta,
	out egress_intrinsic_metadata_t eg_intr_md)
{
	state start{
		packet.extract(eg_intr_md);
		transition accept;
	}
}

control Egress(inout egress_headers_t hdr,
				inout egress_metadata_t meta,
				in egress_intrinsic_metadata_t eg_intr_md,
				in egress_intrinsic_metadata_from_parser_t eg_prsr_md,
				inout egress_intrinsic_metadata_for_deparser_t eg_dprsr_md,
				inout egress_intrinsic_metadata_for_output_port_t eg_oport_md) 
{
    apply {  }
}

/*************************************************************************
***********************  D E P A R S E R  *******************************
*************************************************************************/

control EgressDeparser(packet_out packet, 
						inout egress_headers_t hdr, 
						in egress_metadata_t meta, 
						in egress_intrinsic_metadata_for_deparser_t eg_dprsr_md) {
    apply {
        //parsed headers have to be added again into the packet.
		packet.emit(hdr);
    }
}

/*************************************************************************
***********************  S W I T C H  *******************************
*************************************************************************/

//switch architecture
Pipeline(
MyParser(),
MyIngress(),
IngressDeparser(),
EgressParser(),
Egress(),
EgressDeparser()
) pipe;

Switch(pipe) main;