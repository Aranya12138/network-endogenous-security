/*
 * 课堂接口示例：目的网关的状态声明。
 * 本文件是片段，放在 MyIngress 内部，不是独立 P4 程序。
 */
#define STATE_SLOTS 1024
#define MODE_COUNTER_SLOTS 5

register<bit<32>>(STATE_SLOTS) seq_tag;
register<bit<32>>(STATE_SLOTS) crc_candidate_1;
register<bit<32>>(STATE_SLOTS) crc_candidate_2;
register<bit<8>>(STATE_SLOTS) mode_candidate_1;
register<bit<8>>(STATE_SLOTS) mode_candidate_2;
register<bit<8>>(STATE_SLOTS) seen_modes;
register<bit<2>>(STATE_SLOTS) candidate_counts;
register<bit<1>>(STATE_SLOTS) decided;
register<bit<32>>(STATE_SLOTS) decided_crc;

counter(MODE_COUNTER_SLOTS, CounterType.packets) good_count;
counter(MODE_COUNTER_SLOTS, CounterType.packets) bad_count;
counter(1, CounterType.packets) no_majority_count;

