/*
 * Copyright (C) 2021 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

// The resulting .o needs to load on Android T+
#define NETBPFLOAD_MINAPI_VER NETBPFLOAD_T_VER
#define BPF_OBJ_NAME "dscpPolicy"
#define DEFAULT_BPF_PIN_SUBDIR "net_shared"

#include "bpf_net_helpers.h"
#include "dscpPolicy.h"

#define ECN_MASK 3
#define UPDATE_TOS(dscp, tos) ((dscp) << 2) | ((tos) & ECN_MASK)

// The cache is never read nor written by userspace and is indexed by socket cookie % CACHE_MAP_SIZE
#define CACHE_MAP_SIZE 32  // should be a power of two so we can % cheaply
DEFINE_BPF_MAP_KERNEL_INTERNAL(socket_policy_cache_map, PERCPU_ARRAY, uint32_t, RuleEntry,
                               CACHE_MAP_SIZE)

DEFINE_BPF_MAP_GRW(ipv4_dscp_policies_map, ARRAY, uint32_t, DscpPolicy, MAX_POLICIES, AID_SYSTEM)
DEFINE_BPF_MAP_GRW(ipv6_dscp_policies_map, ARRAY, uint32_t, DscpPolicy, MAX_POLICIES, AID_SYSTEM)

function uint64_t calculate_u64(uint64_t v) {
    COMPILER_FORCE_CALCULATION(v);
    return v;
}

struct compute_ctx {
    uint64_t best_score;
    RuleEntry e;
};

procedure long compute(__unused const void *map,
                       __unused const uint32_t *key,
                       DscpPolicy *policy,
                       void *ctx_) {
    struct compute_ctx *ctx = ctx_;

    // Think of 'nomatch' as a 64-bit boolean: false iff zero, true iff non-zero.
    // Start off with nomatch being false, ie. we assume things *are* matching.
    uint64_t nomatch = 0;

    // Due to 'a ^ b' being 0 iff a == b:
    //   nomatch |= a ^ b
    // should/can be read as:
    //   nomatch ||= (a != b)
    // which you can also think of as:
    //   match &&= (a == b)

    // If policy iface index does not match skb, then skip to next policy.
    nomatch |= (policy->ifindex ^ ctx->e.ifindex);

    // policy->match_* are normal booleans, and should thus always be 0 or 1,
    // thus you can think of these as:
    //   if (policy->match_foo) match &&= (foo == policy->foo);
    nomatch |= policy->match_proto * (ctx->e.proto ^ policy->proto);
    nomatch |= policy->match_src_ip * v6_not_equal(ctx->e.src_ip, policy->src_ip);
    nomatch |= policy->match_dst_ip * v6_not_equal(ctx->e.dst_ip, policy->dst_ip);
    nomatch |= policy->match_src_port * (ctx->e.src_port ^ policy->src_port);

    // Since these values are u16s (<=63 bits), we can rely on u64 subtraction
    // underflow setting the topmost bit.  Basically, you can think of:
    //   nomatch |= (a - b) >> 63
    // as:
    //   match &&= (a >= b)
    uint64_t dport64 = ctx->e.dst_port;  // dst_port_{start_end} range is inclusive of both ends.
    nomatch |= calculate_u64(dport64 - policy->dst_port_start) >> 63;
    nomatch |= calculate_u64(policy->dst_port_end - dport64) >> 63;

    // score is 0x10000 for each matched field (proto, src_ip, dst_ip, src_port)
    // plus 1..0x10000 for the dst_port range match (smaller for bigger ranges)
    uint64_t score = 0;
    score += policy->match_proto;  // reminder: match_* are boolean, thus 0 or 1
    score += policy->match_src_ip;
    score += policy->match_dst_ip;
    score += policy->match_src_port;
    score += 1;  // for a 1 element dst_port_{start,end} range
    score <<= 16;  // scale up: ie. *= 0x10000
    // now reduce score if the dst_port range is more than a single element
    // we want to prioritize (ie. better score) matches of smaller ranges
    score -= (policy->dst_port_end - policy->dst_port_start);  // -= 0..0xFFFF

    // Here we need:
    //   match &&= (score > best_score)
    // which is the same as
    //   match &&= (score >= best_score + 1)
    // > not >= because we want equal score matches to prefer choosing earlier policies
    nomatch |= calculate_u64(score - ctx->best_score - 1) >> 63;

    COMPILER_FORCE_CALCULATION(nomatch);
    if (nomatch) return 0;

    // only reachable if we matched the policy and (score > best_score)
    ctx->best_score = score;
    ctx->e.dscp_val = policy->dscp_val;
    return 0;
}

function void match_policy(struct __sk_buff* skb, const bool ipv4) {
    void* data = (void*)(long)skb->data;
    const void* data_end = (void*)(long)skb->data_end;

    const int l2_header_size = sizeof(struct ethhdr);
    struct ethhdr* eth = data;

    if (data + l2_header_size > data_end) return;

    int hdr_size = 0;

    // used for map lookup
    uint64_t cookie = bpf_get_socket_cookie(skb);
    if (!cookie) return;

    uint32_t cacheid = cookie % CACHE_MAP_SIZE;

    __be16 sport = 0;
    uint16_t dport = 0;
    uint8_t protocol = 0;  // TODO: Use are reserved value? Or int (-1) and cast to uint below?
    struct in6_addr src_ip = {};
    struct in6_addr dst_ip = {};
    uint8_t tos = 0;            // Only used for IPv4
    __be32 old_first_be32 = 0;  // Only used for IPv6
    if (ipv4) {
        const struct iphdr* const iph = (void*)(eth + 1);
        hdr_size = l2_header_size + sizeof(struct iphdr);
        // Must have ipv4 header
        if (data + hdr_size > data_end) return;

        // IP version must be 4
        if (iph->version != 4) return;

        // We cannot handle IP options, just standard 20 byte == 5 dword minimal IPv4 header
        if (iph->ihl != 5) return;

        // V4 mapped address in in6_addr sets 10/11 position to 0xff.
        src_ip.s6_addr32[2] = htonl(0x0000ffff);
        dst_ip.s6_addr32[2] = htonl(0x0000ffff);

        // Copy IPv4 address into in6_addr for easy comparison below.
        src_ip.s6_addr32[3] = iph->saddr;
        dst_ip.s6_addr32[3] = iph->daddr;
        protocol = iph->protocol;
        tos = iph->tos;
    } else {
        struct ipv6hdr* ip6h = (void*)(eth + 1);
        hdr_size = l2_header_size + sizeof(struct ipv6hdr);
        // Must have ipv6 header
        if (data + hdr_size > data_end) return;

        if (ip6h->version != 6) return;

        src_ip = ip6h->saddr;
        dst_ip = ip6h->daddr;
        protocol = ip6h->nexthdr;
        old_first_be32 = *(__be32*)ip6h;
    }

    switch (protocol) {
        case IPPROTO_UDP:
        case IPPROTO_UDPLITE: {
            struct udphdr* udp;
            udp = data + hdr_size;
            if ((void*)(udp + 1) > data_end) return;
            sport = udp->source;
            dport = ntohs(udp->dest);
        } break;
        case IPPROTO_TCP: {
            struct tcphdr* tcp;
            tcp = data + hdr_size;
            if ((void*)(tcp + 1) > data_end) return;
            sport = tcp->source;
            dport = ntohs(tcp->dest);
        } break;
        default:
            return;
    }

    // this array lookup cannot actually fail
    RuleEntry* existing_rule = bpf_socket_policy_cache_map_lookup_elem(&cacheid);

    if (!existing_rule) return; // impossible

    uint64_t nomatch = 0;
    nomatch |= v6_not_equal(src_ip, existing_rule->src_ip);
    nomatch |= v6_not_equal(dst_ip, existing_rule->dst_ip);
    nomatch |= (skb->ifindex ^ existing_rule->ifindex);
    nomatch |= (sport ^ existing_rule->src_port);
    nomatch |= (dport ^ existing_rule->dst_port);
    nomatch |= (protocol ^ existing_rule->proto);
    COMPILER_FORCE_CALCULATION(nomatch);

    /*
     * After the above funky bitwise arithmetic we have 'nomatch == 0' iff
     *   src_ip == existing_rule->src_ip &&
     *   dst_ip == existing_rule->dst_ip &&
     *   skb->ifindex == existing_rule->ifindex &&
     *   sport == existing_rule->src_port &&
     *   dport == existing_rule->dst_port &&
     *   protocol == existing_rule->proto
     */

    if (!nomatch) {
        if (existing_rule->dscp_val < 0) return;  // cached no-op

        if (ipv4) {
            uint8_t newTos = UPDATE_TOS(existing_rule->dscp_val, tos);
            bpf_l3_csum_replace(skb, l2_header_size + IP4_OFFSET(check), htons(tos), htons(newTos),
                                sizeof(uint16_t));
            bpf_skb_store_bytes(skb, l2_header_size + IP4_OFFSET(tos), &newTos, sizeof(newTos), 0);
        } else {
            __be32 new_first_be32 =
                htonl(ntohl(old_first_be32) & 0xF03FFFFF | (existing_rule->dscp_val << 22));
            bpf_skb_store_bytes(skb, l2_header_size, &new_first_be32, sizeof(__be32),
                BPF_F_RECOMPUTE_CSUM);
        }
        return;  // cached DSCP mutation
    }

    struct compute_ctx ctx = {
        .best_score = 0,
        .e.src_ip = src_ip,
        .e.dst_ip = dst_ip,
        .e.ifindex = skb->ifindex,
        .e.src_port = sport,
        .e.dst_port = dport,
        .e.proto = protocol,
        .e.dscp_val = -1,  // meaning no mutation
    };

#ifdef BPF_USE_FUNCS
    // Linear scan ipv?_dscp_policies_map since stored params didn't match skb.
    if (ipv4) {
        bpf_for_each_ipv4_dscp_policies_map_elem(compute, &ctx);
    } else {
        bpf_for_each_ipv6_dscp_policies_map_elem(compute, &ctx);
    }
#else
    for (register uint64_t i = 0; i < MAX_POLICIES; i++) {
        // Using a uint64 in for loop prevents infinite loop during BPF load,
        // but the key is uint32, so convert back.
        uint32_t key = i;

        DscpPolicy* policy;
        if (ipv4) {
            policy = bpf_ipv4_dscp_policies_map_lookup_elem(&key);
        } else {
            policy = bpf_ipv6_dscp_policies_map_lookup_elem(&key);
        }

        // Lookup failure cannot happen on an array with MAX_POLICIES entries.
        // While 'continue' would make logical sense here, 'return' should be
        // easier for the verifier to analyze.
        if (!policy) return;

        if (compute(NULL, &key, policy, &ctx)) break;
    }
#endif

    // Update cache with found policy.
    *existing_rule = ctx.e;

    if (ctx.e.dscp_val < 0) return;  // no mutation

    // Need to store bytes after updating map or program will not load.
    if (ipv4) {
        uint8_t new_tos = UPDATE_TOS(ctx.e.dscp_val, tos);
        bpf_l3_csum_replace(skb, l2_header_size + IP4_OFFSET(check), htons(tos), htons(new_tos), 2);
        bpf_skb_store_bytes(skb, l2_header_size + IP4_OFFSET(tos), &new_tos, sizeof(new_tos), 0);
    } else {
        __be32 new_first_be32 = htonl(ntohl(old_first_be32) & 0xF03FFFFF | (ctx.e.dscp_val << 22));
        bpf_skb_store_bytes(skb, l2_header_size, &new_first_be32, sizeof(__be32),
            BPF_F_RECOMPUTE_CSUM);
    }
    return;
}

// Unsurprisingly this is attached to 'tc egress' - see DscpPolicyTracker.java's attachProgram()
// which calls tcFilterAddDevBpf(..., ingress = false, ...)
//
// In spite of that skb->pkt_type that we observe here *is* PACKET_HOST (0) and not the expected
// PACKET_OUTGOING (4).
//
// This is likely a Linux kernel bug, as 0 is the default, and PACKET_OUTGOING appears to be
// set ONLY in dev_queue_xmit_nit() on skb2 post-clone - ie. on ptype delivered packets
// (ie. AF_PACKET/tcpdump on egress) and not on the core packet itself.
DEFINE_BPF_PROG_KVER(schedcls, set_dscp_ether, AID_SYSTEM, 5_15)
(struct __sk_buff* skb) {
    if (skb->protocol == htons(ETH_P_IP)) {
        match_policy(skb, true);
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        match_policy(skb, false);
    }

    // Always return TC_ACT_PIPE
    return TC_ACT_PIPE;
}

// Require the complete existing policy matcher on the downstream backport contract.
DEFINE_BPF_PROG_EXT(schedcls, set_dscp_ether, AID_ROOT, AID_SYSTEM,
                    4_14, 4_19, 26Q2, 26Q3, MANDATORY,
                    DEFAULT_BPF_MAP_SELINUX_CONTEXT, DEFAULT_BPF_PIN_SUBDIR)
(struct __sk_buff* skb) {
    if (skb->protocol == htons(ETH_P_IP)) {
        match_policy(skb, true);
    } else if (skb->protocol == htons(ETH_P_IPV6)) {
        match_policy(skb, false);
    }

    return TC_ACT_PIPE;
}

LICENSE("Apache 2.0");
