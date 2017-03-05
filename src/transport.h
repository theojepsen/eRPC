/**
 * @file transport.h
 * @brief General definitions for all transport types.
 */
#ifndef ERPC_TRANSPORT_H
#define ERPC_TRANSPORT_H

#include <string>
#include "common.h"
#include "session.h"
#include "transport_types.h"
#include "util/buffer.h"
#include "util/huge_alloc.h"

namespace ERpc {

/// Generic mostly-reliable transport
class Transport {
 public:
  // Queue depths
  static const size_t kRecvQueueDepth = 2048;  ///< RECV queue size
  static const size_t kSendQueueDepth = 128;   ///< SEND queue size

  static_assert(is_power_of_two<size_t>(kRecvQueueDepth), "");
  static_assert(is_power_of_two<size_t>(kSendQueueDepth), "");

  Transport(TransportType transport_type, uint8_t app_tid, uint8_t phy_port);

  /**
   * @brief Initialize transport structures that require hugepages
   * @throw runtime_error if initialization fails. This exception is caught
   * in the parent Rpc, which then deletes \p huge_alloc so we don't need to.
   */
  void init_hugepage_structures(HugeAllocator* huge_alloc);

  /// Initialize the memory registration and deregistratin functions
  void init_mem_reg_funcs();

  ~Transport();

  /**
   * @brief Transmit a batch of packets, and for each packet, update its
   * MsgBuffer's progress tracking information.
   *
   * Multiple packets may belong to the same MsgBuffer. The transport determines
   * the offset of each of these packets by updating the \p data_sent and
   * \p pkts_sent field of the shared MsgBuffer.
   *
   * @param routing_info_arr Per-packet RoutingInfo
   * @param msg_buffer_arr The MsgBuffer for each packet
   * @param num_pkts The total number of packets to transmit (up to kPostlist)
   */
  void tx_burst(RoutingInfo const* const* routing_info_arr,
                MsgBuffer** msg_buffer_arr, size_t num_pkts);

  /**
   * @brief The generic packet reception function
   *
   * This function returns pointers to the transport's RECV DMA ring buffers,
   * so it must not re-post the returned ring buffers to the NIC (because then
   * the NIC could overwrite the buffers while the Rpc layer  is processing
   * them.
   *
   * The Rpc layer controls posting of RECV descriptors explicitly using
   * the post_recvs() function.
   */
  void rx_burst(Buffer* msg_buffer_arr, size_t* num_pkts);

  /// Post RECVs to the receive queue after processing \p rx_burst results
  void post_recvs(size_t num_recvs);

  /// Fill-in local routing information
  void fill_local_routing_info(RoutingInfo* routing_info) const;

  /**
   * @brief Try to resolve routing information received from remote host. (e.g.,
   * for InfiniBand, this involves creating the address handle using the remote
   * port LID.)
   *
   * @return True if resolution succeeds, false otherwise.
   */
  bool resolve_remote_routing_info(RoutingInfo* routing_info) const;

  /// Return a string representation of \p routing_info
  static std::string routing_info_str(RoutingInfo* routing_info);

  // Members that are needed by all transports. Constructor args first.
  const TransportType transport_type;
  const uint8_t app_tid;   /* Debug-only */
  const uint8_t phy_port;  ///< 0-based physical port specified by application

  // Other members
  reg_mr_func_t reg_mr_func;      ///< The memory registration function
  dereg_mr_func_t dereg_mr_func;  ///< The memory deregistration function

  // Members initialized after the hugepage allocator is provided
  HugeAllocator* huge_alloc;  ///< The parent Rpc's hugepage allocator
  size_t numa_node;           ///< Derived from \p huge_alloc
};

}  // End ERpc

#endif  // ERPC_TRANSPORT_H
