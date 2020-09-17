#include "util/latency.h"
#include <gflags/gflags.h>
#include <signal.h>
#include <cstring>
#include "../apps_common.h"
#include "rpc.h"
#include "util/autorun_helpers.h"
#include "util/numautils.h"

#include <object_io.h>
#include <cut_split.h>
#include <tuple_merge.h>
#include <serial_nuevomatch.h>
#include <nuevomatch_config.h>

#define CLASSIFICATION_HEADER_WORDS 3
struct classification_hdr_t {
  uint64_t egr_ts; // switch sends req to server
  uint64_t ingress_mac_tstamp; // switch receives resp from server
  uint32_t trace_idx;
  int32_t match_priority;
  uint64_t headers[CLASSIFICATION_HEADER_WORDS];
} __attribute__((packed));

static constexpr size_t kAppEvLoopMs = 1000;  // Duration of event loop
static constexpr bool kAppVerbose = false;    // Print debug info on datapath
static constexpr double kAppLatFac = 10.0;    // Precision factor for latency

#define USE_SWITCH_TIMESTAMPING false
#if USE_SWITCH_TIMESTAMPING
// XXX If set to 123, the switch will insert timestamps in egr_ts and ingress_mac_tstamp.
static constexpr size_t kAppReqType = 123;    // eRPC request type
#else
static constexpr size_t kAppReqType = 1;      // eRPC request type
#endif

volatile sig_atomic_t ctrl_c_pressed = 0;
void ctrl_c_handler(int) { ctrl_c_pressed = 1; }

class ServerContext : public BasicAppContext {
 public:
  SerialNuevoMatch<1>* classifier;
};

class ClientContext : public BasicAppContext {
 public:
  size_t start_tsc;
  erpc::Latency latency;
  erpc::MsgBuffer req_msgbuf, resp_msgbuf;
  trace_packet* trace_packets;
  uint32_t num_of_packets;
  volatile uint32_t next_trace_idx = 0;
  ~ClientContext() {}
};

void req_handler(erpc::ReqHandle *req_handle, void *_context) {
  auto *c = static_cast<ServerContext *>(_context);

  const auto *req_msgbuf = req_handle->get_req_msgbuf();
  assert(req_msgbuf->get_data_size() == sizeof(struct classification_hdr_t));
  auto *req = reinterpret_cast<const struct classification_hdr_t *>(req_msgbuf->buf);

  auto &resp_msgbuf  = req_handle->pre_resp_msgbuf;
  erpc::Rpc<erpc::CTransport>::resize_msg_buffer(&resp_msgbuf, sizeof(struct classification_hdr_t));
  auto *resp = reinterpret_cast<struct classification_hdr_t *>(resp_msgbuf.buf);

#if 1
  classifier_output_t out = c->classifier->classify((uint32_t*)req->headers);
  resp->match_priority = out.action;
#endif
  resp->trace_idx = req->trace_idx;
  resp->egr_ts = req->egr_ts;
  resp->ingress_mac_tstamp = req->ingress_mac_tstamp;

  c->rpc->enqueue_response(req_handle, &resp_msgbuf);
}

void server_func(erpc::Nexus *nexus) {
  std::vector<size_t> port_vec = flags_get_numa_ports(FLAGS_numa_node);
  uint8_t phy_port = port_vec.at(0);

  ServerContext c;
  erpc::Rpc<erpc::CTransport> rpc(nexus, static_cast<void *>(&c), 0 /* tid */,
                                  basic_sm_handler, phy_port);
  c.rpc = &rpc;

	// Set configuration for NuevoMatch
	NuevoMatchConfig config;
	config.num_of_cores = 1;
	config.max_subsets = 1;
	config.start_from_iset = 0;
	config.disable_isets = false;
	config.disable_remainder = false;
	config.disable_bin_search = false;
	config.disable_validation_phase = false;
	config.disable_all_classification = false;
	//config.force_rebuilding_remainder = true;
	config.force_rebuilding_remainder = false;

	uint32_t binth = 8;
	uint32_t threshold = 25;
  config.remainder_classifier = new CutSplit(binth, threshold);
	config.remainder_type = "cutsplit";

  c.classifier = new SerialNuevoMatch<1>(config);

	// Read classifier file to memory
	ObjectReader classifier_handler("nuevomatch_64.classifier"); // 100K rules
	//ObjectReader classifier_handler("nuevomatch_64_classifier_1krules");
	//ObjectReader classifier_handler("nuevomatch_64_classifier_100rules");
	c.classifier->load(classifier_handler);



  while (true) {
    rpc.run_event_loop(1000);
    if (ctrl_c_pressed == 1) break;
  }
}

void connect_session(ClientContext &c) {
  std::string server_uri = erpc::get_uri_for_process(0);
  printf("Process %zu: Creating session to %s.\n", FLAGS_process_id,
         server_uri.c_str());

  int session_num = c.rpc->create_session(server_uri, 0 /* tid */);
  erpc::rt_assert(session_num >= 0, "Failed to create session");
  c.session_num_vec.push_back(session_num);

  while (c.num_sm_resps != 1) {
    c.rpc->run_event_loop(kAppEvLoopMs);
    if (unlikely(ctrl_c_pressed == 1)) return;
  }
}

void app_cont_func(void *, void *);

inline void send_req(ClientContext &c) {
  c.start_tsc = erpc::rdtsc();
  assert(c.req_msgbuf.get_data_size() == sizeof(struct classification_hdr_t));

  struct classification_hdr_t * req = reinterpret_cast<struct classification_hdr_t *>(c.req_msgbuf.buf);
  req->egr_ts = 0;
  req->ingress_mac_tstamp = 0;
  req->trace_idx = c.next_trace_idx;
  req->match_priority = 0;
  memcpy((uint32_t *)req->headers, c.trace_packets[req->trace_idx].get(), CLASSIFICATION_HEADER_WORDS*8);
  c.next_trace_idx = (c.next_trace_idx+1) % c.num_of_packets;
  c.rpc->enqueue_request(c.session_num_vec[0], kAppReqType, &c.req_msgbuf,
                         &c.resp_msgbuf, app_cont_func, nullptr);
}

void app_cont_func(void *_context, void *) {
  auto *c = static_cast<ClientContext *>(_context);
  assert(c->resp_msgbuf.get_data_size() == sizeof(struct classification_hdr_t));

  erpc::rt_assert(c->resp_msgbuf.get_data_size() == sizeof(struct classification_hdr_t),
                  "Invalid response size");
  auto *resp = reinterpret_cast<struct classification_hdr_t *>(c->resp_msgbuf.buf);
  assert(resp->trace_idx < c->num_of_packets);
#if 0
  if (resp->match_priority != c->trace_packets[resp->trace_idx].match_priority)
    printf("WARNING: trace_idx %u match_priority %d (should be %d)\n", resp->trace_idx, resp->match_priority, c->trace_packets[resp->trace_idx].match_priority);
#endif
#if 0
  else printf("MATCHED!!!!!!!1 trace_idx %u match_priority %d (should be %d)\n", resp->trace_idx, resp->match_priority, c->trace_packets[resp->trace_idx].match_priority);
#endif
  uint64_t egr_ts = be64toh(resp->egr_ts) >> 16;
  uint64_t ingr_ts = be64toh(resp->ingress_mac_tstamp) >> 16;
  uint32_t lat_ns = ingr_ts - egr_ts;
  //printf("egr_ts: 0x%lx    ingress_mac_tstamp: 0x%lx   latency: %ldns\n", egr_ts, ingr_ts, lat_ns);

#if USE_SWITCH_TIMESTAMPING
  double req_lat_us = lat_ns/1e3;
#else
  double req_lat_us =
      erpc::to_usec(erpc::rdtsc() - c->start_tsc, c->rpc->get_freq_ghz());
#endif
  c->latency.update(static_cast<size_t>(req_lat_us * kAppLatFac));

  send_req(*c);
}

void client_func(erpc::Nexus *nexus) {
  std::vector<size_t> port_vec = flags_get_numa_ports(FLAGS_numa_node);
  uint8_t phy_port = port_vec.at(0);

  ClientContext c;
  erpc::Rpc<erpc::CTransport> rpc(nexus, static_cast<void *>(&c), 0,
                                  basic_sm_handler, phy_port);

  rpc.retry_connect_on_invalid_rpc_id = true;
  c.rpc = &rpc;

  c.req_msgbuf = rpc.alloc_msg_buffer_or_die(sizeof(struct classification_hdr_t));
  c.resp_msgbuf = rpc.alloc_msg_buffer_or_die(sizeof(struct classification_hdr_t));
  c.rpc->resize_msg_buffer(&c.req_msgbuf, sizeof(struct classification_hdr_t));
  c.rpc->resize_msg_buffer(&c.resp_msgbuf, sizeof(struct classification_hdr_t));

  // Read the textual trace file
  const char* trace_filename = "trace";
  vector<uint32_t> arbitrary_fields;
  c.trace_packets = read_trace_file(trace_filename, arbitrary_fields, &c.num_of_packets);
  if (!c.trace_packets) {
    throw error("error while reading trace file");
  }
  printf("Total %u packets in trace\n", c.num_of_packets);

  connect_session(c);

  printf("Process %zu: Session connected. Starting work.\n", FLAGS_process_id);
  printf("mean_us median_us 5th_us 99th_us 999th_us\n");

  send_req(c);
  for (size_t i = 0; i < FLAGS_test_ms; i += 1000) {
    rpc.run_event_loop(kAppEvLoopMs);  // 1 second
    if (ctrl_c_pressed == 1) break;
    printf("%.1f %.1f %.1f %.1f %.1f\n", c.latency.avg() / kAppLatFac,
           c.latency.perc(.5) / kAppLatFac, c.latency.perc(.05) / kAppLatFac,
           c.latency.perc(.99) / kAppLatFac, c.latency.perc(.999) / kAppLatFac);

    //c.latency.reset();
  }
}

int main(int argc, char **argv) {
  signal(SIGINT, ctrl_c_handler);

  gflags::ParseCommandLineFlags(&argc, &argv, true);
  erpc::rt_assert(FLAGS_numa_node <= 1, "Invalid NUMA node");
  erpc::Nexus nexus(erpc::get_uri_for_process(FLAGS_process_id),
                    FLAGS_numa_node, 0);
  nexus.register_req_func(kAppReqType, req_handler);

  auto t =
      std::thread(FLAGS_process_id == 0 ? server_func : client_func, &nexus);
  erpc::bind_to_core(t, FLAGS_numa_node, 0);
  t.join();
}
