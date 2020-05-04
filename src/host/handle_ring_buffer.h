// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the Apache 2.0 License.
#pragma once

#include "../ds/files.h"
#include "../ds/logger.h"
#include "../enclave/interface.h"
#include "every_io.h"

#include <chrono>
#include <ctime>
#include <iomanip>
#include <nlohmann/json.hpp>
#include <string>
#include <sys/types.h>
#include <unistd.h>

namespace asynchost
{
  class HandleRingbufferImpl
  {
  private:
    static constexpr size_t max_messages = 128;

    messaging::BufferProcessor& bp;
    ringbuffer::Reader& r;
    ringbuffer::NonBlockingWriterFactory& nbwf;

  public:
    HandleRingbufferImpl(
      messaging::BufferProcessor& bp,
      ringbuffer::Reader& r,
      ringbuffer::NonBlockingWriterFactory& nbwf) :
      bp(bp),
      r(r),
      nbwf(nbwf)
    {
      // Register message handler for log message from enclave
      DISPATCHER_SET_MESSAGE_HANDLER(
        bp, AdminMessage::log_msg, [](const uint8_t* data, size_t size) {
          auto [elapsed, file_name, line_number, log_level, thread_id, msg] =
            ringbuffer::read_message<AdminMessage::log_msg>(data, size);

          logger::Out::write(
            file_name, line_number, log_level, thread_id, msg, elapsed.count());
        });

      DISPATCHER_SET_MESSAGE_HANDLER(
        bp,
        AdminMessage::fatal_error_msg,
        [](const uint8_t* data, size_t size) {
          auto [msg] =
            ringbuffer::read_message<AdminMessage::fatal_error_msg>(data, size);

          std::cerr << msg << std::endl << std::flush;
          throw std::logic_error(msg);
        });
    }

    void every()
    {
      // On each uv loop iteration...

      // ...read (and process) all outbound ringbuffer messages...
      while (bp.read_n(max_messages, r) > 0)
      {
        continue;
      }

      // ...flush any pending inbound messages...
      nbwf.flush_all_inbound();
    }
  };

  using HandleRingbuffer = proxy_ptr<EveryIO<HandleRingbufferImpl>>;
}