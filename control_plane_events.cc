#include "control_plane_events.h"

#include <cstdio>
#include <ctime>
#include <mutex>

static bool g_cp_worker_mode = false;
static std::mutex g_cp_emit_mutex;

void cp_set_worker_mode(bool enabled) {
  std::lock_guard<std::mutex> lock(g_cp_emit_mutex);
  g_cp_worker_mode = enabled;
}

bool cp_is_worker_mode() {
  std::lock_guard<std::mutex> lock(g_cp_emit_mutex);
  return g_cp_worker_mode;
}

std::string cp_json_escape(const std::string &value) {
  std::string escaped;
  escaped.reserve(value.size() + 16);

  for (size_t i = 0; i < value.size(); i++) {
    const unsigned char ch = static_cast<unsigned char>(value[i]);
    switch (ch) {
      case '"':
        escaped += "\\\"";
        break;
      case '\\':
        escaped += "\\\\";
        break;
      case '\b':
        escaped += "\\b";
        break;
      case '\f':
        escaped += "\\f";
        break;
      case '\n':
        escaped += "\\n";
        break;
      case '\r':
        escaped += "\\r";
        break;
      case '\t':
        escaped += "\\t";
        break;
      default:
        if (ch < 0x20) {
          char buf[8];
          std::snprintf(buf, sizeof(buf), "\\u%04x", ch);
          escaped += buf;
        } else {
          escaped.push_back(static_cast<char>(ch));
        }
        break;
    }
  }

  return escaped;
}

std::string cp_now_iso8601_utc() {
  time_t now = time(NULL);
  struct tm tmv;
  gmtime_r(&now, &tmv);

  char buf[64];
  std::snprintf(buf, sizeof(buf), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                tmv.tm_year + 1900,
                tmv.tm_mon + 1,
                tmv.tm_mday,
                tmv.tm_hour,
                tmv.tm_min,
                tmv.tm_sec);
  return std::string(buf);
}

void cp_emit_event_json(const std::string &event_type,
                        const std::string &payload_json) {
  std::lock_guard<std::mutex> lock(g_cp_emit_mutex);

  if (!g_cp_worker_mode)
    return;

  std::string ts = cp_now_iso8601_utc();
  std::string event_type_escaped = cp_json_escape(event_type);

  std::fprintf(stdout,
               "@CP_EVENT {\"event_type\":\"%s\",\"ts\":\"%s\",\"payload\":%s}\n",
               event_type_escaped.c_str(),
               ts.c_str(),
               payload_json.c_str());
  std::fflush(stdout);
}
