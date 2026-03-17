#include "nmap_service.h"

#include "control_plane_events.h"

#include <boost/asio/ip/address.hpp>
#include <boost/asio/ip/tcp.hpp>
#include <boost/beast/core.hpp>
#include <boost/beast/http.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/json.hpp>

#include <atomic>
#include <cerrno>
#include <chrono>
#include <condition_variable>
#include <csignal>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <deque>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <set>
#include <string>
#include <thread>
#include <vector>

#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

namespace beast = boost::beast;
namespace http = beast::http;
namespace websocket = beast::websocket;
namespace net = boost::asio;
using tcp = net::ip::tcp;

enum cp_auth_provider_t {
  CP_AUTH_INLINE_TOKEN,
  CP_AUTH_TOKEN_FILE,
  CP_AUTH_ENV_VAR
};

struct cp_auth_config_t {
  cp_auth_provider_t provider;
  std::string provider_name;
  std::string token;
  std::string token_file;
  std::string env_var;
};

struct cp_service_config_t {
  std::string bind_addr;
  unsigned short port;
  size_t max_event_buffer;
  size_t max_active_scans;
  uint64_t cancel_grace_ms;
  cp_auth_config_t auth;
};

struct cp_event_t {
  uint64_t event_id;
  std::string event_type;
  std::string ts;
  boost::json::value payload;
};

struct cp_job_t {
  std::string job_id;
  std::string status;
  std::vector<std::string> scan_args;

  pid_t worker_pid;
  bool cancel_requested;
  bool timeout_requested;
  uint64_t timeout_ms;
  bool timeout_triggered;
  bool cancel_escalated;
  int raw_wait_status;
  int exit_code;

  uint64_t next_event_id;
  uint64_t dropped_events;
  std::deque<cp_event_t> events;

  std::map<std::string, uint64_t> event_counts;
  uint64_t warning_count;
  uint64_t error_count;
  uint64_t backpressure_count;
  uint64_t event_loss_count;
  std::deque<std::string> recent_warnings;
  std::deque<std::string> recent_errors;

  time_t created_time;
  time_t started_time;
  time_t ended_time;
  uint64_t created_monotonic_ms;
  uint64_t started_monotonic_ms;
  uint64_t ended_monotonic_ms;

  std::mutex mutex;
  std::condition_variable cond;
};

static uint64_t monotonic_ms_now() {
  std::chrono::steady_clock::time_point now = std::chrono::steady_clock::now();
  return (uint64_t) std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
}

static std::string read_first_line_trimmed(const std::string &path) {
  std::ifstream file(path.c_str());
  if (!file)
    return std::string();

  std::string line;
  std::getline(file, line);
  while (!line.empty() &&
         (line[line.size() - 1] == '\n' || line[line.size() - 1] == '\r' ||
          line[line.size() - 1] == ' ' || line[line.size() - 1] == '\t')) {
    line.erase(line.size() - 1);
  }
  return line;
}

static bool starts_with(const std::string &value, const char *prefix) {
  size_t prefix_len = std::strlen(prefix);
  return value.size() >= prefix_len && value.compare(0, prefix_len, prefix) == 0;
}

struct cp_cli_parse_t {
  bool service_mode;
  bool generate_mode;
  bool force;
  bool help;

  std::string service_config_path;
  std::string generate_path;

  std::vector<std::string> runtime_override_flags;
};

static void print_daemon_usage(const char *progname) {
  const char *name = progname ? progname : "nmap";
  std::fprintf(stderr,
               "Daemon mode usage:\n"
               "  %s --service --service-config <path>\n"
               "  %s --service-config-generate <path> [--force]\n"
               "\n"
               "Notes:\n"
               "  * --service requires a JSON config file path.\n"
               "  * Runtime daemon flags passed on CLI are rejected when config is used.\n"
               "  * --service-worker is internal and used by daemon job workers.\n",
               name,
               name);
}

static bool parse_service_cli(int argc,
                              char *argv[],
                              cp_cli_parse_t &out,
                              std::string &error_text,
                              std::string &binary_path) {
  out.service_mode = false;
  out.generate_mode = false;
  out.force = false;
  out.help = false;
  out.service_config_path.clear();
  out.generate_path.clear();
  out.runtime_override_flags.clear();

  if (argc > 0)
    binary_path = argv[0];

  for (int i = 1; i < argc; i++) {
    const std::string arg = argv[i];

    if (arg == "--service") {
      out.service_mode = true;
    } else if (arg == "--service-config") {
      if (i + 1 >= argc) {
        error_text = "--service-config requires a path";
        return false;
      }
      out.service_config_path = argv[++i];
    } else if (arg == "--service-config-generate") {
      if (i + 1 >= argc) {
        error_text = "--service-config-generate requires a path";
        return false;
      }
      out.generate_mode = true;
      out.generate_path = argv[++i];
    } else if (arg == "--force") {
      out.force = true;
    } else if (arg == "--help" || arg == "-h") {
      out.help = true;
    } else if (arg == "--service-worker") {
      continue;
    } else if (arg == "--bind" ||
               arg == "--port" ||
               arg == "--max-event-buffer" ||
               arg == "--max-active-scans" ||
               arg == "--cancel-grace-ms" ||
               arg == "--token" ||
               arg == "--token-file") {
      out.runtime_override_flags.push_back(arg);
      if (i + 1 < argc)
        i++;
    } else if (starts_with(arg, "--")) {
      error_text = "unknown daemon option: " + arg;
      return false;
    }
  }

  if (out.service_mode && out.generate_mode) {
    error_text = "--service and --service-config-generate are mutually exclusive";
    return false;
  }

  if (out.generate_mode && out.generate_path.empty()) {
    error_text = "missing --service-config-generate output path";
    return false;
  }

  if (out.force && !out.generate_mode) {
    error_text = "--force is only valid with --service-config-generate";
    return false;
  }

  return true;
}

static bool write_generic_config(const std::string &path, bool force, std::string &error_text) {
  if (path.empty()) {
    error_text = "output path is empty";
    return false;
  }

  if (!force) {
    std::ifstream existing(path.c_str());
    if (existing.good()) {
      error_text = "config file already exists, pass --force to overwrite";
      return false;
    }
  }

  boost::json::object root;
  boost::json::object runtime;
  runtime["bind_addr"] = "127.0.0.1";
  runtime["port"] = 8765;
  runtime["max_event_buffer"] = 4096;
  runtime["max_active_scans"] = 4;
  runtime["cancel_grace_ms"] = 5000;

  boost::json::object auth;
  auth["provider"] = "inline_token";
  auth["token"] = "change_me";

  root["runtime"] = runtime;
  root["auth"] = auth;

  std::ofstream out(path.c_str(), std::ios::out | std::ios::trunc);
  if (!out) {
    error_text = "failed to open output config path: " + path;
    return false;
  }

  out << boost::json::serialize(root) << "\n";
  out.close();

  if (!out) {
    error_text = "failed while writing config file: " + path;
    return false;
  }

  return true;
}

static bool json_get_object(const boost::json::object &obj,
                            const char *key,
                            boost::json::object &out,
                            std::string &error_text) {
  boost::json::object::const_iterator it = obj.find(key);
  if (it == obj.end() || !it->value().is_object()) {
    error_text = std::string("missing or invalid object: ") + key;
    return false;
  }
  out = it->value().as_object();
  return true;
}

static bool json_get_string(const boost::json::object &obj,
                            const char *key,
                            std::string &out,
                            std::string &error_text) {
  boost::json::object::const_iterator it = obj.find(key);
  if (it == obj.end() || !it->value().is_string()) {
    error_text = std::string("missing or invalid string: ") + key;
    return false;
  }
  out = std::string(it->value().as_string().c_str());
  if (out.empty()) {
    error_text = std::string("empty value is not allowed for: ") + key;
    return false;
  }
  return true;
}

static bool json_get_int64(const boost::json::object &obj,
                           const char *key,
                           int64_t &out,
                           std::string &error_text) {
  boost::json::object::const_iterator it = obj.find(key);
  if (it == obj.end() || !it->value().is_int64()) {
    error_text = std::string("missing or invalid integer: ") + key;
    return false;
  }
  out = it->value().as_int64();
  return true;
}

static bool resolve_auth_token(cp_auth_config_t &auth, std::string &error_text) {
  if (auth.provider == CP_AUTH_INLINE_TOKEN) {
    if (auth.token.empty()) {
      error_text = "auth.token must be non-empty for inline_token provider";
      return false;
    }
    return true;
  }

  if (auth.provider == CP_AUTH_TOKEN_FILE) {
    if (auth.token_file.empty()) {
      error_text = "auth.token_file must be non-empty for token_file provider";
      return false;
    }
    auth.token = read_first_line_trimmed(auth.token_file);
    if (auth.token.empty()) {
      error_text = "failed to load non-empty auth token from token_file";
      return false;
    }
    return true;
  }

  if (auth.provider == CP_AUTH_ENV_VAR) {
    if (auth.env_var.empty()) {
      error_text = "auth.env_var must be non-empty for env_var provider";
      return false;
    }
    const char *env_value = getenv(auth.env_var.c_str());
    if (!env_value || !*env_value) {
      error_text = "environment variable for auth token is unset or empty";
      return false;
    }
    auth.token = env_value;
    return true;
  }

  error_text = "invalid auth provider";
  return false;
}

static bool parse_service_config_file(const std::string &path,
                                      cp_service_config_t &cfg,
                                      std::string &error_text) {
  std::ifstream file(path.c_str());
  if (!file) {
    error_text = "failed to open service config file: " + path;
    return false;
  }

  std::string text;
  {
    std::string line;
    while (std::getline(file, line)) {
      text += line;
      text.push_back('\n');
    }
  }

  boost::json::error_code ec;
  boost::json::value root_value = boost::json::parse(text, ec);
  if (ec || !root_value.is_object()) {
    error_text = "service config is not valid JSON object";
    return false;
  }

  boost::json::object root = root_value.as_object();
  boost::json::object runtime;
  boost::json::object auth_obj;

  if (!json_get_object(root, "runtime", runtime, error_text))
    return false;
  if (!json_get_object(root, "auth", auth_obj, error_text))
    return false;

  if (!json_get_string(runtime, "bind_addr", cfg.bind_addr, error_text))
    return false;

  int64_t port = 0;
  int64_t max_event_buffer = 0;
  int64_t max_active_scans = 0;
  int64_t cancel_grace_ms = 0;

  if (!json_get_int64(runtime, "port", port, error_text))
    return false;
  if (!json_get_int64(runtime, "max_event_buffer", max_event_buffer, error_text))
    return false;
  if (!json_get_int64(runtime, "max_active_scans", max_active_scans, error_text))
    return false;
  if (!json_get_int64(runtime, "cancel_grace_ms", cancel_grace_ms, error_text))
    return false;

  if (port < 1 || port > 65535) {
    error_text = "runtime.port must be between 1 and 65535";
    return false;
  }
  if (max_event_buffer < 64 || max_event_buffer > 1048576) {
    error_text = "runtime.max_event_buffer must be between 64 and 1048576";
    return false;
  }
  if (max_active_scans < 1 || max_active_scans > 256) {
    error_text = "runtime.max_active_scans must be between 1 and 256";
    return false;
  }
  if (cancel_grace_ms < 100 || cancel_grace_ms > 600000) {
    error_text = "runtime.cancel_grace_ms must be between 100 and 600000";
    return false;
  }

  cfg.port = (unsigned short) port;
  cfg.max_event_buffer = (size_t) max_event_buffer;
  cfg.max_active_scans = (size_t) max_active_scans;
  cfg.cancel_grace_ms = (uint64_t) cancel_grace_ms;

  std::string provider;
  if (!json_get_string(auth_obj, "provider", provider, error_text))
    return false;

  cfg.auth.provider_name = provider;
  cfg.auth.token.clear();
  cfg.auth.token_file.clear();
  cfg.auth.env_var.clear();

  if (provider == "inline_token") {
    cfg.auth.provider = CP_AUTH_INLINE_TOKEN;
    if (!json_get_string(auth_obj, "token", cfg.auth.token, error_text))
      return false;
  } else if (provider == "token_file") {
    cfg.auth.provider = CP_AUTH_TOKEN_FILE;
    if (!json_get_string(auth_obj, "token_file", cfg.auth.token_file, error_text))
      return false;
  } else if (provider == "env_var") {
    cfg.auth.provider = CP_AUTH_ENV_VAR;
    if (!json_get_string(auth_obj, "env_var", cfg.auth.env_var, error_text))
      return false;
  } else {
    error_text = "auth.provider must be one of: inline_token, token_file, env_var";
    return false;
  }

  if (!resolve_auth_token(cfg.auth, error_text))
    return false;

  return true;
}

static bool validate_scan_args(const std::vector<std::string> &args,
                               std::string &error_text) {
  static const char *const flags_no_value[] = {
    "-sS", "-sT", "-sU", "-sV", "-O", "-sn", "-Pn", "-n",
    "-v", "-vv", "-d", "-dd", "-A", "-6", "-F", "-r",
    "--reason", "--open", "--traceroute", "--noninteractive"
  };

  static const char *const flags_with_value[] = {
    "-p", "-T", "--top-ports", "--host-timeout", "--max-retries",
    "--min-rate", "--max-rate", "--script", "--script-args",
    "--script-timeout", "--exclude", "--exclude-ports"
  };

  static const char *const flags_inline_prefix[] = {
    "-p", "-T", "--top-ports=", "--host-timeout=", "--max-retries=",
    "--min-rate=", "--max-rate=", "--script=", "--script-args=",
    "--script-timeout=", "--exclude=", "--exclude-ports="
  };

  if (args.size() > 256) {
    error_text = "too many args; maximum is 256";
    return false;
  }

  for (size_t i = 0; i < args.size(); i++) {
    const std::string &arg = args[i];

    if (arg.empty() || arg.size() > 512) {
      error_text = "each arg must be 1..512 characters";
      return false;
    }
    if (arg.find('\n') != std::string::npos || arg.find('\r') != std::string::npos) {
      error_text = "args must not contain newlines";
      return false;
    }
    if (arg == "--service" ||
        arg == "--service-worker" ||
        arg == "--service-config" ||
        arg == "--service-config-generate") {
      error_text = "service control arguments are not allowed in scan args";
      return false;
    }

    if (arg[0] != '-')
      continue;

    bool no_value_flag = false;
    for (size_t j = 0; j < sizeof(flags_no_value) / sizeof(flags_no_value[0]); j++) {
      if (arg == flags_no_value[j]) {
        no_value_flag = true;
        break;
      }
    }
    if (no_value_flag)
      continue;

    bool with_value_flag = false;
    for (size_t j = 0; j < sizeof(flags_with_value) / sizeof(flags_with_value[0]); j++) {
      if (arg == flags_with_value[j]) {
        with_value_flag = true;
        break;
      }
    }
    if (with_value_flag) {
      if (i + 1 >= args.size()) {
        error_text = "missing value for " + arg;
        return false;
      }
      if (args[i + 1].empty() || args[i + 1].size() > 512) {
        error_text = "invalid value for " + arg;
        return false;
      }
      i++;
      continue;
    }

    bool allowed_inline = false;
    for (size_t j = 0; j < sizeof(flags_inline_prefix) / sizeof(flags_inline_prefix[0]); j++) {
      if (starts_with(arg, flags_inline_prefix[j])) {
        allowed_inline = true;
        break;
      }
    }
    if (allowed_inline)
      continue;

    error_text = "unsupported or disallowed option: " + arg;
    return false;
  }

  return true;
}

class cp_state_t {
 public:
  cp_state_t(const cp_service_config_t &config,
             const std::string &binary_path)
      : cfg(config),
        binary_path(binary_path),
        daemon_started_at(cp_now_iso8601_utc()),
        next_job_id(1),
        stopping(false),
        daemon_start_time(time(NULL)),
        daemon_start_monotonic_ms(monotonic_ms_now()),
        session_count(0),
        total_events(0),
        total_warnings(0),
        total_errors(0),
        total_backpressure(0),
        total_event_loss(0),
        total_jobs_queued(0),
        total_jobs_started(0),
        total_jobs_completed(0),
        total_jobs_failed(0),
        total_jobs_canceled(0),
        total_jobs_timeout(0) {
  }

  void start_workers() {
    for (size_t i = 0; i < cfg.max_active_scans; i++) {
      worker_threads.push_back(std::thread([this]() {
        worker_loop();
      }));
    }
  }

  void stop_workers() {
    {
      std::lock_guard<std::mutex> lock(state_mutex);
      stopping = true;
    }
    scheduler_cond.notify_all();
    terminate_all_active_workers();

    for (size_t i = 0; i < worker_threads.size(); i++) {
      if (worker_threads[i].joinable())
        worker_threads[i].join();
    }
    worker_threads.clear();
  }

  void note_session_open() {
    session_count.fetch_add(1);
  }

  void note_session_close() {
    session_count.fetch_sub(1);
  }

  size_t get_max_active_scans() const {
    return cfg.max_active_scans;
  }

  std::shared_ptr<cp_job_t> create_job(const std::vector<std::string> &scan_args,
                                       bool timeout_requested,
                                       uint64_t timeout_ms) {
    std::shared_ptr<cp_job_t> job(new cp_job_t());
    job->job_id = make_job_id();
    job->status = "job_queued";
    job->scan_args = scan_args;

    job->worker_pid = -1;
    job->cancel_requested = false;
    job->timeout_requested = timeout_requested;
    job->timeout_ms = timeout_ms;
    job->timeout_triggered = false;
    job->cancel_escalated = false;
    job->raw_wait_status = -1;
    job->exit_code = -1;

    job->next_event_id = 1;
    job->dropped_events = 0;

    job->warning_count = 0;
    job->error_count = 0;
    job->backpressure_count = 0;
    job->event_loss_count = 0;

    job->created_time = time(NULL);
    job->started_time = 0;
    job->ended_time = 0;
    job->created_monotonic_ms = monotonic_ms_now();
    job->started_monotonic_ms = 0;
    job->ended_monotonic_ms = 0;

    {
      std::lock_guard<std::mutex> lock(state_mutex);
      jobs[job->job_id] = job;
      queue.push_back(job->job_id);
      total_jobs_queued.fetch_add(1);
      scheduler_cond.notify_all();
    }

    append_event(job, "job_queued", boost::json::object());
    return job;
  }

  std::shared_ptr<cp_job_t> get_job(const std::string &job_id) {
    std::lock_guard<std::mutex> lock(state_mutex);
    std::map<std::string, std::shared_ptr<cp_job_t> >::iterator it = jobs.find(job_id);
    if (it == jobs.end())
      return std::shared_ptr<cp_job_t>();
    return it->second;
  }

  boost::json::array list_jobs() {
    boost::json::array arr;
    std::lock_guard<std::mutex> lock(state_mutex);
    for (std::map<std::string, std::shared_ptr<cp_job_t> >::iterator it = jobs.begin();
         it != jobs.end(); ++it) {
      std::shared_ptr<cp_job_t> job = it->second;
      std::lock_guard<std::mutex> job_lock(job->mutex);
      boost::json::object obj;
      obj["job_id"] = job->job_id;
      obj["status"] = job->status;
      obj["exit_code"] = job->exit_code;
      obj["worker_pid"] = (int64_t) job->worker_pid;
      arr.emplace_back(obj);
    }
    return arr;
  }

  bool cancel_job(const std::string &job_id) {
    std::shared_ptr<cp_job_t> job = get_job(job_id);
    if (!job)
      return false;

    bool queued_cancel = false;
    pid_t pid = -1;

    {
      std::lock_guard<std::mutex> lock(job->mutex);
      if (is_terminal_status_locked(job))
        return true;

      job->cancel_requested = true;
      pid = job->worker_pid;

      if (job->status == "job_queued") {
        job->status = "job_canceled";
        job->ended_time = time(NULL);
        job->ended_monotonic_ms = monotonic_ms_now();
        queued_cancel = true;
      }
    }

    if (queued_cancel) {
      remove_job_from_queue(job_id);
      append_event(job, "job_canceled", boost::json::object());
      return true;
    }

    if (pid > 0)
      kill(pid, SIGTERM);

    return true;
  }

  void append_event(const std::shared_ptr<cp_job_t> &job,
                    const std::string &event_type,
                    const boost::json::value &payload) {
    boost::json::object payload_obj;
    if (payload.is_object())
      payload_obj = payload.as_object();

    {
      std::lock_guard<std::mutex> lock(job->mutex);

      if (job->dropped_events > 0 &&
          event_type != "event_loss" &&
          event_type != "stream_backpressure") {
        boost::json::object backpressure_payload;
        backpressure_payload["reason"] = "event_buffer_overflow";
        backpressure_payload["dropped_events"] = (int64_t) job->dropped_events;
        push_event_locked(job, "stream_backpressure", backpressure_payload);
        update_job_event_counters_locked(job, "stream_backpressure", backpressure_payload);
        total_backpressure.fetch_add(1);

        boost::json::object loss_payload;
        loss_payload["dropped_events"] = (int64_t) job->dropped_events;
        push_event_locked(job, "event_loss", loss_payload);
        update_job_event_counters_locked(job, "event_loss", loss_payload);
        total_event_loss.fetch_add(1);

        job->dropped_events = 0;
      }

      push_event_locked(job, event_type, payload_obj);
      update_job_event_counters_locked(job, event_type, payload_obj);
      job->cond.notify_all();
    }

    total_events.fetch_add(1);
    if (event_type == "scan_warning")
      total_warnings.fetch_add(1);
    else if (event_type == "scan_error")
      total_errors.fetch_add(1);
    else if (event_type == "stream_backpressure")
      total_backpressure.fetch_add(1);
    else if (event_type == "event_loss")
      total_event_loss.fetch_add(1);
    else if (event_type == "job_started")
      total_jobs_started.fetch_add(1);
    else if (event_type == "job_completed")
      total_jobs_completed.fetch_add(1);
    else if (event_type == "job_failed")
      total_jobs_failed.fetch_add(1);
    else if (event_type == "job_canceled")
      total_jobs_canceled.fetch_add(1);
    else if (event_type == "job_timeout")
      total_jobs_timeout.fetch_add(1);
  }

  std::vector<cp_event_t> events_after(const std::shared_ptr<cp_job_t> &job,
                                       uint64_t last_event_id,
                                       bool wait_for_more,
                                       int wait_ms) {
    std::unique_lock<std::mutex> lock(job->mutex);

    if (wait_for_more) {
      if (!has_events_after_locked(job, last_event_id) && !is_terminal_status_locked(job)) {
        job->cond.wait_for(lock, std::chrono::milliseconds(wait_ms));
      }
    }

    std::vector<cp_event_t> out;
    for (std::deque<cp_event_t>::const_iterator it = job->events.begin();
         it != job->events.end(); ++it) {
      if (it->event_id > last_event_id)
        out.push_back(*it);
    }
    return out;
  }

  bool is_terminal_status(const std::shared_ptr<cp_job_t> &job) {
    std::lock_guard<std::mutex> lock(job->mutex);
    return is_terminal_status_locked(job);
  }

  boost::json::object daemon_diagnostics() {
    boost::json::object out;

    size_t queue_depth = 0;
    size_t active_jobs = 0;
    size_t total_jobs = 0;
    bool stopping_now = false;

    {
      std::lock_guard<std::mutex> lock(state_mutex);
      queue_depth = queue.size();
      active_jobs = active_job_ids.size();
      total_jobs = jobs.size();
      stopping_now = stopping;
    }

    time_t now = time(NULL);
    uint64_t uptime_sec = (uint64_t) (now - daemon_start_time);

    out["pid"] = (int64_t) getpid();
    out["daemon_version"] = "nmap_extended_control_plane_v1";
    out["binary_path"] = binary_path;
    out["started_at"] = daemon_started_at;
    out["uptime_sec"] = (int64_t) uptime_sec;
    out["scheduler_health"] = stopping_now ? "stopping" : "running";
    out["queue_depth"] = (int64_t) queue_depth;
    out["active_jobs"] = (int64_t) active_jobs;
    out["total_jobs"] = (int64_t) total_jobs;
    out["websocket_sessions"] = (int64_t) session_count.load();

    boost::json::object limits;
    limits["bind_addr"] = cfg.bind_addr;
    limits["port"] = (int64_t) cfg.port;
    limits["max_event_buffer"] = (int64_t) cfg.max_event_buffer;
    limits["max_active_scans"] = (int64_t) cfg.max_active_scans;
    limits["cancel_grace_ms"] = (int64_t) cfg.cancel_grace_ms;
    limits["auth_provider"] = cfg.auth.provider_name;
    out["limits"] = limits;

    boost::json::object counters;
    counters["total_events"] = (int64_t) total_events.load();
    counters["total_warnings"] = (int64_t) total_warnings.load();
    counters["total_errors"] = (int64_t) total_errors.load();
    counters["total_backpressure"] = (int64_t) total_backpressure.load();
    counters["total_event_loss"] = (int64_t) total_event_loss.load();
    counters["jobs_queued"] = (int64_t) total_jobs_queued.load();
    counters["jobs_started"] = (int64_t) total_jobs_started.load();
    counters["jobs_completed"] = (int64_t) total_jobs_completed.load();
    counters["jobs_failed"] = (int64_t) total_jobs_failed.load();
    counters["jobs_canceled"] = (int64_t) total_jobs_canceled.load();
    counters["jobs_timeout"] = (int64_t) total_jobs_timeout.load();
    out["counters"] = counters;

    return out;
  }

  bool job_diagnostics(const std::string &job_id,
                       boost::json::object &out,
                       std::string &error_text) {
    std::shared_ptr<cp_job_t> job = get_job(job_id);
    if (!job) {
      error_text = "job not found";
      return false;
    }

    std::lock_guard<std::mutex> lock(job->mutex);
    uint64_t now_ms = monotonic_ms_now();
    uint64_t elapsed_ms = 0;
    if (job->started_monotonic_ms > 0) {
      if (job->ended_monotonic_ms > 0)
        elapsed_ms = job->ended_monotonic_ms - job->started_monotonic_ms;
      else if (now_ms >= job->started_monotonic_ms)
        elapsed_ms = now_ms - job->started_monotonic_ms;
    }

    out["job_id"] = job->job_id;
    out["status"] = job->status;
    out["phase"] = job->status;
    out["worker_pid"] = (int64_t) job->worker_pid;
    out["exit_code"] = (int64_t) job->exit_code;
    out["raw_wait_status"] = (int64_t) job->raw_wait_status;

    boost::json::object flags;
    flags["cancel_requested"] = job->cancel_requested;
    flags["timeout_requested"] = job->timeout_requested;
    flags["timeout_triggered"] = job->timeout_triggered;
    flags["cancel_escalated"] = job->cancel_escalated;
    out["flags"] = flags;

    boost::json::object timing;
    timing["created_time"] = (int64_t) job->created_time;
    timing["started_time"] = (int64_t) job->started_time;
    timing["ended_time"] = (int64_t) job->ended_time;
    timing["elapsed_ms"] = (int64_t) elapsed_ms;
    timing["timeout_ms"] = (int64_t) job->timeout_ms;
    out["timing"] = timing;

    out["last_event_id"] = (int64_t) (job->next_event_id > 0 ? job->next_event_id - 1 : 0);
    out["buffered_events"] = (int64_t) job->events.size();
    out["dropped_events"] = (int64_t) job->dropped_events;

    boost::json::object event_counts;
    for (std::map<std::string, uint64_t>::const_iterator it = job->event_counts.begin();
         it != job->event_counts.end(); ++it) {
      event_counts[it->first] = (int64_t) it->second;
    }
    out["event_counts"] = event_counts;

    out["warning_count"] = (int64_t) job->warning_count;
    out["error_count"] = (int64_t) job->error_count;
    out["backpressure_count"] = (int64_t) job->backpressure_count;
    out["event_loss_count"] = (int64_t) job->event_loss_count;

    boost::json::array recent_warnings;
    for (size_t i = 0; i < job->recent_warnings.size(); i++)
      recent_warnings.emplace_back(job->recent_warnings[i]);
    out["recent_warnings"] = recent_warnings;

    boost::json::array recent_errors;
    for (size_t i = 0; i < job->recent_errors.size(); i++)
      recent_errors.emplace_back(job->recent_errors[i]);
    out["recent_errors"] = recent_errors;

    return true;
  }

  bool parse_worker_event(const std::string &json_line,
                          std::string &event_type,
                          boost::json::value &payload) {
    boost::json::error_code ec;
    boost::json::value v = boost::json::parse(json_line, ec);
    if (ec || !v.is_object())
      return false;

    boost::json::object obj = v.as_object();
    boost::json::object::const_iterator it = obj.find("event_type");
    if (it == obj.end() || !it->value().is_string())
      return false;

    event_type = std::string(it->value().as_string().c_str());
    boost::json::object::const_iterator payload_it = obj.find("payload");
    if (payload_it != obj.end())
      payload = payload_it->value();
    else
      payload = boost::json::object();

    return true;
  }

 private:
  std::string make_job_id() {
    unsigned long id = next_job_id.fetch_add(1);
    char buf[64];
    std::snprintf(buf, sizeof(buf), "job-%lu", id);
    return std::string(buf);
  }

  bool is_terminal_status_locked(const std::shared_ptr<cp_job_t> &job) {
    return job->status == "job_completed" ||
           job->status == "job_failed" ||
           job->status == "job_canceled" ||
           job->status == "job_timeout";
  }

  bool has_events_after_locked(const std::shared_ptr<cp_job_t> &job,
                               uint64_t last_event_id) {
    if (job->events.empty())
      return false;
    return job->events.back().event_id > last_event_id;
  }

  void push_event_locked(const std::shared_ptr<cp_job_t> &job,
                         const std::string &event_type,
                         const boost::json::value &payload) {
    cp_event_t event;
    event.event_id = job->next_event_id++;
    event.event_type = event_type;
    event.ts = cp_now_iso8601_utc();
    event.payload = payload;

    if (job->events.size() >= cfg.max_event_buffer) {
      job->events.pop_front();
      job->dropped_events++;
    }

    job->events.push_back(event);
  }

  void push_recent_locked(std::deque<std::string> &dq, const std::string &message) {
    static const size_t MAX_RECENT = 32;
    dq.push_back(message);
    while (dq.size() > MAX_RECENT)
      dq.pop_front();
  }

  void update_job_event_counters_locked(const std::shared_ptr<cp_job_t> &job,
                                        const std::string &event_type,
                                        const boost::json::value &payload) {
    job->event_counts[event_type]++;

    if (event_type == "scan_warning") {
      job->warning_count++;
      if (payload.is_object()) {
        boost::json::object obj = payload.as_object();
        boost::json::object::const_iterator it = obj.find("message");
        if (it != obj.end() && it->value().is_string())
          push_recent_locked(job->recent_warnings, std::string(it->value().as_string().c_str()));
      }
    } else if (event_type == "scan_error") {
      job->error_count++;
      if (payload.is_object()) {
        boost::json::object obj = payload.as_object();
        boost::json::object::const_iterator it = obj.find("message");
        if (it != obj.end() && it->value().is_string())
          push_recent_locked(job->recent_errors, std::string(it->value().as_string().c_str()));
      }
    } else if (event_type == "stream_backpressure") {
      job->backpressure_count++;
    } else if (event_type == "event_loss") {
      job->event_loss_count++;
    }
  }

  void remove_job_from_queue(const std::string &job_id) {
    std::lock_guard<std::mutex> lock(state_mutex);
    for (std::deque<std::string>::iterator it = queue.begin(); it != queue.end();) {
      if (*it == job_id)
        it = queue.erase(it);
      else
        ++it;
    }
  }

  void worker_loop() {
    while (true) {
      std::string next_job_id;

      {
        std::unique_lock<std::mutex> lock(state_mutex);
        scheduler_cond.wait(lock, [this]() {
          return stopping || !queue.empty();
        });

        if (stopping && queue.empty())
          return;

        if (queue.empty())
          continue;

        next_job_id = queue.front();
        queue.pop_front();
        active_job_ids.insert(next_job_id);
      }

      std::shared_ptr<cp_job_t> job = get_job(next_job_id);
      if (job)
        run_job(job);

      {
        std::lock_guard<std::mutex> lock(state_mutex);
        active_job_ids.erase(next_job_id);
        scheduler_cond.notify_all();
      }
    }
  }

  void terminate_all_active_workers() {
    std::vector<pid_t> active_pids;

    {
      std::lock_guard<std::mutex> lock(state_mutex);
      for (std::map<std::string, std::shared_ptr<cp_job_t> >::iterator it = jobs.begin();
           it != jobs.end(); ++it) {
        std::shared_ptr<cp_job_t> job = it->second;
        std::lock_guard<std::mutex> job_lock(job->mutex);
        if (job->worker_pid > 0)
          active_pids.push_back(job->worker_pid);
      }
    }

    for (size_t i = 0; i < active_pids.size(); i++)
      kill(active_pids[i], SIGTERM);

    std::this_thread::sleep_for(std::chrono::milliseconds(cfg.cancel_grace_ms));

    for (size_t i = 0; i < active_pids.size(); i++)
      kill(active_pids[i], SIGKILL);
  }

  void run_job(const std::shared_ptr<cp_job_t> &job) {
    bool emit_early_canceled = false;
    {
      std::lock_guard<std::mutex> lock(job->mutex);
      if (job->status == "job_canceled")
        return;
      if (job->cancel_requested) {
        job->status = "job_canceled";
        job->ended_time = time(NULL);
        job->ended_monotonic_ms = monotonic_ms_now();
        emit_early_canceled = true;
      }
    }
    if (emit_early_canceled) {
      append_event(job, "job_canceled", boost::json::object());
      return;
    }

    int pipefd[2] = {-1, -1};
    if (pipe(pipefd) != 0) {
      {
        std::lock_guard<std::mutex> lock(job->mutex);
        job->status = "job_failed";
        job->ended_time = time(NULL);
        job->ended_monotonic_ms = monotonic_ms_now();
      }
      boost::json::object payload;
      payload["error"] = "pipe_failed";
      append_event(job, "job_failed", payload);
      return;
    }

    pid_t pid = fork();
    if (pid < 0) {
      close(pipefd[0]);
      close(pipefd[1]);

      {
        std::lock_guard<std::mutex> lock(job->mutex);
        job->status = "job_failed";
        job->ended_time = time(NULL);
        job->ended_monotonic_ms = monotonic_ms_now();
      }

      boost::json::object payload;
      payload["error"] = "fork_failed";
      append_event(job, "job_failed", payload);
      return;
    }

    if (pid == 0) {
      dup2(pipefd[1], STDOUT_FILENO);
      dup2(pipefd[1], STDERR_FILENO);
      close(pipefd[0]);
      close(pipefd[1]);

      std::vector<std::string> child_args;
      child_args.push_back(binary_path);
      child_args.push_back("--service-worker");
      child_args.push_back("--noninteractive");
      for (size_t i = 0; i < job->scan_args.size(); i++) {
        child_args.push_back(job->scan_args[i]);
      }

      std::vector<char *> exec_args;
      exec_args.reserve(child_args.size() + 1);
      for (size_t i = 0; i < child_args.size(); i++) {
        exec_args.push_back(const_cast<char *>(child_args[i].c_str()));
      }
      exec_args.push_back(NULL);

      execv(exec_args[0], &exec_args[0]);
      _exit(127);
    }

    close(pipefd[1]);

    {
      std::lock_guard<std::mutex> lock(job->mutex);
      job->worker_pid = pid;
      job->status = "job_started";
      job->started_time = time(NULL);
      job->started_monotonic_ms = monotonic_ms_now();
    }

    append_event(job, "job_started", boost::json::object());

    int read_fd = pipefd[0];
    std::thread reader([this, job, read_fd]() {
      FILE *fp = fdopen(read_fd, "r");
      if (!fp)
        return;

      char *line = NULL;
      size_t cap = 0;
      while (getline(&line, &cap, fp) != -1) {
        std::string s(line);
        while (!s.empty() && (s[s.size() - 1] == '\n' || s[s.size() - 1] == '\r'))
          s.erase(s.size() - 1);

        if (s.rfind("@CP_EVENT ", 0) == 0) {
          std::string event_type;
          boost::json::value payload;
          if (parse_worker_event(s.substr(10), event_type, payload)) {
            append_event(job, event_type, payload);
          }
        } else if (!s.empty()) {
          boost::json::object text_payload;
          text_payload["message"] = s;

          if (s.find("error") != std::string::npos ||
              s.find("ERROR") != std::string::npos ||
              s.find("QUITTING!") != std::string::npos ||
              s.find("Failed") != std::string::npos) {
            append_event(job, "scan_error", text_payload);
          } else {
            append_event(job, "scan_warning", text_payload);
          }
        }
      }

      if (line)
        free(line);
      fclose(fp);
    });

    int status = 0;
    bool wait_error = false;
    bool term_sent = false;
    bool kill_sent = false;
    uint64_t term_sent_ms = 0;

    while (true) {
      pid_t wait_result = waitpid(pid, &status, WNOHANG);
      if (wait_result == pid)
        break;

      if (wait_result < 0) {
        if (errno == EINTR)
          continue;
        wait_error = true;
        break;
      }

      uint64_t now_ms = monotonic_ms_now();

      bool cancel_requested = false;
      bool timeout_hit_now = false;
      bool timeout_active = false;
      uint64_t timeout_ms = 0;

      {
        std::lock_guard<std::mutex> lock(job->mutex);
        cancel_requested = job->cancel_requested;
        timeout_active = job->timeout_requested;
        timeout_ms = job->timeout_ms;

        if (timeout_active && !job->timeout_triggered && job->started_monotonic_ms > 0) {
          uint64_t elapsed_ms = now_ms - job->started_monotonic_ms;
          if (elapsed_ms >= timeout_ms) {
            job->timeout_triggered = true;
            timeout_hit_now = true;
          }
        }
      }

      if ((cancel_requested || timeout_hit_now) && !term_sent) {
        kill(pid, SIGTERM);
        term_sent = true;
        term_sent_ms = now_ms;
      }

      if (term_sent && !kill_sent && now_ms - term_sent_ms >= cfg.cancel_grace_ms) {
        if (kill(pid, SIGKILL) == 0) {
          std::lock_guard<std::mutex> lock(job->mutex);
          job->cancel_escalated = true;
        }
        kill_sent = true;
      }

      std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }

    if (reader.joinable())
      reader.join();

    bool canceled = false;
    bool timeout_triggered = false;

    {
      std::lock_guard<std::mutex> lock(job->mutex);
      job->worker_pid = -1;
      job->raw_wait_status = status;
      job->ended_time = time(NULL);
      job->ended_monotonic_ms = monotonic_ms_now();

      canceled = job->cancel_requested;
      timeout_triggered = job->timeout_triggered;

      if (wait_error) {
        job->exit_code = -1;
        job->status = "job_failed";
      } else if (WIFEXITED(status)) {
        job->exit_code = WEXITSTATUS(status);
      } else if (WIFSIGNALED(status)) {
        job->exit_code = -WTERMSIG(status);
      } else {
        job->exit_code = -1;
      }

      if (canceled) {
        job->status = "job_canceled";
      } else if (timeout_triggered) {
        job->status = "job_timeout";
      } else if (!wait_error && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
        job->status = "job_completed";
      } else {
        job->status = "job_failed";
      }
    }

    if (canceled) {
      boost::json::object payload;
      payload["cancel_escalated"] = job->cancel_escalated;
      append_event(job, "job_canceled", payload);
    } else if (timeout_triggered) {
      boost::json::object payload;
      payload["timeout_ms"] = (int64_t) job->timeout_ms;
      append_event(job, "job_timeout", payload);
    } else if (!wait_error && WIFEXITED(status) && WEXITSTATUS(status) == 0) {
      append_event(job, "job_completed", boost::json::object());
    } else {
      boost::json::object payload;
      payload["exit_status"] = (int64_t) status;
      payload["wait_error"] = wait_error;
      append_event(job, "job_failed", payload);
    }
  }

  cp_service_config_t cfg;
  std::string binary_path;
  std::string daemon_started_at;

  std::atomic<unsigned long> next_job_id;
  bool stopping;

  std::mutex state_mutex;
  std::condition_variable scheduler_cond;
  std::map<std::string, std::shared_ptr<cp_job_t> > jobs;
  std::deque<std::string> queue;
  std::set<std::string> active_job_ids;
  std::vector<std::thread> worker_threads;

  time_t daemon_start_time;
  uint64_t daemon_start_monotonic_ms;

  std::atomic<uint64_t> session_count;
  std::atomic<uint64_t> total_events;
  std::atomic<uint64_t> total_warnings;
  std::atomic<uint64_t> total_errors;
  std::atomic<uint64_t> total_backpressure;
  std::atomic<uint64_t> total_event_loss;
  std::atomic<uint64_t> total_jobs_queued;
  std::atomic<uint64_t> total_jobs_started;
  std::atomic<uint64_t> total_jobs_completed;
  std::atomic<uint64_t> total_jobs_failed;
  std::atomic<uint64_t> total_jobs_canceled;
  std::atomic<uint64_t> total_jobs_timeout;
};

static std::string extract_token_from_target(const std::string &target) {
  std::string::size_type query_pos = target.find('?');
  if (query_pos == std::string::npos)
    return std::string();

  std::string query = target.substr(query_pos + 1);
  std::string::size_type start = 0;
  while (start < query.size()) {
    std::string::size_type end = query.find('&', start);
    if (end == std::string::npos)
      end = query.size();

    std::string part = query.substr(start, end - start);
    std::string::size_type eq = part.find('=');
    if (eq != std::string::npos && part.substr(0, eq) == "token")
      return part.substr(eq + 1);

    start = end + 1;
  }

  return std::string();
}

static boost::json::object make_response(const std::string &request_id,
                                         const std::string &status,
                                         const boost::json::value &payload,
                                         const std::string &error_text) {
  boost::json::object out;
  out["request_id"] = request_id;
  out["status"] = status;
  out["payload"] = payload;
  if (!error_text.empty())
    out["error"] = error_text;
  return out;
}

static bool ws_send_json(websocket::stream<tcp::socket> &ws,
                         const boost::json::value &value) {
  boost::json::error_code ec;
  std::string body = boost::json::serialize(value);
  ws.write(net::buffer(body), ec);
  return !ec;
}

static boost::json::value make_event_envelope(const std::shared_ptr<cp_job_t> &job,
                                              const cp_event_t &event) {
  boost::json::object obj;
  obj["event_id"] = (int64_t) event.event_id;
  obj["job_id"] = job->job_id;
  obj["event_type"] = event.event_type;
  obj["ts"] = event.ts;
  obj["payload"] = event.payload;
  return obj;
}

static void stream_events(websocket::stream<tcp::socket> &ws,
                          cp_state_t &state,
                          const std::shared_ptr<cp_job_t> &job,
                          uint64_t last_event_id) {
  uint64_t cursor = last_event_id;

  while (true) {
    std::vector<cp_event_t> events = state.events_after(job, cursor, true, 1000);
    for (size_t i = 0; i < events.size(); i++) {
      if (!ws_send_json(ws, make_event_envelope(job, events[i])))
        return;
      cursor = events[i].event_id;
    }

    if (state.is_terminal_status(job) && events.empty())
      return;
  }
}

static bool parse_start_scan_payload(const boost::json::object &payload,
                                     std::vector<std::string> &args,
                                     bool &timeout_requested,
                                     uint64_t &timeout_ms,
                                     std::string &error_text) {
  timeout_requested = false;
  timeout_ms = 0;

  boost::json::object::const_iterator args_it = payload.find("args");
  if (args_it == payload.end() || !args_it->value().is_array()) {
    error_text = "payload.args must be an array of strings";
    return false;
  }

  boost::json::array arr = args_it->value().as_array();
  args.clear();
  for (size_t i = 0; i < arr.size(); i++) {
    if (!arr[i].is_string()) {
      error_text = "payload.args must contain only strings";
      return false;
    }
    args.push_back(std::string(arr[i].as_string().c_str()));
  }

  if (args.empty()) {
    error_text = "payload.args must not be empty";
    return false;
  }

  boost::json::object::const_iterator timeout_it = payload.find("timeout_ms");
  if (timeout_it != payload.end()) {
    if (!timeout_it->value().is_int64()) {
      error_text = "payload.timeout_ms must be an integer when provided";
      return false;
    }

    int64_t requested_timeout = timeout_it->value().as_int64();
    if (requested_timeout <= 0 || requested_timeout > 604800000) {
      error_text = "payload.timeout_ms must be between 1 and 604800000";
      return false;
    }

    timeout_requested = true;
    timeout_ms = (uint64_t) requested_timeout;
  }

  if (!validate_scan_args(args, error_text))
    return false;

  return true;
}

static bool handle_request(websocket::stream<tcp::socket> &ws,
                           cp_state_t &state,
                           const boost::json::object &request_obj) {
  std::string request_id;
  std::string command;

  boost::json::object::const_iterator request_id_it = request_obj.find("request_id");
  if (request_id_it != request_obj.end() && request_id_it->value().is_string())
    request_id = std::string(request_id_it->value().as_string().c_str());

  boost::json::object::const_iterator command_it = request_obj.find("command");
  if (command_it == request_obj.end() || !command_it->value().is_string()) {
    return ws_send_json(ws, make_response(request_id,
                                          "error",
                                          boost::json::object(),
                                          "missing command"));
  }
  command = std::string(command_it->value().as_string().c_str());

  boost::json::object payload;
  boost::json::object::const_iterator payload_it = request_obj.find("payload");
  if (payload_it != request_obj.end() && payload_it->value().is_object())
    payload = payload_it->value().as_object();

  if (command == "ping") {
    boost::json::object pong;
    pong["message"] = "pong";
    return ws_send_json(ws, make_response(request_id, "ok", pong, ""));
  }

  if (command == "get_capabilities") {
    boost::json::object caps;
    boost::json::array commands;
    commands.emplace_back("ping");
    commands.emplace_back("get_capabilities");
    commands.emplace_back("start_scan");
    commands.emplace_back("get_job");
    commands.emplace_back("list_jobs");
    commands.emplace_back("cancel_job");
    commands.emplace_back("subscribe_events");
    commands.emplace_back("get_daemon_diagnostics");
    commands.emplace_back("get_job_diagnostics");
    caps["commands"] = commands;
    caps["max_concurrent_scans"] = (int64_t) state.get_max_active_scans();
    caps["event_delivery"] = "at_least_once_with_replay";
    return ws_send_json(ws, make_response(request_id, "ok", caps, ""));
  }

  if (command == "get_daemon_diagnostics") {
    boost::json::object body = state.daemon_diagnostics();
    return ws_send_json(ws, make_response(request_id, "ok", body, ""));
  }

  if (command == "start_scan") {
    std::vector<std::string> args;
    bool timeout_requested = false;
    uint64_t timeout_ms = 0;
    std::string parse_error;

    if (!parse_start_scan_payload(payload, args, timeout_requested, timeout_ms, parse_error)) {
      return ws_send_json(ws, make_response(request_id,
                                            "error",
                                            boost::json::object(),
                                            parse_error));
    }

    std::shared_ptr<cp_job_t> job = state.create_job(args, timeout_requested, timeout_ms);

    boost::json::object body;
    body["job_id"] = job->job_id;
    body["status"] = "job_queued";
    body["timeout_requested"] = timeout_requested;
    if (timeout_requested)
      body["timeout_ms"] = (int64_t) timeout_ms;
    return ws_send_json(ws, make_response(request_id, "ok", body, ""));
  }

  if (command == "list_jobs") {
    boost::json::object body;
    body["jobs"] = state.list_jobs();
    return ws_send_json(ws, make_response(request_id, "ok", body, ""));
  }

  if (command == "get_job" ||
      command == "cancel_job" ||
      command == "subscribe_events" ||
      command == "get_job_diagnostics") {
    boost::json::object::const_iterator job_id_it = payload.find("job_id");
    if (job_id_it == payload.end() || !job_id_it->value().is_string()) {
      return ws_send_json(ws, make_response(request_id,
                                            "error",
                                            boost::json::object(),
                                            "payload.job_id is required"));
    }

    std::string job_id = std::string(job_id_it->value().as_string().c_str());
    std::shared_ptr<cp_job_t> job = state.get_job(job_id);
    if (!job) {
      return ws_send_json(ws, make_response(request_id,
                                            "error",
                                            boost::json::object(),
                                            "job not found"));
    }

    if (command == "get_job") {
      boost::json::object body;
      {
        std::lock_guard<std::mutex> lock(job->mutex);
        body["job_id"] = job->job_id;
        body["status"] = job->status;
        body["exit_code"] = (int64_t) job->exit_code;
      }
      return ws_send_json(ws, make_response(request_id, "ok", body, ""));
    }

    if (command == "get_job_diagnostics") {
      boost::json::object body;
      std::string diag_error;
      if (!state.job_diagnostics(job_id, body, diag_error)) {
        return ws_send_json(ws, make_response(request_id,
                                              "error",
                                              boost::json::object(),
                                              diag_error));
      }
      return ws_send_json(ws, make_response(request_id, "ok", body, ""));
    }

    if (command == "cancel_job") {
      if (!state.cancel_job(job_id)) {
        return ws_send_json(ws, make_response(request_id,
                                              "error",
                                              boost::json::object(),
                                              "cancel failed"));
      }
      return ws_send_json(ws, make_response(request_id, "ok", boost::json::object(), ""));
    }

    if (command == "subscribe_events") {
      uint64_t last_event_id = 0;
      boost::json::object::const_iterator last_event_it = payload.find("last_event_id");
      if (last_event_it != payload.end() && last_event_it->value().is_int64()) {
        int64_t cursor = last_event_it->value().as_int64();
        if (cursor > 0)
          last_event_id = (uint64_t) cursor;
      }

      if (!ws_send_json(ws, make_response(request_id, "ok", boost::json::object(), "")))
        return false;

      stream_events(ws, state, job, last_event_id);
      return false;
    }
  }

  return ws_send_json(ws,
                      make_response(request_id,
                                    "error",
                                    boost::json::object(),
                                    "unknown command"));
}

static void handle_session(tcp::socket socket,
                           const cp_service_config_t &cfg,
                           cp_state_t &state) {
  beast::error_code ec;
  beast::flat_buffer buffer;
  http::request<http::string_body> req;

  http::read(socket, buffer, req, ec);
  if (ec)
    return;

  std::string token = extract_token_from_target(std::string(req.target()));
  if (token != cfg.auth.token) {
    http::response<http::string_body> res{http::status::unauthorized, req.version()};
    res.set(http::field::content_type, "text/plain");
    res.body() = "unauthorized";
    res.prepare_payload();
    http::write(socket, res, ec);
    return;
  }

  websocket::stream<tcp::socket> ws(std::move(socket));
  ws.read_message_max(1024 * 1024);
  ws.accept(req, ec);
  if (ec)
    return;

  state.note_session_open();

  for (;;) {
    beast::flat_buffer ws_buffer;
    ws.read(ws_buffer, ec);
    if (ec)
      break;

    std::string msg = beast::buffers_to_string(ws_buffer.data());
    boost::json::error_code jec;
    boost::json::value parsed = boost::json::parse(msg, jec);
    if (jec || !parsed.is_object()) {
      ws_send_json(ws,
                   make_response("",
                                 "error",
                                 boost::json::object(),
                                 "invalid json"));
      continue;
    }

    if (!handle_request(ws, state, parsed.as_object()))
      break;
  }

  state.note_session_close();
}

int nmap_service_main(int argc, char *argv[]) {
  cp_cli_parse_t cli;
  std::string parse_error;
  std::string binary_path;

  if (!parse_service_cli(argc, argv, cli, parse_error, binary_path)) {
    std::fprintf(stderr, "Error: %s\n", parse_error.c_str());
    print_daemon_usage(argc > 0 ? argv[0] : "nmap");
    return 2;
  }

  if (cli.help) {
    print_daemon_usage(argc > 0 ? argv[0] : "nmap");
    return 0;
  }

  if (cli.generate_mode) {
    std::string generate_error;
    if (!write_generic_config(cli.generate_path, cli.force, generate_error)) {
      std::fprintf(stderr, "Error: %s\n", generate_error.c_str());
      return 2;
    }

    std::fprintf(stdout,
                 "Wrote daemon config template to %s\n",
                 cli.generate_path.c_str());
    return 0;
  }

  if (!cli.service_mode) {
    std::fprintf(stderr,
                 "Error: daemon options require --service or --service-config-generate\n");
    print_daemon_usage(argc > 0 ? argv[0] : "nmap");
    return 2;
  }

  if (cli.service_config_path.empty()) {
    std::fprintf(stderr, "Error: --service requires --service-config <path>\n");
    print_daemon_usage(argc > 0 ? argv[0] : "nmap");
    return 2;
  }

  if (!cli.runtime_override_flags.empty()) {
    std::fprintf(stderr,
                 "Error: runtime daemon flags are not allowed with --service-config; remove CLI overrides and use config values\n");
    return 2;
  }

  cp_service_config_t cfg;
  std::string cfg_error;
  if (!parse_service_config_file(cli.service_config_path, cfg, cfg_error)) {
    std::fprintf(stderr, "Error: %s\n", cfg_error.c_str());
    return 2;
  }

  boost::system::error_code ec;
  net::ip::address bind_address = net::ip::make_address(cfg.bind_addr, ec);
  if (ec) {
    std::fprintf(stderr, "Error: invalid bind address '%s'\n", cfg.bind_addr.c_str());
    return 2;
  }

  net::io_context ioc;
  tcp::acceptor acceptor(ioc);

  acceptor.open(bind_address.is_v6() ? tcp::v6() : tcp::v4(), ec);
  if (ec) {
    std::fprintf(stderr, "Error: failed to open acceptor: %s\n", ec.message().c_str());
    return 2;
  }

  acceptor.set_option(net::socket_base::reuse_address(true), ec);
  acceptor.bind(tcp::endpoint(bind_address, cfg.port), ec);
  if (ec) {
    std::fprintf(stderr,
                 "Error: failed to bind %s:%u: %s\n",
                 cfg.bind_addr.c_str(),
                 cfg.port,
                 ec.message().c_str());
    return 2;
  }

  acceptor.listen(net::socket_base::max_listen_connections, ec);
  if (ec) {
    std::fprintf(stderr, "Error: failed to listen: %s\n", ec.message().c_str());
    return 2;
  }

  cp_state_t state(cfg, binary_path);
  state.start_workers();

  std::fprintf(stdout,
               "Service mode listening on ws://%s:%u/?token=<token>\n",
               cfg.bind_addr.c_str(),
               cfg.port);
  std::fflush(stdout);

  for (;;) {
    tcp::socket socket(ioc);
    acceptor.accept(socket, ec);
    if (ec)
      continue;

    std::thread session_thread(handle_session,
                               std::move(socket),
                               std::cref(cfg),
                               std::ref(state));
    session_thread.detach();
  }

  state.stop_workers();
  return 0;
}
