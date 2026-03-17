#ifndef CONTROL_PLANE_EVENTS_H
#define CONTROL_PLANE_EVENTS_H

#include <string>

void cp_set_worker_mode(bool enabled);
bool cp_is_worker_mode();

std::string cp_json_escape(const std::string &value);
std::string cp_now_iso8601_utc();

void cp_emit_event_json(const std::string &event_type,
                        const std::string &payload_json);

#endif
