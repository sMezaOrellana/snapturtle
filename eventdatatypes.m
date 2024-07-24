#include "eventdatatypes.h"

NSString *formatted_date_str(__darwin_time_t secs_since_1970);
uint64_t MachTimeToNanoseconds(uint64_t machTime);
NSString *SHA1ForFileAtPath(NSString *filePath);
NSString *codesigning_flags_str(const uint32_t codesigning_flags);
const NSString *event_type_str(const es_event_type_t event_type);
NSString *esstring_to_nsstring(const es_string_token_t es_string_token);

#define BOOL_VALUE(x) x ? "Yes" : "No"

NSDictionary *audit_token_to_dict(const audit_token_t *audit_token) {
  return @{
    @"pid" : @(audit_token_to_pid(*audit_token)),
    @"ruid" : @(audit_token_to_ruid(*audit_token)),
    @"euid" : @(audit_token_to_euid(*audit_token)),
    @"rgid" : @(audit_token_to_rgid(*audit_token)),
    @"egid" : @(audit_token_to_egid(*audit_token)),
  };
}

NSDictionary *stat_to_dictionary(const struct stat *stat) {
  return @{
    @"st_dev" : @(stat->st_dev),
    @"st_ino" : @(stat->st_ino),
    @"st_mode" : @(stat->st_mode),
    @"st_nlink" : @(stat->st_nlink),
    @"st_uid" : @(stat->st_uid),
    @"st_gid" : @(stat->st_gid),
    @"st_atime" : formatted_date_str(stat->st_atime),
    @"st_mtime" : formatted_date_str(stat->st_mtime),
    @"st_ctime" : formatted_date_str(stat->st_ctime),
    @"st_birthtime" : formatted_date_str(stat->st_birthtime),
    @"st_size" : @(stat->st_size),
    @"st_blocks" : @(stat->st_blocks),
    @"st_blksize" : @(stat->st_blksize),
    @"st_flags" : @(stat->st_flags),
    @"st_gen" : @(stat->st_gen),
  };
}

NSDictionary *es_file_t_to_dict(const es_file_t *file) {
  NSString *file_path = esstring_to_nsstring(file->path);
  NSString *process_sha1;

  if (S_ISREG(file->stat.st_mode) && file->stat.st_size < 40000000) {
    file_path = esstring_to_nsstring(file->path);
    process_sha1 = SHA1ForFileAtPath(file_path);
  } else {
    process_sha1 = @"";
  }
  return @{
    @"path" : esstring_to_nsstring(file->path),
    @"path_truncated" : @(BOOL_VALUE(file->path_truncated)),
    @"stat" : stat_to_dictionary(&(file->stat)),
    @"sha1" : process_sha1,
  };
}

NSDictionary *es_process_t_to_dict(const es_process_t *proc) {

  NSString *path = esstring_to_nsstring(proc->executable->path);
  NSString *process_sha1 = SHA1ForFileAtPath(path);
  return @{
    @"proc" : @{
      @"audit_token" : audit_token_to_dict(&(proc->audit_token)),
      @"ppid" : @(proc->ppid),
      @"original_ppid" : @(proc->original_ppid),
      @"group_id" : @(proc->group_id),
      @"session_id" : @(proc->session_id),
      @"is_platform_binary" : @(BOOL_VALUE(proc->is_platform_binary)),
      @"is_es_client" : @(BOOL_VALUE(proc->is_es_client)),
      @"signing_id" : esstring_to_nsstring(proc->signing_id),
      @"team_id" : esstring_to_nsstring(proc->team_id),
      @"codesigning_flags" : codesigning_flags_str(proc->codesigning_flags),
      @"executable" : es_file_t_to_dict(proc->executable),
      @"sha1" : process_sha1,
    }
  };
}

NSMutableArray *
exec_command_line_arguments_to_array(const es_event_exec_t *exec) {
  NSMutableArray *list = [NSMutableArray array];

  uint32_t arg_count = es_exec_arg_count(exec);
  for (uint32_t i = 0; i < arg_count; i++) {
    es_string_token_t arg = es_exec_arg(exec, i);
    [list addObject:esstring_to_nsstring(arg)];
  }
  return list;
}

NSDictionary *es_event_exec_to_dict(const es_event_exec_t *exec) {

  return @{
    @"target" : es_process_t_to_dict(exec->target),
    @"command_line_arguments" : exec_command_line_arguments_to_array(exec),

  };
}

NSDictionary *es_event_open_to_dict(const es_event_open_t *open) {
  NSMutableArray *match_flags = [NSMutableArray new];

  if ((open->fflag & FREAD) == FREAD) {
    [match_flags addObject:@"FREAD"];
  }

  if ((open->fflag & FWRITE) == FWRITE) {
    [match_flags addObject:@"FWRITE"];
  }

  return @{
    @"match_flags" : match_flags,
    @"open_file" : es_file_t_to_dict(open->file),
  };
}

NSDictionary *event_to_dict(const es_message_t *msg) {
  switch (msg->event_type) {
  case ES_EVENT_TYPE_AUTH_EXEC: {
    return es_event_exec_to_dict(&msg->event.exec);
  } break;

  case ES_EVENT_TYPE_AUTH_OPEN: {
    return es_event_open_to_dict(&msg->event.open);
  } break;

  case ES_EVENT_TYPE_NOTIFY_FORK: {
  } break;

  case ES_EVENT_TYPE_LAST:
  default: {
  }
  }
  return @{};
}

NSDictionary *event_message_to_dict(const es_message_t *msg) {
  return @{
    @"event_type" : event_type_str(msg->event_type),
    @"process" : es_process_t_to_dict(msg->process),
    @"version" : @(msg->version),
    @"time" : formatted_date_str(msg->time.tv_sec),
    @"mach_time" : @(msg->mach_time),
    @"deadline" : @(msg->deadline),
    @"event" : event_to_dict(msg),
  };
}
