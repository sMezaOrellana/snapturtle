#ifndef EventDataTypes_h
#define EventDataTypes_h

#include <EndpointSecurity/EndpointSecurity.h>
#include <Foundation/Foundation.h>
#include <bsm/libbsm.h>

NSDictionary *audit_token_to_dict(const audit_token_t *audit_token);
NSDictionary *stat_to_dictionary(const struct stat *stat);
NSDictionary *es_file_t_to_dict(const es_file_t *file);
NSDictionary *es_process_t_to_dict(const es_process_t *proc);
NSMutableArray *
exec_command_line_arguments_to_array(const es_event_exec_t *exec);
NSDictionary *es_event_open_to_dict(const es_event_open_t *open);
NSDictionary *event_to_dict(const es_message_t *msg);
NSDictionary *event_message_to_dict(const es_message_t *msg);
#endif
