#ifndef __TC_TRACK_H_
#define __TC_TRACK_H_

#define MAX_HTTP_HEADER_SIZE	4096 // 4KB
#define MAX_HTTP_PATH_LENGTH	256
#define MAX_HTTP_METHOD_LENGTH	8

typedef struct http_event {
	__u64 timestamp_ns;
	__u32 src_ip;
	__u32 dst_ip;
	__u32 pid;
//	__u16 header_size;
	char method[MAX_HTTP_METHOD_LENGTH];
	char path[MAX_HTTP_PATH_LENGTH];
//	char raw_header[MAX_HTTP_HEADER_SIZE];
} ip_event_t;

#endif /* __TC_TRACK_H_ */
