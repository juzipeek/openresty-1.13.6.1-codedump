
/*
 * Copyright (C) Igor Sysoev
 * Copyright (C) Nginx, Inc.
 */


#ifndef _NGX_HTTP_UPSTREAM_H_INCLUDED_
#define _NGX_HTTP_UPSTREAM_H_INCLUDED_


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_event.h>
#include <ngx_event_connect.h>
#include <ngx_event_pipe.h>
#include <ngx_http.h>


#define NGX_HTTP_UPSTREAM_FT_ERROR           0x00000002
#define NGX_HTTP_UPSTREAM_FT_TIMEOUT         0x00000004
#define NGX_HTTP_UPSTREAM_FT_INVALID_HEADER  0x00000008
#define NGX_HTTP_UPSTREAM_FT_HTTP_500        0x00000010
#define NGX_HTTP_UPSTREAM_FT_HTTP_502        0x00000020
#define NGX_HTTP_UPSTREAM_FT_HTTP_503        0x00000040
#define NGX_HTTP_UPSTREAM_FT_HTTP_504        0x00000080
#define NGX_HTTP_UPSTREAM_FT_HTTP_403        0x00000100
#define NGX_HTTP_UPSTREAM_FT_HTTP_404        0x00000200
#define NGX_HTTP_UPSTREAM_FT_HTTP_429        0x00000400
#define NGX_HTTP_UPSTREAM_FT_UPDATING        0x00000800
#define NGX_HTTP_UPSTREAM_FT_BUSY_LOCK       0x00001000
#define NGX_HTTP_UPSTREAM_FT_MAX_WAITING     0x00002000
#define NGX_HTTP_UPSTREAM_FT_NON_IDEMPOTENT  0x00004000
#define NGX_HTTP_UPSTREAM_FT_NOLIVE          0x40000000
#define NGX_HTTP_UPSTREAM_FT_OFF             0x80000000

#define NGX_HTTP_UPSTREAM_FT_STATUS          (NGX_HTTP_UPSTREAM_FT_HTTP_500  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_502  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_503  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_504  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_403  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_404  \
                                             |NGX_HTTP_UPSTREAM_FT_HTTP_429)

#define NGX_HTTP_UPSTREAM_INVALID_HEADER     40


#define NGX_HTTP_UPSTREAM_IGN_XA_REDIRECT    0x00000002
#define NGX_HTTP_UPSTREAM_IGN_XA_EXPIRES     0x00000004
#define NGX_HTTP_UPSTREAM_IGN_EXPIRES        0x00000008
#define NGX_HTTP_UPSTREAM_IGN_CACHE_CONTROL  0x00000010
#define NGX_HTTP_UPSTREAM_IGN_SET_COOKIE     0x00000020
#define NGX_HTTP_UPSTREAM_IGN_XA_LIMIT_RATE  0x00000040
#define NGX_HTTP_UPSTREAM_IGN_XA_BUFFERING   0x00000080
#define NGX_HTTP_UPSTREAM_IGN_XA_CHARSET     0x00000100
#define NGX_HTTP_UPSTREAM_IGN_VARY           0x00000200


typedef struct {
    ngx_uint_t                       status;
    ngx_msec_t                       response_time;
    ngx_msec_t                       connect_time;
    ngx_msec_t                       header_time;
    off_t                            response_length;
    off_t                            bytes_received;

    ngx_str_t                       *peer;
} ngx_http_upstream_state_t;


typedef struct {
    ngx_hash_t                       headers_in_hash;
    ngx_array_t                      upstreams;
                                             /* ngx_http_upstream_srv_conf_t */
} ngx_http_upstream_main_conf_t;

typedef struct ngx_http_upstream_srv_conf_s  ngx_http_upstream_srv_conf_t;

typedef ngx_int_t (*ngx_http_upstream_init_pt)(ngx_conf_t *cf,
    ngx_http_upstream_srv_conf_t *us);
typedef ngx_int_t (*ngx_http_upstream_init_peer_pt)(ngx_http_request_t *r,
    ngx_http_upstream_srv_conf_t *us);


typedef struct {
    ngx_http_upstream_init_pt        init_upstream;
    ngx_http_upstream_init_peer_pt   init;
    void                            *data;
} ngx_http_upstream_peer_t;


typedef struct {
    ngx_str_t                        name;
    ngx_addr_t                      *addrs;
    ngx_uint_t                       naddrs;
    ngx_uint_t                       weight;
    ngx_uint_t                       max_conns;
    ngx_uint_t                       max_fails;
    time_t                           fail_timeout;
    ngx_msec_t                       slow_start;
    ngx_uint_t                       down;

    unsigned                         backup:1;

    NGX_COMPAT_BEGIN(6)
    NGX_COMPAT_END
} ngx_http_upstream_server_t;


#define NGX_HTTP_UPSTREAM_CREATE        0x0001
#define NGX_HTTP_UPSTREAM_WEIGHT        0x0002
#define NGX_HTTP_UPSTREAM_MAX_FAILS     0x0004
#define NGX_HTTP_UPSTREAM_FAIL_TIMEOUT  0x0008
#define NGX_HTTP_UPSTREAM_DOWN          0x0010
#define NGX_HTTP_UPSTREAM_BACKUP        0x0020
#define NGX_HTTP_UPSTREAM_MAX_CONNS     0x0100


struct ngx_http_upstream_srv_conf_s {
    ngx_http_upstream_peer_t         peer;
    void                           **srv_conf;

    ngx_array_t                     *servers;  /* ngx_http_upstream_server_t */

    ngx_uint_t                       flags;
    ngx_str_t                        host;
    u_char                          *file_name;
    ngx_uint_t                       line;
    in_port_t                        port;
    ngx_uint_t                       no_port;  /* unsigned no_port:1 */

#if (NGX_HTTP_UPSTREAM_ZONE)
    ngx_shm_zone_t                  *shm_zone;
#endif
};


typedef struct {
    ngx_addr_t                      *addr;
    ngx_http_complex_value_t        *value;
#if (NGX_HAVE_TRANSPARENT_PROXY)
    ngx_uint_t                       transparent; /* unsigned  transparent:1; */
#endif
} ngx_http_upstream_local_t;


typedef struct {
    ngx_http_upstream_srv_conf_t    *upstream;

    // 建立TCP连接的超时时间，实际上就是写事件添加到定时器中设置的超时时间
    ngx_msec_t                       connect_timeout;
    // 发送请求的超时时间
    ngx_msec_t                       send_timeout;
    // 接收响应的超时时间
    ngx_msec_t                       read_timeout;
    ngx_msec_t                       next_upstream_timeout;

    // TCP的SO_SNOLOWAT选项，表示发送缓冲区的下限
    size_t                           send_lowat;
    // 定义了接收头部的缓冲区分配的内存大小（ngx_http_upstream_t中的buffer缓冲区），当不转
    // 发响应给下游或者在buffering标志位为0的情况下转发响应时，它同样表示接收包体的缓冲区大小
    size_t                           buffer_size;
    size_t                           limit_rate;

    // 仅当buffering标志位为1，并且向下游转发响应时生效，它会设置到ngx_event_pipt_t结构体
    // 的busy_size成员中
    size_t                           busy_buffers_size;

    // 在buffering为1时，如果上游速度快于下游速度，将有可能将来自上游的响应存储到临时文件中，
    // 而max_temp_file_size指定了临时文件的最大长度，实际上它将限制ngx_event_pipt_t结构中的temp_file
    size_t                           max_temp_file_size;
    // 表示将缓冲区中的响应写入临时文件时一次写入字符流的最大长度
    size_t                           temp_file_write_size;

    size_t                           busy_buffers_size_conf;
    size_t                           max_temp_file_size_conf;
    size_t                           temp_file_write_size_conf;

    // 将缓存响应的方式转发上游服务器的包体时所使用的内存大小
    ngx_bufs_t                       bufs;

    // 针对ngx_http_upstream_t结构体中保存解析完的包头的header_in成员，
    // ignore_headers可以按照二进制位使得upstream在转发包头时跳过对某些包头的处理。
    ngx_uint_t                       ignore_headers;

    // 以二进制位来保存一些错误码，如果处理上游响应时发现这些错误码，那么在没有将
    // 响应转发给下游客户端时，将会选择下一个上游服务器来重发请求
    ngx_uint_t                       next_upstream;

    // 在buffering为1的情况下转发响应时，将有可能把响应存放到临时文件中。
    //
    ngx_uint_t                       store_access;

    ngx_uint_t                       next_upstream_tries;

    // 决定转发响应方式的标志位，buffering为1时表示打开缓存，这时认为上游的网速
    // 快于下游的网速，会尽量在内存或磁盘中缓存来自上游的响应，如果buffering为0，
    // 仅会开辟一块固定大小的内存块作为缓存来转发响应
    ngx_flag_t                       buffering;
    ngx_flag_t                       request_buffering;
    ngx_flag_t                       pass_request_headers;
    ngx_flag_t                       pass_request_body;

    // 为1时表示与上游服务器交互时将不检查Nginx与下游客户端间的连接是否断开。
    // 也就是说，即使下游客户端主动关闭了连接，也不会中断与上游服务器的交互。
    ngx_flag_t                       ignore_client_abort;

    // 当解析上游响应的包头时，如果解析后设置到headers_in结构体中的status_n错误码大于400，
    // 则会试图把它与error_page中指定的错误码相匹配，如果匹配上则发送error_page中指定的
    // 响应，否则继续返回上游服务器的错误码。
    ngx_flag_t                       intercept_errors;

    // buffering为1的情况下转发响应时才有意义。这时，如果cyclic_temp_file为1，则会试图
    // 复用临时文件中已经使用过的空间。
    ngx_flag_t                       cyclic_temp_file;
    ngx_flag_t                       force_ranges;

    // 存放临时文件的路径
    ngx_path_t                      *temp_path;

    // 不转发的头部
    ngx_hash_t                       hide_headers_hash;

    // 当转发上游响应头部（ngx_http_upstream_t中headers_in结构体的头部）给下游客户端时，
    // 如果不希望某些头部转发给下游，就设置到hide_headers中
    ngx_array_t                     *hide_headers;

    // 与hide_headers相反，希望转发的放在pass_headers中
    ngx_array_t                     *pass_headers;

    ngx_http_upstream_local_t       *local;

#if (NGX_HTTP_CACHE)
    ngx_shm_zone_t                  *cache_zone;
    ngx_http_complex_value_t        *cache_value;

    ngx_uint_t                       cache_min_uses;
    ngx_uint_t                       cache_use_stale;
    ngx_uint_t                       cache_methods;

    off_t                            cache_max_range_offset;

    ngx_flag_t                       cache_lock;
    ngx_msec_t                       cache_lock_timeout;
    ngx_msec_t                       cache_lock_age;

    ngx_flag_t                       cache_revalidate;
    ngx_flag_t                       cache_convert_head;
    ngx_flag_t                       cache_background_update;

    ngx_array_t                     *cache_valid;
    ngx_array_t                     *cache_bypass;
    ngx_array_t                     *cache_purge;
    ngx_array_t                     *no_cache;
#endif

    // 当ngx_http_upstream_t中的store标志位为1，如果需要将上游的响应发到文件，
    // store_lengths存放路径长度，store_values存放路径
    ngx_array_t                     *store_lengths;
    ngx_array_t                     *store_values;

#if (NGX_HTTP_CACHE)
    signed                           cache:2;
#endif
    signed                           store:2;
    unsigned                         intercept_404:1;
    unsigned                         change_buffering:1;

#if (NGX_HTTP_SSL || NGX_COMPAT)
    ngx_ssl_t                       *ssl;
    ngx_flag_t                       ssl_session_reuse;

    ngx_http_complex_value_t        *ssl_name;
    ngx_flag_t                       ssl_server_name;
    ngx_flag_t                       ssl_verify;
#endif

    ngx_str_t                        module;

    NGX_COMPAT_BEGIN(2)
    NGX_COMPAT_END
} ngx_http_upstream_conf_t;


typedef struct {
    ngx_str_t                        name;
    ngx_http_header_handler_pt       handler;
    ngx_uint_t                       offset;
    ngx_http_header_handler_pt       copy_handler;
    ngx_uint_t                       conf;
    ngx_uint_t                       redirect;  /* unsigned   redirect:1; */
} ngx_http_upstream_header_t;


typedef struct {
    ngx_list_t                       headers;

    ngx_uint_t                       status_n;
    ngx_str_t                        status_line;

    ngx_table_elt_t                 *status;
    ngx_table_elt_t                 *date;
    ngx_table_elt_t                 *server;
    ngx_table_elt_t                 *connection;

    ngx_table_elt_t                 *expires;
    ngx_table_elt_t                 *etag;
    ngx_table_elt_t                 *x_accel_expires;
    ngx_table_elt_t                 *x_accel_redirect;
    ngx_table_elt_t                 *x_accel_limit_rate;

    ngx_table_elt_t                 *content_type;
    ngx_table_elt_t                 *content_length;

    ngx_table_elt_t                 *last_modified;
    ngx_table_elt_t                 *location;
    ngx_table_elt_t                 *accept_ranges;
    ngx_table_elt_t                 *www_authenticate;
    ngx_table_elt_t                 *transfer_encoding;
    ngx_table_elt_t                 *vary;

#if (NGX_HTTP_GZIP)
    ngx_table_elt_t                 *content_encoding;
#endif

    ngx_array_t                      cache_control;
    ngx_array_t                      cookies;

    off_t                            content_length_n;
    time_t                           last_modified_time;

    unsigned                         connection_close:1;
    unsigned                         chunked:1;
} ngx_http_upstream_headers_in_t;


typedef struct {
    ngx_str_t                        host;
    in_port_t                        port;
    ngx_uint_t                       no_port; /* unsigned no_port:1 */

    ngx_uint_t                       naddrs;
    ngx_resolver_addr_t             *addrs;

    struct sockaddr                 *sockaddr;
    socklen_t                        socklen;
    ngx_str_t                        name;

    ngx_resolver_ctx_t              *ctx;
} ngx_http_upstream_resolved_t;


typedef void (*ngx_http_upstream_handler_pt)(ngx_http_request_t *r,
    ngx_http_upstream_t *u);


struct ngx_http_upstream_s {
    // 读事件的回调函数，每个阶段对应不能的读回调函数
    ngx_http_upstream_handler_pt     read_event_handler;
    // 写事件的回调函数，每个阶段对应不能的写回调函数
    ngx_http_upstream_handler_pt     write_event_handler;
    // 主动向upstream发起的连接
    ngx_peer_connection_t            peer;
    // 当向下游客户端转发响应时，如果打开了缓存并且认为上游网速更快(conf配置中的buffering为1)，
    // 这时会使用pipe成员来转发响应。在使用这种方式的时候，必须由HTTP模块在使用upstream机制
    // 前构造pipe结构体，否则会出现严重的coredump
    ngx_event_pipe_t                *pipe;

    ngx_chain_t                     *request_bufs;

    // 定义了向下游发送响应的方式
    ngx_output_chain_ctx_t           output;
    ngx_chain_writer_ctx_t           writer;

    // 使用upstream机制时的各种配置
    ngx_http_upstream_conf_t        *conf;
    ngx_http_upstream_srv_conf_t    *upstream;
#if (NGX_HTTP_CACHE)
    ngx_array_t                     *caches;
#endif

#define HAVE_NGX_UPSTREAM_TIMEOUT_FIELDS  1
    ngx_msec_t                       connect_timeout;
    ngx_msec_t                       send_timeout;
    ngx_msec_t                       read_timeout;

    ngx_http_upstream_headers_in_t   headers_in;

    ngx_http_upstream_resolved_t    *resolved;

    ngx_buf_t                        from_client;

    // 接收上游服务器响应包头的缓冲区，在不需要把响应直接转发给客户端，
    // 或者buffering标志位为0的情况下转发包体时，接收包体的缓冲区仍然
    // 使用buffer。注意，如果没有定义input_filter方法处理包体，将会使用
    // buffer存储全部的包体，这时buffer必须足够大。它的大小由ngx_http_upstream_conf_t
    // 中的buffer_size配置项决定
    ngx_buf_t                        buffer;

    // 表示来自上游服务器的响应包体长度
    off_t                            length;

    // out_bufs在两种场景下有不同的意义：1）当不需要转发包体，且使用默认的input_filter
    // 方法（ngx_http_upstream_non_buffered_filter）处理包体时，out_bufs将会指向响应体，
    // 事实上，out_bufs链表将会产生多个ngx_buf_t缓冲区，每个缓冲区都指向buffer缓存中的一部分。
    // 而这里的一部分就是每次调用recv方法收到的一段TCP流。2）当需要转发响应体到下游时(buffering为0，
    // 即以下游网速优先)，这个链表指向上一次向下游转发响应到现在这段时间内接收自上游的缓存响应。
    ngx_chain_t                     *out_bufs;

    // 当需要转发响应包体到下游时（buffering为0，以下游网速优先），它表示上一次向下游转发
    // 响应时没有发送完的内容
    ngx_chain_t                     *busy_bufs;

    // 这个链表将用于回收out_bufs中已经发送给下游的ngx_buf_t结构体，这同样应用在buffering为0
    // 即以下游网速优先的场景下
    ngx_chain_t                     *free_bufs;

    /*
     * 处理包体前的初始化方法；
     * 其中data参数用于传递用户数据结构，就是下面成员input_filter_ctx
     */
    ngx_int_t                      (*input_filter_init)(void *data);
    /*
     * 处理包体的方法；
     * 其中data参数用于传递用户数据结构，就是下面成员input_filter_ctx，
     * bytes表示本次接收到包体的长度；
     */
    ngx_int_t                      (*input_filter)(void *data, ssize_t bytes);
    /* 用于传递HTTP自定义的数据结构 */
    void                            *input_filter_ctx;

#if (NGX_HTTP_CACHE)
    ngx_int_t                      (*create_key)(ngx_http_request_t *r);
#endif
    /* HTTP模块实现的create_request方法用于构造发往上游服务器的请求 */
    ngx_int_t                      (*create_request)(ngx_http_request_t *r);
    /* 与上游服务器的通信失败后，若想再次向上游服务器发起连接，则调用该函数 */
    ngx_int_t                      (*reinit_request)(ngx_http_request_t *r);
    /*
     * 解析上游服务器返回的响应包头，该函数返回四个值中的一个：
     * NGX_AGAIN                            表示包头没有接收完整；
     * NGX_HTTP_UPSTREAM_INVALID_HEADER     表示包头不合法；
     * NGX_ERROR                            表示出现错误；
     * NGX_OK                               表示解析到完整的包头；
     */
    ngx_int_t                      (*process_header)(ngx_http_request_t *r);
    /* 当客户端放弃请求时被调用，由于系统会自动关闭连接，因此，该函数不会进行任何具体操作 */
    void                           (*abort_request)(ngx_http_request_t *r);
    /* 结束upstream请求时会调用该函数 */
    void                           (*finalize_request)(ngx_http_request_t *r,
                                         ngx_int_t rc);
    /*
     * 在上游返回的响应出现location或者refresh头部表示重定向时，
     * 会通过ngx_http_upstream_process_headers方法调用到可由HTTP模块
     * 实现的rewrite_redirect方法；
     */
    ngx_int_t                      (*rewrite_redirect)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h, size_t prefix);
    ngx_int_t                      (*rewrite_cookie)(ngx_http_request_t *r,
                                         ngx_table_elt_t *h);

    ngx_msec_t                       timeout;

    // 表示上游响应的错误码、包体长度等信息
    ngx_http_upstream_state_t       *state;

    ngx_str_t                        method;
    ngx_str_t                        schema;
    ngx_str_t                        uri;

#if (NGX_HTTP_SSL || NGX_COMPAT)
    ngx_str_t                        ssl_name;
#endif

    ngx_http_cleanup_pt             *cleanup;

    // 是否指定文件缓存路径的标志位
    unsigned                         store:1;
    // 是否启用文件缓存
    unsigned                         cacheable:1;
    unsigned                         accel:1;
    // 是否基于SSL协议访问上游服务器
    unsigned                         ssl:1;
#if (NGX_HTTP_CACHE)
    unsigned                         cache_status:3;
#endif

    // 向下游转发上游的响应包体时，是否开启更大的内存及临时磁盘文件用于缓存来不及发送
    // 到下游的响应包体
    unsigned                         buffering:1;
    unsigned                         keepalive:1;
    unsigned                         upgrade:1;

    // 表示是否已经向上游服务器发送了请求，当request_sent为1时，表示upstream机制已经向
    // 上游服务器发送了全部或者部分的请求，事实上这个标志位更多的是为了使用ngx_output_chain
    // 方法发送请求，因为该方法发送请求时会自动把未发送完的request_bufs链表记录下来，为了
    // 防止反复发送重复请求，必须有request_sent标志位来记录是否调用过ngx_output_chain方法
    unsigned                         request_sent:1;
    unsigned                         request_body_sent:1;
    // 为1表示把包头转发给客户端了，如果不转发响应给客户端，这个标志位没有意义
    unsigned                         header_sent:1;
};


typedef struct {
    ngx_uint_t                      status;
    ngx_uint_t                      mask;
} ngx_http_upstream_next_t;


typedef struct {
    ngx_str_t   key;
    ngx_str_t   value;
    ngx_uint_t  skip_empty;
} ngx_http_upstream_param_t;


ngx_int_t ngx_http_upstream_create(ngx_http_request_t *r);
void ngx_http_upstream_init(ngx_http_request_t *r);
ngx_http_upstream_srv_conf_t *ngx_http_upstream_add(ngx_conf_t *cf,
    ngx_url_t *u, ngx_uint_t flags);
char *ngx_http_upstream_bind_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
char *ngx_http_upstream_param_set_slot(ngx_conf_t *cf, ngx_command_t *cmd,
    void *conf);
ngx_int_t ngx_http_upstream_hide_headers_hash(ngx_conf_t *cf,
    ngx_http_upstream_conf_t *conf, ngx_http_upstream_conf_t *prev,
    ngx_str_t *default_hide_headers, ngx_hash_init_t *hash);


#define ngx_http_conf_upstream_srv_conf(uscf, module)                         \
    uscf->srv_conf[module.ctx_index]


extern ngx_module_t        ngx_http_upstream_module;
extern ngx_conf_bitmask_t  ngx_http_upstream_cache_method_mask[];
extern ngx_conf_bitmask_t  ngx_http_upstream_ignore_headers_masks[];

#define HAVE_BALANCER_STATUS_CODE_PATCH

#endif /* _NGX_HTTP_UPSTREAM_H_INCLUDED_ */
