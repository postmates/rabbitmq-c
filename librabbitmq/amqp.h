#ifndef librabbitmq_amqp_h
#define librabbitmq_amqp_h

/*
 * ***** BEGIN LICENSE BLOCK *****
 * Version: MIT
 *
 * Portions created by VMware are Copyright (c) 2007-2012 VMware, Inc.
 * All Rights Reserved.
 *
 * Portions created by Tony Garnock-Jones are Copyright (c) 2009-2010
 * VMware, Inc. and Tony Garnock-Jones. All Rights Reserved.
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use, copy,
 * modify, merge, publish, distribute, sublicense, and/or sell copies
 * of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS
 * BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN
 * ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
 * CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 * ***** END LICENSE BLOCK *****
 */

#include <stdint.h>
#include <stddef.h>

#ifdef __cplusplus
extern "C" {
#endif

#ifdef  _WIN32
#ifdef BUILDING_LIBRABBITMQ
#define RABBITMQ_EXPORT extern __declspec(dllexport)
#else
#define RABBITMQ_EXPORT extern __declspec(dllimport)
#endif
#else
#define RABBITMQ_EXPORT extern
#endif

typedef int amqp_boolean_t;
typedef uint32_t amqp_method_number_t;
typedef uint32_t amqp_flags_t;
typedef uint16_t amqp_channel_t;

typedef struct amqp_bytes_t_ {
  size_t len;
  void *bytes;
} amqp_bytes_t;

typedef struct amqp_decimal_t_ {
  uint8_t decimals;
  uint32_t value;
} amqp_decimal_t;

typedef struct amqp_table_t_ {
  int num_entries;
  struct amqp_table_entry_t_ *entries;
} amqp_table_t;

typedef struct amqp_array_t_ {
  int num_entries;
  struct amqp_field_value_t_ *entries;
} amqp_array_t;

/*
  0-9   0-9-1   Qpid/Rabbit  Type               Remarks
---------------------------------------------------------------------------
        t       t            Boolean
        b       b            Signed 8-bit
        B                    Unsigned 8-bit
        U       s            Signed 16-bit	(A1)
        u                    Unsigned 16-bit
  I     I       I	     Signed 32-bit
        i		     Unsigned 32-bit
        L       l	     Signed 64-bit	(B)
        l		     Unsigned 64-bit
        f       f	     32-bit float
        d       d	     64-bit float
  D     D       D	     Decimal
        s		     Short string	(A2)
  S     S       S	     Long string
        A		     Nested Array
  T     T       T	     Timestamp (u64)
  F     F       F	     Nested Table
  V     V       V	     Void
                x	     Byte array

Remarks:

 A1, A2: Notice how the types **CONFLICT** here. In Qpid and Rabbit,
         's' means a signed 16-bit integer; in 0-9-1, it means a
	 short string.

 B: Notice how the signednesses **CONFLICT** here. In Qpid and Rabbit,
    'l' means a signed 64-bit integer; in 0-9-1, it means an unsigned
    64-bit integer.

I'm going with the Qpid/Rabbit types, where there's a conflict, and
the 0-9-1 types otherwise. 0-8 is a subset of 0-9, which is a subset
of the other two, so this will work for both 0-8 and 0-9-1 branches of
the code.
*/

typedef struct amqp_field_value_t_ {
  uint8_t kind;
  union {
    amqp_boolean_t boolean;
    int8_t i8;
    uint8_t u8;
    int16_t i16;
    uint16_t u16;
    int32_t i32;
    uint32_t u32;
    int64_t i64;
    uint64_t u64;
    float f32;
    double f64;
    amqp_decimal_t decimal;
    amqp_bytes_t bytes;
    amqp_table_t table;
    amqp_array_t array;
  } value;
} amqp_field_value_t;

typedef struct amqp_table_entry_t_ {
  amqp_bytes_t key;
  amqp_field_value_t value;
} amqp_table_entry_t;

typedef enum {
  AMQP_FIELD_KIND_BOOLEAN = 't',
  AMQP_FIELD_KIND_I8 = 'b',
  AMQP_FIELD_KIND_U8 = 'B',
  AMQP_FIELD_KIND_I16 = 's',
  AMQP_FIELD_KIND_U16 = 'u',
  AMQP_FIELD_KIND_I32 = 'I',
  AMQP_FIELD_KIND_U32 = 'i',
  AMQP_FIELD_KIND_I64 = 'l',
  AMQP_FIELD_KIND_U64 = 'L',
  AMQP_FIELD_KIND_F32 = 'f',
  AMQP_FIELD_KIND_F64 = 'd',
  AMQP_FIELD_KIND_DECIMAL = 'D',
  AMQP_FIELD_KIND_UTF8 = 'S',
  AMQP_FIELD_KIND_ARRAY = 'A',
  AMQP_FIELD_KIND_TIMESTAMP = 'T',
  AMQP_FIELD_KIND_TABLE = 'F',
  AMQP_FIELD_KIND_VOID = 'V',
  AMQP_FIELD_KIND_BYTES = 'x'
} amqp_field_value_kind_t;

typedef struct amqp_pool_blocklist_t_ {
  int num_blocks;
  void **blocklist;
} amqp_pool_blocklist_t;

typedef struct amqp_pool_t_ {
  size_t pagesize;

  amqp_pool_blocklist_t pages;
  amqp_pool_blocklist_t large_blocks;

  int next_page;
  char *alloc_block;
  size_t alloc_used;
} amqp_pool_t;

typedef struct amqp_method_t_ {
  amqp_method_number_t id;
  void *decoded;
} amqp_method_t;

typedef struct amqp_frame_t_ {
  uint8_t frame_type; /* 0 means no event */
  amqp_channel_t channel;
  union {
    amqp_method_t method;
    struct {
      uint16_t class_id;
      uint64_t body_size;
      void *decoded;
      amqp_bytes_t raw;
    } properties;
    amqp_bytes_t body_fragment;
    struct {
      uint8_t transport_high;
      uint8_t transport_low;
      uint8_t protocol_version_major;
      uint8_t protocol_version_minor;
    } protocol_header;
  } payload;
} amqp_frame_t;

typedef enum amqp_response_type_enum_ {
  AMQP_RESPONSE_NONE = 0,
  AMQP_RESPONSE_NORMAL,
  AMQP_RESPONSE_LIBRARY_EXCEPTION,
  AMQP_RESPONSE_SERVER_EXCEPTION
} amqp_response_type_enum;

typedef struct amqp_rpc_reply_t_ {
  amqp_response_type_enum reply_type;
  amqp_method_t reply;
  int library_error; /* if AMQP_RESPONSE_LIBRARY_EXCEPTION, then 0 here means socket EOF */
} amqp_rpc_reply_t;

typedef enum amqp_sasl_method_enum_ {
  AMQP_SASL_METHOD_PLAIN = 0
} amqp_sasl_method_enum;

/* Opaque struct. */
typedef struct amqp_connection_state_t_ *amqp_connection_state_t;

/**
 * @brief Gets the version string for the library
 *
 * Gets the library version. Format will be of the form vX.Y
 * where X is the major verion, Y is the minor version.
 * Memory for the string is owned by the library.
 *
 */
RABBITMQ_EXPORT char const *amqp_version(void);

/* Exported empty data structures */
RABBITMQ_EXPORT const amqp_bytes_t amqp_empty_bytes;
RABBITMQ_EXPORT const amqp_table_t amqp_empty_table;
RABBITMQ_EXPORT const amqp_array_t amqp_empty_array;

/* Compatibility macros for the above, to avoid the need to update
   code written against earlier versions of librabbitmq. */
#define AMQP_EMPTY_BYTES amqp_empty_bytes
#define AMQP_EMPTY_TABLE amqp_empty_table
#define AMQP_EMPTY_ARRAY amqp_empty_array

/**
 * @brief initializes an \ref amqp_pool_t memory pool
 *
 * @param pool a pointer to the amqp_pool_t to be initialized
 * @param pagesize the minimum allocation size in the pool. Any allocations
 *        made using amqp_pool_alloc smaller than pagesize will make using
 *        a page of this size, larger allocations will be made using the size
 *        of the allocation requested in a 'large page pool'
 */
RABBITMQ_EXPORT void init_amqp_pool(amqp_pool_t *pool, size_t pagesize);
/**
 * @brief recycles memory associated with an \ref amqp_pool_t memory pool
 *
 * Recycles the memory in the amqp_pool_t. Freeing any memory that are considered
 * 'large pages'
 * Use of pointers that were returned by amqp_pool_alloc from the pool that
 * is being recycled, the effects are undefined (the pointers may or may not
 * be valid).
 * 
 * @param pool a pointed to the amqp_pool_t to be recycled
 */
RABBITMQ_EXPORT void recycle_amqp_pool(amqp_pool_t *pool);
/**
 * @brief frees all memory associated with an \ref amqp_pool_t memory pool
 *
 * Frees all memory associated with an \ref amqp_pool_t memory pool
 *
 * @param pool the pool to empty
 */
RABBITMQ_EXPORT void empty_amqp_pool(amqp_pool_t *pool);

/**
 * @brief allocates memory from an \ref amqp_pool_t
 *
 * @param pool a pointer to the pool to allocate the memory from
 * @param amount the number of bytes to allocate
 * @returns a pointer to the allocated memory, NULL on error
 */
RABBITMQ_EXPORT void *amqp_pool_alloc(amqp_pool_t *pool, size_t amount);
/**
 * @brief allocates memory from an \ref amqp_pool_t and puts it in a \ref amqp_bytes_t structure
 *
 * If allocation fails, output.bytes will be NULL
 * 
 * @param pool a pointer to the \ref amqp_pool_t memory to allocate from
 * @param amount the number of bytes to allocate
 * @param output a amqp_bytes_t structure to store the pointer and length
 */
RABBITMQ_EXPORT void amqp_pool_alloc_bytes(amqp_pool_t *pool,
                                          size_t amount, amqp_bytes_t *output);

/**
 * @brief creates an amqp_bytes_t structure from a c-string
 *
 * Creates an amqp_bytes_t structre from a c-string.
 * output.bytes = cstr
 * output.len = strlen(cstr)
 * NOTE: no memory is allocated by this function, the pointer is simply copied
 *
 * @param cstr the cstring to assign to the amqp_bytes_t structure
 * @returns amqp_bytes_t
 */
RABBITMQ_EXPORT amqp_bytes_t amqp_cstring_bytes(char const *cstr);

/**
 * @brief creates a copy of an amqp_bytes_t structure
 *
 * Duplicates a amqp_bytes_t structure, duplicating the memory it refers to.
 * amqp_bytes_t objects created with this function should be freed with
 * amqp_bytes_free
 *
 * @param src the amqp_bytes_t structure to be duplicated
 * @returns a duplicate of src, output.bytes will be NULL on error
 */
RABBITMQ_EXPORT amqp_bytes_t amqp_bytes_malloc_dup(amqp_bytes_t src);
/**
 * @brief Allocates a amqp_bytes_t structure with a given size
 *
 * Allocates an amqp_bytes_t structure with a given size. amqp_bytes_t 
 * structures. amqp_bytes_t objects created with this function should be
 * freed using amqp_bytes_free
 *
 * @param amount the size that the amqp_bytes_t structure should point to
 * @returns amqp_bytes_t, output.bytes will be NULL on error
 */
RABBITMQ_EXPORT amqp_bytes_t amqp_bytes_malloc(size_t amount);
/**
 * @brief free memory allocated with amqp_bytes_malloc or amqp_bytes_malloc_dup
 *
 * @param bytes the amqp_bytes_t to free
 */
RABBITMQ_EXPORT void amqp_bytes_free(amqp_bytes_t bytes);

/**
 * @brief Create and initialize a new amqp_connection_state_t object
 *
 * @returns amqp_connection_state_t object, NULL in case of failure
 */
RABBITMQ_EXPORT amqp_connection_state_t amqp_new_connection(void);

/**
 * @brief Get the socket file descriptor associated with a amqp_connection_state_t object
 *
 * @param state the amqp_connection_state_t to retrieve the socket from
 * @returns the socket descriptor associated with the connection, 0 if there isn't one
 */
RABBITMQ_EXPORT int amqp_get_sockfd(amqp_connection_state_t state);
/**
 * @brief Set the socket file descriptor associated with an amqp_connection_state_t object
 *
 * Sets the socket file descriptor associated with an amqp_connection_state_t object,
 * note that this function will overwrite an existing file descriptor without checking
 * to see if an existing socket is associated and connected, setting with a connected
 * socket will lead to undefined behavior
 *
 * @param state the amqp_connection_state_t to set the socket for
 * @param sockfd the socket file descriptor
 */
RABBITMQ_EXPORT void amqp_set_sockfd(amqp_connection_state_t state,
				     int sockfd);
/**
 * @brief Sets connection-wide amqp_connection_state_t parameters with the broker
 *
 * Sets connection-wide amqp_connection_state_t parameters with the broker.
 *
 * @param state
 * @param channel_max the maximum number of channels, 0 = no limit, 2, is the minimum, 65536 is the maximum
 * @param frame_max the maximum frame size in bytes. Minimum is 4096, 
 * @param heartbeat
 * @returns
 */
RABBITMQ_EXPORT int amqp_tune_connection(amqp_connection_state_t state,
					 int channel_max,
					 int frame_max,
					 int heartbeat);
/**
 * @brief Gets the maximum number of channels supported by this connection
 *
 * @param state
 * @returns the maximum number of channels supported by this connection
 */
RABBITMQ_EXPORT int amqp_get_channel_max(amqp_connection_state_t state);
/**
 * @brief Destroys a amqp_connection_state_t object created with amqp_new_connection
 *
 * @param state
 * @return
 */
RABBITMQ_EXPORT int amqp_destroy_connection(amqp_connection_state_t state);

/**
 * @brief Given some input handle it handles it an might fill in a frame object
 *
 * @param state
 * @param received_data
 * @param decoded_frame
 * @return
 */
RABBITMQ_EXPORT int amqp_handle_input(amqp_connection_state_t state,
				      amqp_bytes_t received_data,
				      amqp_frame_t *decoded_frame);

/**
 * @brief Determines whether its ok to release buffers
 *
 * @param state
 * @returns
 */
RABBITMQ_EXPORT amqp_boolean_t amqp_release_buffers_ok(
                                                amqp_connection_state_t state);

/**
 * @brief Unconditionally recycles the buffers associated with provided connection
 *
 * @param state
 */
RABBITMQ_EXPORT void amqp_release_buffers(amqp_connection_state_t state);

/**
 * @brief Recycles the buffers associated with the provided connection if its ok to do so
 *
 * @param state
 */
RABBITMQ_EXPORT void amqp_maybe_release_buffers(amqp_connection_state_t state);

/**
 * @brief Sends a frame to the broker
 *
 * @param state
 * @param frame
 * @returns
 */
RABBITMQ_EXPORT int amqp_send_frame(amqp_connection_state_t state,
				    amqp_frame_t const *frame);

/**
 * @brief Compares two table entries
 *
 * @param entry1
 * @param entry2
 * @returns
 */
RABBITMQ_EXPORT int amqp_table_entry_cmp(void const *entry1,
					 void const *entry2);

/**
 * @brief Opens a socket to a host on a port
 *
 * @param hostname the hostname or IP address to connect to
 * @param port the port on the hostname to attempt connecting to
 * @returns a socket file descriptor
 */
RABBITMQ_EXPORT int amqp_open_socket(char const *hostname,
				     int portnumber);

/**
 * @brief Send a handshake to the broker
 *
 * @param state
 * @returns
 */
RABBITMQ_EXPORT int amqp_send_header(amqp_connection_state_t state);

/**
 * @brief Checks to see if there are any inbound frames queued up
 *
 * @param state
 * @returns
 */
RABBITMQ_EXPORT amqp_boolean_t amqp_frames_enqueued(
                                               amqp_connection_state_t state);

/**
 * @brief Does a blocking wait for a single frame from the broker
 *
 * @param state
 * @param decoded_frame
 * @returns
 */
RABBITMQ_EXPORT int amqp_simple_wait_frame(amqp_connection_state_t state,
					   amqp_frame_t *decoded_frame);

/**
 * @brief Sends a method to the broker and waits for a reply
 *
 * @param state
 * @param channel
 * @param request_id
 * @param expected_reply_ids
 * @param decoded_request_method
 * @returns
 */
RABBITMQ_EXPORT amqp_rpc_reply_t amqp_simple_rpc(amqp_connection_state_t state,
                                      amqp_channel_t channel,
                                      amqp_method_number_t request_id,
                                      amqp_method_number_t *expected_reply_ids,
                                      void *decoded_request_method);

/**
 * @brief Sends a method to the broker and waits for a reply
 *
 * @param state
 * @param channel
 * @param request_id
 * @param reply_id
 * @param decoded_request_method
 * @returns
 */
RABBITMQ_EXPORT void *amqp_simple_rpc_decoded(amqp_connection_state_t state,
					      amqp_channel_t channel,
					      amqp_method_number_t request_id,
					      amqp_method_number_t reply_id,
					      void *decoded_request_method);

/**
 * @brief Checks for the result of the last RPC
 *
 * The API methods corresponding to most synchronous AMQP methods
 * return a pointer to the decoded method result.  Upon error, they
 * return NULL, and we need some way of discovering what, if anything,
 * went wrong. amqp_get_rpc_reply() returns the most recent
 * amqp_rpc_reply_t instance corresponding to such an API operation
 * for the given connection.
 *
 * Only use it for operations that do not themselves return
 * amqp_rpc_reply_t; operations that do return amqp_rpc_reply_t
 * generally do NOT update this per-connection-global amqp_rpc_reply_t
 * instance.
 *
 * @param state
 * @returns
 */
RABBITMQ_EXPORT amqp_rpc_reply_t amqp_get_rpc_reply(
                                                amqp_connection_state_t state);

/**
 * @brief Completes the initial handshake with the broker after connecting
 *
 * @param state
 * @param vhost
 * @param channel_max
 * @param frame_max
 * @param heartbeat
 * @param sasl_method...
 * @returns
 */
RABBITMQ_EXPORT amqp_rpc_reply_t amqp_login(amqp_connection_state_t state,
                                        char const *vhost,
                                        int channel_max,
                                        int frame_max,
                                        int heartbeat,
                                        amqp_sasl_method_enum sasl_method, ...);

struct amqp_basic_properties_t_;
/**
 * @brief Publishes a message to the broker
 *
 * @param state
 * @param channel
 * @param exchange
 * @param routing_key
 * @param mandatory
 * @param immediate
 * @param properties
 * @param body
 * @returns
 */
RABBITMQ_EXPORT int amqp_basic_publish(amqp_connection_state_t state,
                              amqp_channel_t channel,
                              amqp_bytes_t exchange,
                              amqp_bytes_t routing_key,
                              amqp_boolean_t mandatory,
                              amqp_boolean_t immediate,
                              struct amqp_basic_properties_t_ const *properties,
                              amqp_bytes_t body);

/**
 * @brief closes a channel
 *
 * @param state
 * @param channel
 * @param code
 * @returns
 */
RABBITMQ_EXPORT amqp_rpc_reply_t amqp_channel_close(
                                                 amqp_connection_state_t state,
                                                 amqp_channel_t channel,
                                                 int code);
/**
 * @brief shuts down the connection to the broker
 *
 * @param state
 * @param code
 * @returns
 */
RABBITMQ_EXPORT amqp_rpc_reply_t amqp_connection_close(
                                                 amqp_connection_state_t state,
                                                 int code);

/**
 * @brief does a basic.ack for a message
 *
 * @param state
 * @param channel
 * @param delivery_tag
 * @param multipl
 * @returns
 */
RABBITMQ_EXPORT int amqp_basic_ack(amqp_connection_state_t state,
				   amqp_channel_t channel,
				   uint64_t delivery_tag,
				   amqp_boolean_t multiple);

/**
 * @brief performs a basic.get for a message
 *
 * @param state
 * @param channel
 * @param queue
 * @param no_ack
 * @returns
 */
RABBITMQ_EXPORT amqp_rpc_reply_t amqp_basic_get(amqp_connection_state_t state,
                                                amqp_channel_t channel,
                                                amqp_bytes_t queue,
                                                amqp_boolean_t no_ack);

/**
 * @brief rejects a received message
 *
 * @param state
 * @param channel
 * @param delivery_tag
 * @param requeue
 * @returns
 */
RABBITMQ_EXPORT int amqp_basic_reject(amqp_connection_state_t state,
				      amqp_channel_t channel,
				      uint64_t delivery_tag,
				      amqp_boolean_t requeue);

/**
 * Can be used to see if there is data still in the buffer, if so
 * calling amqp_simple_wait_frame will not immediately enter a
 * blocking read.
 *
 * Possibly amqp_frames_enqueued should be used for this?
 *
 * @param state
 * @returns
 */
RABBITMQ_EXPORT amqp_boolean_t amqp_data_in_buffer(
                                                amqp_connection_state_t state);

/**
 * @briefGet the error string for the given error code.
 *
 * The returned string resides on the heap; the caller is responsible
 * for freeing it.
 *
 * @param err
 * @returns
 */
RABBITMQ_EXPORT char *amqp_error_string(int err);

/**
 * @brief decodes a amqp table
 *
 * @param encoded
 * @param pool
 * @param output
 * @param offset
 * @returns
 */
RABBITMQ_EXPORT int amqp_decode_table(amqp_bytes_t encoded,
                                      amqp_pool_t *pool,
                                      amqp_table_t *output,
                                      size_t *offset);

/**
 * @brief encodes an amqp table
 *
 * @param encoded
 * @param input
 * @param offset
 * @returns
 */
RABBITMQ_EXPORT int amqp_encode_table(amqp_bytes_t encoded,
                                      amqp_table_t *input,
                                      size_t *offset);

struct amqp_connection_info {
  char *user;
  char *password;
  char *host;
  char *vhost;
  int port;
};


/**
 * @brief Initializes a amqp_connection_info struct to some default values
 *
 * @param parsed
 */
RABBITMQ_EXPORT void amqp_default_connection_info(
					  struct amqp_connection_info *parsed);
/**
 * @brief Parses an AMQP connection string
 *
 * @param url
 * @param parsed
 * @returns
 */
RABBITMQ_EXPORT int amqp_parse_url(char *url,
				   struct amqp_connection_info *parsed);

#ifdef __cplusplus
}
#endif

#include <amqp_framing.h>

#endif
