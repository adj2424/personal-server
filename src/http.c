/*
 * A server implementation of HTTP/1.0/1.1
 *
 * This code is mainly intended as a replacement for the book's 'tiny.c' server
 * It provides an implementation of HTTP/1.0/1,1 with other features as well
 *
 * @author G. Back for CS 3214 Spring 2018
 */
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <string.h>
#include <stdarg.h> 
#include <stdio.h>
#include <stdbool.h>
#include <errno.h>
#include <unistd.h>
#include <time.h>
#include <fcntl.h>
#include <linux/limits.h>

#include "http.h"
#include "hexdump.h"
#include "socket.h"
#include "bufio.h"
#include "main.h"

// Need macros here because of the sizeof

#define CRLF "\r\n"
#define CR "\r"
#define STARTS_WITH(field_name, header) \
    (!strncasecmp(field_name, header, sizeof(header) - 1))

static const char* SECRET_PRIVATE_KEY = "6DEBE4F266938EF548B0ACD2A167759D";
static const char* USER = "user0";

/* Parse HTTP request line, setting req_method, req_path, and req_version. */
static bool
http_parse_request(struct http_transaction *ta)
{
    size_t req_offset;
    ssize_t len = bufio_readline(ta->client->bufio, &req_offset);
    if (len < 2)       // error, EOF, or less than 2 characters
        return false;

    char *request = bufio_offset2ptr(ta->client->bufio, req_offset);
    request[len-2] = '\0';  // replace LF with 0 to ensure zero-termination
    //printf("request url--->%s\n", request);
    char *endptr;
    char *method = strtok_r(request, " ", &endptr);
    if (method == NULL)
        return false;

    if (!strcmp(method, "GET"))
        ta->req_method = HTTP_GET;
    else if (!strcmp(method, "POST"))
        ta->req_method = HTTP_POST;
    else
        ta->req_method = HTTP_UNKNOWN;

    char *req_path = strtok_r(NULL, " ", &endptr);
    if (req_path == NULL)
        return false;

    ta->req_path = bufio_ptr2offset(ta->client->bufio, req_path);

    char *http_version = strtok_r(NULL, CR, &endptr);
    if (http_version == NULL)  // would be HTTP 0.9
        return false;

    // record client's HTTP version in request
    if (!strcmp(http_version, "HTTP/1.1")) {
        //printf("request is http 1.1\n");
        ta->req_version = HTTP_1_1;
        ta->connection_close = false;
    }
    else if (!strcmp(http_version, "HTTP/1.0")) {
        //printf("request is http 1.0\n");
        ta->req_version = HTTP_1_0;
        ta->connection_close = true;
    }
    else {
        return false;
    }
    return true;
}

/* Process HTTP headers. */
static bool
http_process_headers(struct http_transaction *ta)
{
    for (;;) {
        size_t header_offset;
        ssize_t len = bufio_readline(ta->client->bufio, &header_offset);
        if (len <= 0)
            return false;

        char *header = bufio_offset2ptr(ta->client->bufio, header_offset);
        if (len == 2 && STARTS_WITH(header, CRLF))       // empty CRLF
            return true;

        header[len-2] = '\0';
        /* Each header field consists of a name followed by a 
         * colon (":") and the field value. Field names are 
         * case-insensitive. The field value MAY be preceded by 
         * any amount of LWS, though a single SP is preferred.
         */
        char *endptr;
        char *field_name = strtok_r(header, ":", &endptr);
        if (field_name == NULL)
            return false;

        // skip white space
        char *field_value = endptr;
        while (*field_value == ' ' || *field_value == '\t')
            field_value++;

        // you may print the header like so
        //printf("Header: %s: %s\n", field_name, field_value);
        if (!strcasecmp(field_name, "Content-Length")) {
            ta->req_content_len = atoi(field_value);
        }

        /* Handle other headers here. Both field_value and field_name
         * are zero-terminated strings.
         */
        if (!strcasecmp(field_name, "Cookie")) {
            ta->req_cookie = field_value;
        }
        ta->connection_close = false;
        if (!strcasecmp(field_name, "Connection")) {
            if (!strcasecmp(field_value, "Close")) {
                ta->connection_close = true;
            }
        }

        if (!strcasecmp(field_name, "Range")) {
            ta->req_range = field_value;
        }
    }
}

const int MAX_HEADER_LEN = 2048;

/* add a formatted header to the response buffer. */
void 
http_add_header(buffer_t * resp, char* key, char* fmt, ...) {
    va_list ap;
    buffer_appends(resp, key);
    buffer_appends(resp, ": ");
    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(resp, MAX_HEADER_LEN);
    int len = vsnprintf(error, MAX_HEADER_LEN, fmt, ap);
    resp->len += len > MAX_HEADER_LEN ? MAX_HEADER_LEN - 1 : len;
    va_end(ap);
    buffer_appends(resp, "\r\n");
}

/* add body to respose buffer */
void http_add_body(buffer_t* body, char* message) {
    buffer_ensure_capacity(body, strlen(message) + 1);
    buffer_appends(body, message);
    body->len = strlen(message);
}
/* add a content-length header. */
static void
add_content_length(buffer_t *res, size_t len) {
    http_add_header(res, "Content-Length", "%ld", len);
}

/* start the response by writing the first line of the response 
 * to the response buffer.  Used in send_response_header */
static void start_response(struct http_transaction * ta, buffer_t *res) {
    if (ta->req_version == HTTP_1_0) {
        buffer_appends(res, "HTTP/1.0 ");
    }
    if (ta->req_version == HTTP_1_1) {
        buffer_appends(res, "HTTP/1.1 ");
    }
    switch (ta->resp_status) {
    case HTTP_OK:
        buffer_appends(res, "200 OK");
        break;
    case HTTP_PARTIAL_CONTENT:
        buffer_appends(res, "206 Partial Content");
        break;
    case HTTP_BAD_REQUEST:
        buffer_appends(res, "400 Bad Request");
        break;
    case HTTP_PERMISSION_DENIED:
        buffer_appends(res, "403 Permission Denied");
        break;
    case HTTP_NOT_FOUND:
        buffer_appends(res, "404 Not Found");
        break;
    case HTTP_METHOD_NOT_ALLOWED:
        buffer_appends(res, "405 Method Not Allowed");
        break;
    case HTTP_REQUEST_TIMEOUT:
        buffer_appends(res, "408 Request Timeout");
        break;
    case HTTP_REQUEST_TOO_LONG:
        buffer_appends(res, "414 Request Too Long");
        break;
    case HTTP_NOT_IMPLEMENTED:
        buffer_appends(res, "501 Not Implemented");
        break;
    case HTTP_SERVICE_UNAVAILABLE:
        buffer_appends(res, "503 Service Unavailable");
        break;
    case HTTP_INTERNAL_ERROR:
    default:
        buffer_appends(res, "500 Internal Server Error");
        break;
    }
    buffer_appends(res, CRLF);
}

/* Send response headers to client */
static bool send_response_header(struct http_transaction *ta) {
    buffer_t response;
    buffer_init(&response, 80);
    start_response(ta, &response);
    if (bufio_sendbuffer(ta->client->bufio, &response) == -1)
        return false;

    buffer_appends(&ta->resp_headers, CRLF);
    if (bufio_sendbuffer(ta->client->bufio, &ta->resp_headers) == -1)
        return false;

    buffer_delete(&response);
    return true;
}

/* Send a full response to client with the content in resp_body. */
static bool send_response(struct http_transaction *ta) {
    // add content-length.  All other headers must have already been set.
    add_content_length(&ta->resp_headers, ta->resp_body.len);
    if (!send_response_header(ta))
        return false;

    return bufio_sendbuffer(ta->client->bufio, &ta->resp_body) != -1;
}

const int MAX_ERROR_LEN = 2048;

/* Send an error response. */
static bool send_error(struct http_transaction * ta, enum http_response_status status, const char *fmt, ...) {
    va_list ap;

    va_start(ap, fmt);
    char *error = buffer_ensure_capacity(&ta->resp_body, MAX_ERROR_LEN);
    int len = vsnprintf(error, MAX_ERROR_LEN, fmt, ap);
    ta->resp_body.len += len > MAX_ERROR_LEN ? MAX_ERROR_LEN - 1 : len;
    va_end(ap);
    ta->resp_status = status;
    http_add_header(&ta->resp_headers, "Content-Type", "text/plain");
    return send_response(ta);
}

/* Send Not Found response. */
static bool send_not_found(struct http_transaction *ta) {
    return send_error(ta, HTTP_NOT_FOUND, "File %s not found", 
        bufio_offset2ptr(ta->client->bufio, ta->req_path));
}

/* A start at assigning an appropriate mime type.  Real-world 
 * servers use more extensive lists such as /etc/mime.types
 */
static const char * guess_mime_type(char *filename) {
    char *suffix = strrchr(filename, '.');
    if (suffix == NULL)
        return "text/plain";
    if (!strcasecmp(suffix, ".html"))
        return "text/html";
    if (!strcasecmp(suffix, ".gif"))
        return "image/gif";
    if (!strcasecmp(suffix, ".png"))
        return "image/png";
    if (!strcasecmp(suffix, ".jpg"))
        return "image/jpeg";
    if (!strcasecmp(suffix, ".js"))
        return "text/javascript";
    if (!strcasecmp(suffix, ".mp4"))
        return "video/mp4";
    if (!strcasecmp(suffix, ".json"))
        return "application/json";
    if (!strcasecmp(suffix, ".css"))
        return "text/css";
    if (!strcasecmp(suffix, ".svg"))
        return "image/svg+xml";
    if (!strcasecmp(suffix, ".xml"))
        return "application/xml";

    return "text/plain";
}

/* Handle HTTP transaction for static files. */
static bool handle_static_asset(struct http_transaction *ta, char *basedir) {
    char fname[PATH_MAX];
    char *req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    // The code below is vulnerable to an attack.  Can you see
    // which?  Fix it to avoid indirect object reference (IDOR) attacks.
    //printf("req_path->%s\n", req_path);
    http_add_header(&ta->resp_headers, "Accept-Ranges", "bytes");
    char* check;
    //checks for relative paths and idor attacks
    check = strstr(req_path,"/../");
    if (check) {
        return send_error(ta, HTTP_NOT_FOUND, "Not found");
    }
    snprintf(fname, sizeof fname, "%s%s", basedir, req_path);
    //printf("request path file name %s\n", fname);
    //html5 fallback for root and / path
    if (strcasecmp(req_path, "/") == 0 && html5_fallback == true) {
        snprintf(fname, sizeof fname, "%s%s", server_root, "/index.html");
        req_path = fname;
        //printf("request path with html5 fallback-> %s\n", req_path);
    }
    //html5 fallback if its not an /api path, otherwise return 404
    int checkValidFile = open(fname, O_RDONLY);
    if (checkValidFile == -1) {
        char *ret;
        ret = strstr(req_path + sizeof(char), "/api");
        if (ret != req_path && html5_fallback == true) {
            snprintf(fname, sizeof fname, "%s%s", server_root, "/index.html");
            req_path = fname;
            //printf("request path with html5 fallback-> %s\n", req_path);
        }
    }
 
    if (access(fname, R_OK)) {
        if (errno == EACCES)
            return send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied.");
        else
            return send_not_found(ta);
    }
    
    // Determine file size
    struct stat st;
    int rc = stat(fname, &st);
    if (rc == -1) {
        return send_error(ta, HTTP_INTERNAL_ERROR, "Could not stat file.");
    }
        
    int filefd = open(fname, O_RDONLY);
    if (filefd == -1) {
        return send_not_found(ta);
    }
    ta->resp_status = HTTP_OK;
    http_add_header(&ta->resp_headers, "Content-Type", "%s", guess_mime_type(fname));
    off_t from = 0, to = st.st_size - 1;
    off_t content_length = to + 1 - from;
    add_content_length(&ta->resp_headers, content_length);
    bool success = send_response_header(ta);
    if (!success)
        goto out;
    // sendfile may send fewer bytes than requested, hence the loop
    while (success && from <= to)
        success = bufio_sendfile(ta->client->bufio, filefd, &from, to + 1 - from) > 0;
out:
    close(filefd);
    return success;
}
/* Checks for corrent user name and password and creates a jwt token if valid */
static bool handle_pwd_and_create_token(struct http_transaction * ta) {
    json_error_t error;
    char* content = bufio_offset2ptr(ta->client->bufio, ta->req_body);
    content[ta->req_content_len] = '\0';

    json_t* json = json_loads(content, 0, &error);
    if (!json) {
        send_error(ta, HTTP_BAD_REQUEST, error.text);
        return false;
    }
    json_t* usr, * pwd;
    usr = json_object_get(json, "username");
    pwd = json_object_get(json, "password");
    if (usr == NULL || pwd == NULL) {
        send_error(ta, HTTP_PERMISSION_DENIED, "wrong json obj\n");
        //printf("wrong json obj\n");
        return false;
    }
    const char* username = json_string_value(usr);
    const char* password = json_string_value(pwd);
    //printf("%s\t%s\n", username, password);
    //validates 
    if (strcmp(username, USER) != 0 || strcmp(password, "thepassword") != 0) {
        send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied\n");
        //printf("Wrong credentials\t%s %s\n", username, password);
        return false;
    }
    // adds jwt token to header and cookie once validated
    jwt_t* token;
    time_t currentTime = time(NULL);
    int rc = jwt_new(&token);
    if (rc) {
        send_error(ta, HTTP_INTERNAL_ERROR, strerror(rc));
        return false;
    }
    rc = jwt_add_grant(token, "sub", USER);
    if (rc) {
        send_error(ta, HTTP_INTERNAL_ERROR, strerror(rc));
        return false;
    }
    rc = jwt_add_grant_int(token, "iat", currentTime);
    if (rc) {
        send_error(ta, HTTP_INTERNAL_ERROR, strerror(rc));
        return false;
    }
    //24hrs
    rc = jwt_add_grant_int(token, "exp", currentTime + token_expiration_time);
    if (rc) {
        send_error(ta, HTTP_INTERNAL_ERROR, strerror(rc));
        return false;
    }
    rc = jwt_set_alg(token, JWT_ALG_HS256, 
        (unsigned char *)SECRET_PRIVATE_KEY, 
        strlen(SECRET_PRIVATE_KEY));
    if (rc) {
        send_error(ta, HTTP_INTERNAL_ERROR, strerror(rc));
        return false;
    }
    //printf("dump:\n");
    //rc = jwt_dump_fp(token, stdout, 1);
    char *encodedToken = jwt_encode_str(token);
    char* grants = jwt_get_grants_json(token, NULL);
    //printf("encodedtoken-->\n %s\n", encodedToken);
    //printf("grants json-->%s\n", grants);
    int buffLen = strlen(encodedToken) + strlen("auth-token=; Path=/") + 1;
    char cookie[buffLen];
    snprintf(cookie, buffLen, "auth-token=%s; Path=/", encodedToken);
    //printf("%s\n", cookie);
    http_add_header(&ta->resp_headers, "Set-Cookie", cookie);
    http_add_header(&ta->resp_headers, "Content-Type", "application/json");
    http_add_body(&ta->resp_body, grants);
    ta->resp_status = HTTP_OK;
    //send_response_header(ta);
    send_response(ta);
    return true;
}

/* handles all /api path requests */
static bool handle_api(struct http_transaction *ta, char* base_dir) {
    char* req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
    //content[ta->req_content_len] = '\0';
    //printf("req_path-->%s\n", req_path);
    // uses wants to login with username and password
    if (strcasecmp(req_path, "/api/login") == 0 && ta->req_method == HTTP_POST) {
        //printf("post /api/login\n");
        return handle_pwd_and_create_token(ta);
    }
    // validates cookie
    const char* json_body = validate_cookie(ta, req_path);

    //valid cookie if json != null
    // returns response of the grants from the token
    if (strcasecmp(req_path, "/api/login") == 0 && ta->req_method == HTTP_GET) {
        http_add_header(&ta->resp_headers, "Content-Type", "application/json");
        ta->resp_status = HTTP_OK;
        if (json_body != NULL) {
            //printf("json body->%s\n", json_body);
            http_add_body(&ta->resp_body, (char*)json_body);
            //printf("/api/login is ok\n");
        }
        else {
            http_add_body(&ta->resp_body, "{}");   
            //printf("/api/login is fail because cookie is invalid\n");
        }
        return send_response(ta);
    }

    // will return the request mp4 file based on the byte range
    if (strcasecmp(req_path, "/api/video") == 0 && ta->req_method == HTTP_GET) {
        struct dirent *entry;
        DIR *dir = opendir(base_dir);
        if (dir == NULL) {
            //printf("open base dir return null\n");
            return false;
        }
        json_t *mp4Array = json_array();
        while ((entry = readdir(dir)) != NULL) {
            //printf("file --->%s\n", entry->d_name);
            if (strstr(entry->d_name, ".mp4") == NULL)
                continue;
            int mp4FileLen = strlen(base_dir) + strlen(entry->d_name) + 2;
            char mp4File[mp4FileLen];
            snprintf(mp4File, mp4FileLen, "%s/%s", base_dir, entry->d_name);
            //printf("mp4pathfile->%s\n", mp4File);
            struct stat st;
            if (stat(mp4File, &st) == -1) {
                //printf("stat error\n"); 
                continue;
            }
            int size = (int)st.st_size;
            json_t *obj = json_object();
            if (json_object_set_new(obj, "size", json_integer(size)) != 0){
                //printf("obj int set fail"); 
            }
            if (json_object_set(obj, "name", json_string(entry->d_name))!= 0) {
                //printf("obj name set fail"); 
            }
            json_array_append_new(mp4Array, obj);
            //printf("%s\t%d\n", entry->d_name, size); 
        }
        
        closedir(dir);
        char* mp4json = json_dumps(mp4Array, 0);
        //printf("mp4json-->%s\n", mp4json); 
        http_add_header(&ta->resp_headers, "Content-Type", "application/json");
        ta->resp_status = HTTP_OK;
        http_add_body(&ta->resp_body, mp4json);
        return send_response(ta);
    }
    // invalid token
    if (json_body != NULL) {
        ta->resp_status = HTTP_OK;
        return send_response(ta);
    }
    return send_error(ta, HTTP_NOT_FOUND, "not post or get");
    //return true;
}

/* Set up an http client, associating it with a bufio buffer. */
void 
http_setup_client(struct http_client *self, struct bufio *bufio)
{
    self->bufio = bufio;
}

// checks if token is valid 
// returns grants if valid or null if invalid
char* validate_cookie(struct http_transaction *ta, char* path) { 
    char* cookie = ta->req_cookie;
    int rc;
    //printf("validating cookie..\n");
    if (cookie == NULL) {
        //printf("no cookie found\n");
        //send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied");
        return NULL;
    }
    char* token = NULL;
    char* test = strstr(cookie, "auth-token=");
    if (test) {
        token = test + (sizeof(char) * strlen("auth-token="));
    }
    if (token == NULL) {
        //printf("no token found\n");
        //send_error(ta, HTTP_PERMISSION_DENIED, "Permission denied");
        return NULL;
    }
    //send_response_header(ta);
    //printf("token -> \n%s\n", token);
    test = strstr(token, ";");
    if (test) {
        *test = '\0';
    }
    //printf("token split from ;-> \n%s\n", token);

    jwt_t* decodeToken;
    rc = jwt_decode(&decodeToken, token,
        (unsigned char *)SECRET_PRIVATE_KEY, 
        strlen(SECRET_PRIVATE_KEY));
    if (rc) {
        //printf("invalid token\n");
        //send_error(ta, HTTP_PERMISSION_DENIED, "Invalid token");
        return NULL;
    }
    char* grants = jwt_get_grants_json(decodeToken, NULL);
    if (grants == NULL) {
        //printf("null grant\n");
        //send_error(ta, HTTP_PERMISSION_DENIED, "Invalid token");
        return NULL;
    }
    //printf("grants ->\n %s\n", grants);
    json_error_t error;
    char* json_body = malloc(sizeof(char)*(strlen(grants) + 1));
    snprintf(json_body, strlen(grants) + 1, "%s", grants);
    json_t* json = json_loadb(grants, strlen(grants), 0, &error);
    if (!json) {
        //printf("json is null\n");
        return NULL;
    }
    json_t* usr, * expire;
    usr = json_object_get(json, "sub");
    expire = json_object_get(json, "exp");
    const char* username = json_string_value(usr);
    const int exp = json_integer_value(expire);
    if (strcmp(username, USER) != 0) {
        //printf("Wrong user\n");
        return NULL;
    }
    // exp is expired
    time_t currentTime = time(NULL);
    //session expired
    if (currentTime > exp) {
        //printf("user0 session expired\n");
        //send_error(ta, HTTP_PERMISSION_DENIED, "user0 session expired");
        return NULL;
    }
    //printf("authentication successful user0\n");
    return json_body;
}
/* Handle a single HTTP transaction.  Returns true on success. */
bool
http_handle_transaction(struct http_client *self, bool* connection)
{
    struct http_transaction ta;
    memset(&ta, 0, sizeof ta);
    ta.client = self;
    *connection = false;
    if (!http_parse_request(&ta))
        return false;
    if (!http_process_headers(&ta))
        return false;
    // check HTTP connection flag
    // initialize to true for keep-alive
    // if HTTP/1.0 or HTTP/1.1 and close in request connection header
    //    set *connection = false
    *connection = true;
    if (ta.req_version == HTTP_1_0 || (ta.req_version == HTTP_1_1 && ta.connection_close))
        *connection = false;
    
    // has content
    if (ta.req_content_len > 0) {
        int rc = bufio_read(self->bufio, ta.req_content_len, &ta.req_body);
        if (rc != ta.req_content_len)
            return false;
        // To see the body, use this:
        //char *body = bufio_offset2ptr(ta.client->bufio, ta.req_body);
        //hexdump(body, ta.req_content_len);
    }

    buffer_init(&ta.resp_headers, 1024);
    http_add_header(&ta.resp_headers, "Server", "CS3214-Alan-Server");
    buffer_init(&ta.resp_body, 0);
    bool rc = false;
    char *req_path = bufio_offset2ptr(ta.client->bufio, ta.req_path);
    //printf("request path-> %s\n", req_path);

    if (ta.req_method == HTTP_UNKNOWN) {
        return send_error(&ta, HTTP_METHOD_NOT_ALLOWED, "not valid http method");
    }

    if (STARTS_WITH(req_path, "/api")) {
        rc = handle_api(&ta, server_root);
    }
    else if (STARTS_WITH(req_path, "/private")) {
        //printf("private-> %s\n", req_path);
        if (validate_cookie(&ta, req_path) != NULL) {
            //printf("private valid cookie\n");
            rc = handle_static_asset(&ta, server_root);
        }
        else {
            //printf("invalid token\n");
            http_add_header(&ta.resp_headers, "Content-Type", "application/json");
            rc = send_error(&ta, HTTP_PERMISSION_DENIED, "invalid token");
        }
    }
    else {
        if (strcasecmp(guess_mime_type(req_path), "video/mp4") == 0) {
            //printf("reqpath is mp4-->%s\n", req_path);
            rc = handle_video(&ta, server_root);  
        }
        else {
            rc = handle_static_asset(&ta, server_root);
        } 
        
    }
    buffer_delete(&ta.resp_headers);
    buffer_delete(&ta.resp_body);
    return rc;
}
/* Handle HTTP transaction for mp4 files. */
bool handle_video(struct http_transaction* ta, char* base_dir) {
    if (ta->req_range == NULL || strlen(ta->req_range) <= 0) {
        //printf("no range header\n");
        return handle_static_asset(ta, base_dir);
    }
    //printf("header range->%s\n", ta->req_range);
    http_add_header(&ta->resp_headers, "Accept-Ranges", "bytes");
    char* req_path = bufio_offset2ptr(ta->client->bufio, ta->req_path);
   // int mp4FileLen = strlen(base_dir) + strlen(req_path) + 2;
    char mp4File[PATH_MAX];
    snprintf(mp4File, sizeof mp4File, "%s%s", base_dir, req_path);

    struct stat st;
    if (stat(mp4File, &st) == -1) {
        //printf("stat error from this file->%s\n", mp4File); 
        return false;
    }
    off_t size = (off_t)st.st_size;
    char* startRange = NULL;
    char* test = strstr(ta->req_range, "bytes=");
    if (test) {
        startRange = test + (sizeof(char) * strlen("bytes="));
    }
    off_t begin = 0;
    off_t end = size - 1;
    char* endRange = strstr(startRange, "-");
    if (endRange) {
        *endRange = '\0';
        endRange += sizeof(char);
    }
    if (startRange != NULL && strlen(startRange) != 0) {
        begin = atoi(startRange);
    }
    if (endRange != NULL && strlen(endRange) != 0) {
        end = atoi(endRange);
    }
    //printf("start range-->%ld\tend range-->%ld\n", begin, end);
    int filefd = open(mp4File, O_RDONLY);
    if (filefd == -1) {
        return send_not_found(ta);
    }
    int content_length = end - begin + 1;
    add_content_length(&ta->resp_headers, content_length);
    http_add_header(&ta->resp_headers, "Content-Type", "video/mp4");
    char range[200];
    snprintf(range, 200, "bytes %ld-%ld/%ld", begin, end, size);
    http_add_header(&ta->resp_headers, "Content-Range", range);
    ta->resp_status = HTTP_PARTIAL_CONTENT;
    bool success = send_response_header(ta);
    // sendfile may send fewer bytes than requested, hence the loop
    while (success && begin <= end)
        success = bufio_sendfile(ta->client->bufio, filefd, &begin, content_length) > 0;
    close(filefd);
    return success;
}
