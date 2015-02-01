#ifndef _SOCKS_H
#define _SOCKS_H

struct socks5_method_request {
    char ver;
    char nmethods;
    char methods[255];
}__attribute__((packed));

struct socks5_method_response {
    char ver;
    char method;
}__attribute__((packed));

struct socks5_request {
    char ver;
    char cmd;
    char rsv;
    char atyp;
    char addr[0];
}__attribute__((packed));

struct socks5_response {
    char ver;
    char rep;
    char rsv;
    char atyp;
}__attribute__((packed));

enum s5_auth_method {
    S5_AUTH_NONE = 0x00,
    S5_AUTH_GSSAPI = 0x01,
    S5_AUTH_PASSWD = 0x02,
};

enum s5_auth_result {
    S5_AUTH_ALLOW = 0x00,
    S5_AUTH_DENY = 0x01,
};

enum s5_atyp {
    S5_ATYP_IPV4 = 0x01,
    S5_ATYP_HOST = 0x03,
    S5_ATYP_IPV6 = 0x04,
};

enum s5_cmd {
    S5_CMD_CONNECT = 0x01,
    S5_CMD_BIND = 0x02,
    S5_CMD_UDP_ASSOCIATE = 0x03,
};

enum s5_rep {
    S5_REP_SUCCESSED = 0X00,
    S5_REP_SOCKS_FAILURE = 0X01,
    S5_REP_RULESET_DENY = 0X02,
    S5_REP_NETWORK_UNREACHABLE = 0X03,
    S5_REP_HOST_UNREACHABLE = 0X04,
    S5_REP_CONNECTION_REFUSED = 0X05,
    S5_REP_TTL_EXPIRED = 0X06,
    S5_REP_CMD_NOT_SUPPORTED = 0X07,
    S5_REP_ADDRESS_TYPE_NOT_SUPPORTED = 0X08,
    S5_REP_UNASSIGNED = 0X09,
};

enum s5_stage {
    S5_STAGE_AUTH_NEGO, /* authentication negociation */
    S5_STAGE_HANDSHAKE,
    S5_STAGE_REQUEST,
    S5_STAGE_RESOLVE,
    S5_STAGE_CONNECT,
    S5_STAGE_FORWARD,
    S5_STAGE_TERMINATE,
    S5_STAGE_DEAD,
};

#endif // for #ifndef _SOCKS_H
