
#ifndef GLORIOUSOCKS_SOCKS5_HPP
#define GLORIOUSOCKS_SOCKS5_HPP

#include <ev.h>
#include <unistd.h>

#include <iostream>
using namespace std;

namespace socks5 {

/* Socks5 protocol [RFC 1928 / RFC 1929] */

    const uint8_t VERSION           = 0x05;            // Socks5


// socks5 认证协议
    const uint8_t AUTH_USERNAMEPASSWORD_VER           = 0x01;
    const int AUTH_USERNAMEPASSWORD_MAX_LEN           = 256;
    struct auth_request {
        uint8_t ver;       
        uint8_t ulen;       // Длина имени пользователя
        char  uname[AUTH_USERNAMEPASSWORD_MAX_LEN];      // имя пользователя
        uint8_t plen;       // Длина пароля
        char  passewd[AUTH_USERNAMEPASSWORD_MAX_LEN];     // пароль
    };

    const uint8_t AUTH_USERNAMEPASSWORD_STATUS_OK     = 0x00;
    const uint8_t AUTH_USERNAMEPASSWORD_STATUS_FAIL   = 0x01;
    struct auth_response {
        uint8_t ver;        // Протокол аутентификации
        uint8_t status;     // Статус идентификации
    };

// socks5 согласование метода аутентификации
    const uint8_t METHOD_NOAUTH                             = 0x00;
    const uint8_t METHOD_GSSAPI                             = 0x01;
    const uint8_t METHOD_USERNAMEPASSWORD                   = 0x02;
    const uint8_t METHOD_TOX7F_IANA_ASSIGNED                = 0x03;
    const uint8_t METHOD_TOXFE_RESERVED_FOR_PRIVATE_METHODS = 0x80;
    const uint8_t METHOD_NOACCEPTABLE_METHODS               = 0xff;

    struct method_request {
        uint8_t  ver;             // версия socks (0x05 в socks5)
        uint8_t  nmethods;        // Количество методов, отображаемых в поле methods
        uint8_t* methods;         // Список методов аутентификации, поддерживаемых клиентом, каждый метод занимает 1 байт
    };

    struct method_response {
        uint8_t ver;        // версия socks (0x05 в socks5)
        uint8_t method;     // Метод, выбранный сервером (если возвращается 0xFF, это означает, что метод не выбран, и клиенту необходимо закрыть соединение)
    };

// socks5 запрос
    const uint8_t REQUEST_CMD_CONNECT       = 0x01;
    const uint8_t REQUEST_CMD_BIND          = 0x02;
    const uint8_t REQUEST_CMD_UDPASSOCIATE  = 0x03;

    const uint8_t REQUEST_RSV               = 0x00;

    const uint8_t ADDRTYPE_IPV4     = 0x01;
    const uint8_t ADDRTYPE_DOMAIN   = 0x03;
    const uint8_t ADDRTYPE_IPV6     = 0x04;

    struct request {
        uint8_t  ver;                           // версия socks
        uint8_t  cmd;                           /* SOCK ：
                                                      CONNECT X’01’
                                                      BIND X’02’
                                                      UDP ASSOCIATE X’03’
                                                */
        uint8_t  rsv;                           // зарезервированный текст
        uint8_t  atyp;                          /* тип адреса
                                                      IP V4 адрес: X'01'
                                                      имя домена: X'03'
                                                      IP V6 адрес: X'04'
                                                */
        char*     dst_addr;                     // адрес назнчаения
        uint16_t dst_port;                      // порт назначения
    };

// socks5 回应
    const uint8_t RESPONSE_REP_SUCCESS                 = 0x00;
    const uint8_t RESPONSE_REP_SERVER_FAILURE          = 0x01;
    const uint8_t RESPONSE_REP_CONN_NOT_ALLOWED        = 0x02;
    const uint8_t RESPONSE_REP_NETWORK_UNREACHABLE     = 0x03;
    const uint8_t RESPONSE_REP_HOST_UNREACHABLE        = 0x04;
    const uint8_t RESPONSE_REP_CONN_REFUSED            = 0x05;
    const uint8_t RESPONSE_REP_TTL_EXPIRED             = 0x06;
    const uint8_t RESPONSE_REP_COMMAND_NOT_SUPPORTED   = 0x07;
    const uint8_t RESPONSE_REP_ADDR_TYPE_NOT_SUPPORTED = 0x08;
    const uint8_t RESPONSE_REP_TOXFF_UNASSIGNED        = 0x09;

    const uint8_t RESPONSE_RSV                         = 0x00;

    struct response {
        uint8_t  ver;                        // версия 
        uint8_t  rep;                        /* код состояния ответа：
                                                  X’00’ succeeded
                                                  X’01’ general socks server failure
                                                  X’02’ connection not allowed by ruleset
                                                  X’03’ Network unreachable
                                                  X’04’ Host unreachable
                                                  X’05’ Connection refused
                                                  X’06’ TTL expired
                                                  X’07’ Command not supported
                                                  X’08’ Address type not supported
                                                  X’09’ to X’FF’ unassigned
                                             */
        uint8_t  rsv;                        // Зарезервированное поле (X’00’）
        uint8_t  atyp;                       /* тип адреса
                                                      IP V4 адрес: X'01'
                                                      имя домена: X'03'
                                                      IP V6 адрес: X'04'
                                             */
        char*   bnd_addr;                    // адрес, привязанный к серверу
        uint16_t bnd_port;                   // порт, связанный с сервером
    };


/* Socks5 ProxyServer */

    struct conn_external /* внешнее подключение */ {
        int      fd;          // дескриптор сокета
        string   input;       // входной буфер
        string   output;      // выходной буфер
        struct   ev_io *rw;   // наблюдение доступности фд для чтения
        struct   ev_io *ww;   // наблюдение доступности фд для записи
        uint8_t  atype;       // тип адреса
        char*    addr;        // адреса
        uint16_t port;        // порт
    };

    struct conn_internal /* связь с клиентом */ {
        int     fd;          // дескриптор сокета
        string  input;       // входной буфер
        string  output;      // выходной буфер
        struct  ev_io *rw;   // наблюдение доступности фд для чтения
        struct  ev_io *ww;   // наблюдение доступности фд для записи
    };

    struct server /* Свойства сервера */ {
        size_t   ulen;            // длина имени пользователя
        string   uname;           // имя пользователя
        size_t   plen;            // длина пароля пользователя
        string   passwd;          // пароль пользователя
        uint16_t port;            // порт прокси
        uint8_t  auth_method;     // метод аутентификации
    };

    const uint8_t STATUS_NEGO_METHODS           = 0x01;
    const uint8_t STATUS_UNAME_PASSWD           = 0x02;
    const uint8_t STATUS_ESTABLISH_CONNECTION   = 0x03;
    const uint8_t STATUS_DNS_QUERY              = 0x04;
    const uint8_t STATUS_CONNECTING             = 0x05;
    const uint8_t STATUS_CONNETED               = 0x06;
    const uint8_t STATUS_STREAM                 = 0x07;
    const uint8_t STATUS_CLOSING                = 0x08;
    const uint8_t STATUS_CLOSED                 = 0x09;

    class conn /* Соединение */ {
    public:
        struct ev_loop  *loop;
        conn_external   remote;    // Внешнее подключение
        conn_internal   client;    // Соединение с клиентом
        uint8_t  auth_method;      // метод аутентификации
        uint8_t stage;
        struct server *server;     // Атрибут
        conn();                    // Инициализация
        virtual ~conn();           // Удаление

    };

}
#endif //GLORIOUSOCKS_SOCKS5_HPP
