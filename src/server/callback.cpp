#include "callback.h"


void accept_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    int fd = watcher->fd;
    auto *server = (socks5::server *)watcher->data;     // accept 

    bool loopable = true;   // цикл
    do {
        sockaddr_in addr {};
        socklen_t len = sizeof(sockaddr_in);
        int client_fd = accept(fd, (sockaddr*)&addr, &len);

        if (client_fd == -1) {
            utils::close_conn(nullptr, client_fd, "accept error", true, &loopable);
            break;
        }

        // информация о ссылке
        char ip[32];
        inet_ntop(addr.sin_family, &addr.sin_addr.s_addr, ip, 32);
        utils::msg("host: " + *(new string(ip)) + "   " + "port: " + to_string(ntohs(addr.sin_port)));

        // неблокирующий
        if (utils::setSocketNonBlocking(client_fd) < 0) {
            utils::close_conn(nullptr, client_fd, "set nonblocking: ", true, nullptr);
            continue;
        }

        
        if(utils::setSocketReuseAddr(client_fd) < 0) {
            utils::close_conn(nullptr, client_fd, "set reuseaddr: ", true, nullptr);
            continue;
        }

        auto conn = new socks5::conn();
        // Заканчивается, когда указатель удаляется другими функциями
        if(conn == nullptr) {
            utils::close_conn(conn, client_fd, "connection fail", false, nullptr);
            continue;
        }

        conn->loop = loop;
        conn->server = server;
        conn->client.fd = client_fd;

        utils::msg("accept, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));

        ev_io_init(conn->client.rw, client_recv_cb, client_fd, EV_READ);
        ev_io_init(conn->client.ww, client_send_cb, client_fd, EV_WRITE);

        ev_io_start(loop, conn->client.rw);

    } while(loopable);

}


void client_recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    int fd = watcher->fd;
    auto *conn = (socks5::conn *)watcher->data;
    auto *server = conn->server;
    auto *client = &(conn->client);
    auto *remote = &(conn->remote);

    utils::msg("client_recv_cb start here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));

    // Чтение
    io::readFromFD(loop, watcher, fd, client->input);

    utils::msg("client_recv_cb finish here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));



    switch(conn->stage) {

    /* 1. Согласование метода аутентификации */
        case socks5::STATUS_NEGO_METHODS: {
            auto ver = (uint8_t)(*(&client->input[0]));
            auto nmethods = (uint8_t)(*(&client->input[1]));
            auto methods = (char*)malloc(nmethods*sizeof(uint8_t));
            memcpy(methods, &client->input[2], nmethods);

            // Проверка версии
            if(socks5::VERSION != ver) {
                utils::msg("client ver: " + to_string(ver));
                utils::close_conn(conn, fd, "version error", false, nullptr);
                return;
            }

            // Создание ответ клиенту
            socks5::method_response method_resp {};
            method_resp.ver = socks5::VERSION;
            method_resp.method = socks5::METHOD_NOACCEPTABLE_METHODS;

            // Сопоставление методов
            for(int i = nmethods - 1; i >= 0; i--) {
                if(server->auth_method == methods[i]) {
                    method_resp.method = server->auth_method;
                    conn->auth_method = server->auth_method;
                    break;
                }
            }
            utils::msg("Auth method confirm: "  + to_string(method_resp.method));

            // структура resp
            auto method_resp_seq = (char*)&method_resp;
            utils::str_concat_char(client->output, method_resp_seq, sizeof(method_resp));

            // если недоступен результат
            if (socks5::METHOD_NOACCEPTABLE_METHODS == method_resp.method) {
                conn->stage = socks5::STATUS_CLOSING;
            }

            // очистить принимающий кэш
            ev_io_stop(loop, watcher);
            client->input.clear();

            // отправить ответ (client_send_cb)
            ev_io_start(loop, client->ww);

            break;
        }

    /* 2. Аутентификация имени пользователя и пароля (если NOAUTH, то режим простой аутентификации, установить соединение ) */
        case socks5::STATUS_UNAME_PASSWD: {

            auto ver = (uint8_t)(*(&client->input[0]));     // По умолчанию 0x01
            auto ulen = (uint8_t)(*(&client->input[1]));
            auto uname = (char*) malloc(ulen * sizeof(char) + 1);
            memcpy(uname, &client->input[2], ulen);
            auto plen = (uint8_t)(*(&client->input[2+ulen]));
            auto passwd = (char*) malloc(plen * sizeof(char) + 1);
            memcpy(passwd, &client->input[2+ulen+1], plen);

            uname[ulen] = '\0';
            passwd[plen] = '\0';

            std::string uname_str = *(new string(uname));
            std::string passwd_str = *(new string(passwd));
            utils::msg("[AUTH] uname:passwd -> " + uname_str + ":" + passwd_str);

            socks5::auth_response auth_resp {};
            auth_resp.ver = 0x01;
            auth_resp.status = 0x00;

            // Определение версии
            if (ver != socks5::AUTH_USERNAMEPASSWORD_VER) {
                utils::msg("auth version error.");
                auth_resp.status = 0x01;        // Установить статус, чтобы  клиент мог завершить работу
            }

            // Проверка длины и правильность пароля
            if((uname_str.length() != ulen || uname_str != conn->server->uname)
                && (passwd_str.length() != plen || passwd_str != conn->server->passwd)) {
                utils::msg("uname or passwd error");
                auth_resp.status = 0x01;
            }

            // Если пароль учетной записи недоступен, сменить этап
            if (auth_resp.status == 0x01) {
                conn->stage = socks5::STATUS_CLOSING;
            }

            // Структура resp
            auto auth_resp_seq = (char*)&auth_resp;
            utils::str_concat_char(client->output, auth_resp_seq, sizeof(auth_resp));

            // Очистить принимающий кэш
            ev_io_stop(loop, watcher);
            client->input.clear();

            // Отправить ответ client_send_cb
            ev_io_start(loop, client->ww);

            break;
        }
    /*3. Установка соединения, связка с удаленным сервером*/
        case socks5::STATUS_ESTABLISH_CONNECTION: {

            // Проверка версии
            auto ver = (uint8_t)(*(&client->input[0]));     // Socks5
            if (ver != socks5::VERSION) {
                utils::close_conn(conn, fd, "version error", false, nullptr);
                return;
            }


//            auto rsv = (uint8_t)(*(&client->input[2]));  // 保留字段 0X00
//            utils::msg("rsv: " + to_string(rsv));

            /* Проверка адреса: IPv4, доменное имя, IPv6*/
            auto atype = (uint8_t)(*(&client->input[3]));
            remote->atype = atype;

            // Создание ответа
            socks5::response resp {};
            resp.ver = ver;
            resp.rep = socks5::RESPONSE_REP_SUCCESS;
            resp.atyp = atype;

            // Создание socaddr для удаленного сервера
            struct sockaddr_in addr {};
            memset((char *)&addr, 0, sizeof(addr));

            auto cmd = (uint8_t)(*(&client->input[1]));
            if (cmd != socks5::REQUEST_CMD_CONNECT) {
                resp.rep = socks5::RESPONSE_REP_COMMAND_NOT_SUPPORTED;
                // ответ
                auto resp_seq = (char*)&resp;
                utils::str_concat_char(client->output, resp_seq, sizeof(resp));
                ev_io_stop(loop, watcher);
                ev_io_start(loop, client->ww);
                utils::close_conn(conn, fd, "remote cmd error.", false, nullptr);
                return;
            }

            switch(atype) {
                case socks5::ADDRTYPE_IPV4: /* ipv4 */{
                    // длина ipv4  = 4Byte
                    auto dst_addr = (uint32_t*)malloc(4*sizeof(char));
                    memcpy(dst_addr, &client->input[4], 4);

                    auto *dst_port = (uint16_t*)malloc(sizeof(uint16_t));  // uint16_t преобразование в байты хоста
                    memcpy(dst_port, &client->input[8], 2);

                    // проверка адреса и порта
                    char ipv4_addr_buf[32];
                    inet_ntop(AF_INET, dst_addr, ipv4_addr_buf, sizeof(ipv4_addr_buf));
                    utils::msg("[DETAILS] addr:port -> " + *(new string(ipv4_addr_buf)) +
                               ":" + to_string(ntohs(*dst_port)));

                    remote->addr = (char*)malloc(4*sizeof(char));
                    memcpy(remote->addr, &client->input[4], 4);
                    remote->port = *dst_port;

                    addr.sin_family = AF_INET;
                    addr.sin_port = *dst_port;
                    addr.sin_addr.s_addr = *dst_addr;

                    // создание удаленного сокета
                    int remote_fd = socket(AF_INET, SOCK_STREAM, 0);
                    if (remote_fd < 0) {
                        utils::close_conn(conn, remote_fd, "remote fd closed.", false, nullptr);
                        return;
                    }
                    // неблокирующий
                    if (utils::setSocketNonBlocking(remote_fd) < 0) {
                        utils::close_conn(nullptr, remote_fd, "remote set nonblocking: ", true, nullptr);
                        return;
                    }
                    
                    if(utils::setSocketReuseAddr(remote_fd) < 0) {
                        utils::close_conn(nullptr, remote_fd, "remote set reuseaddr: ", true, nullptr);
                        return;
                    }

                    // Можно установить ТСР и, remote_fd будет смотреть в порт, на котором установлено соединение 
                    if (connect(remote_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
                        /*
                         *Т.к. connect() уже запущен, любая операция над сокетом ведет к ошибке
                         * Игноирование 115 ошибки
                         * */
                        if((errno != EINPROGRESS)){
                            utils::close_conn(nullptr, remote_fd, "remote set reuseaddr: ", true, nullptr);
                            return;
                        }
                    }

                    // Очистка принимающего кэша
                    ev_io_stop(loop, watcher);
                    client->input.clear();

                    remote->fd = remote_fd;

                    // Изменение статуса: подключение
                    conn->stage = socks5::STATUS_CONNECTING;

                    // Передача удаленной информации клиенту ( remote_send_cb)
                    //  client
                    ev_io_init(remote->rw, remote_recv_cb, remote->fd, EV_READ);
                    ev_io_init(remote->ww, remote_send_cb, remote->fd, EV_WRITE);
                    ev_io_start(loop, remote->ww);

                    break;
                }
                case socks5::ADDRTYPE_DOMAIN: {



                    break;
                }
                case socks5::ADDRTYPE_IPV6: {


                    break;
                }
                default: break;
            }
            break;
        } // switch details
        case socks5::STATUS_STREAM: {
            // Получение клиентского запроса и перенаправка на удаленный 
            remote->output = client->input;
            client->input.clear();
            ev_io_start(loop, remote->ww);
            break;
        }
        default: {
            utils::msg("unvalid stage.");
            break;
        }
    } // switch outtest
    utils::msg("client_recv_cb deal with stage, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));
}


void client_send_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    int fd = watcher->fd;
    auto *conn = (socks5::conn *)watcher->data;
    auto *client = &(conn->client);
    auto *remote = &(conn->remote);

    utils::msg("client_send_cb start here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));

    // Запись
    io::writeToFD(loop, watcher, fd, client->output);
    switch(conn->stage) {
        case socks5::STATUS_NEGO_METHODS: {
            switch(conn->server->auth_method) {
                case socks5::METHOD_USERNAMEPASSWORD: {
                    conn->stage = socks5::STATUS_UNAME_PASSWD;
                    ev_io_start(loop, client->rw); break;
                }
                case socks5::METHOD_NOAUTH: {
                    conn->stage = socks5::STATUS_ESTABLISH_CONNECTION;  // Directly
                    ev_io_start(loop, client->rw); break;
                }
                case socks5::METHOD_GSSAPI: break;                             
                case socks5::METHOD_TOX7F_IANA_ASSIGNED: break;                 
                case socks5::METHOD_TOXFE_RESERVED_FOR_PRIVATE_METHODS: break;  
                case socks5::METHOD_NOACCEPTABLE_METHODS: break;                
                default: break;
            }
            break;
        }
        case socks5::STATUS_UNAME_PASSWD: {
            conn->stage = socks5::STATUS_ESTABLISH_CONNECTION;
            ev_io_start(loop, client->rw);
            break;
        }
        case socks5::STATUS_CONNETED: {
            conn->stage = socks5::STATUS_STREAM;
            ev_io_start(loop, client->rw);  
            ev_io_start(loop, remote->rw);  
            break;
        }
        case socks5::STATUS_CLOSING: {
            utils::close_conn(conn, fd, "close conn.", false, nullptr);
            break;
        }
        default: break;
    }
    utils::msg("client_send_cb finish here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));
}

void remote_recv_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    int fd = watcher->fd;
    auto *conn = (socks5::conn *)watcher->data;
    auto *server = conn->server;
    auto *client = &(conn->client);
    auto *remote = &(conn->remote);

    utils::msg("remote_recv_cb start here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));

    // Чтение
    io::readFromFD(loop, watcher, fd, remote->input, true);

    utils::msg("remote_recv_cb finish here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));

    // Передача данных в client-> output
    client->output += remote->input;
    remote->input.clear();

    // отправить данные клиенту
    ev_io_start(loop, client->ww);
}

void remote_send_cb(struct ev_loop *loop, struct ev_io *watcher, int revents) {
    int fd = watcher->fd;
    auto *conn = (socks5::conn *)watcher->data;
    auto *server = conn->server;
    auto *client = &(conn->client);
    auto *remote = &(conn->remote);

    utils::msg("remote_send_cb start here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));

    switch(conn->stage) {
        // на этапе подключения отправить ответ клиенту
        case socks5::STATUS_CONNECTING: {
            socks5::response resp {};
            resp.ver = socks5::VERSION;
            resp.rep = socks5::RESPONSE_REP_SUCCESS;
            resp.atyp = remote->atype;
            resp.rsv = 0x00;    // зарезервированный текст
            resp.bnd_port = remote->port;
            if(remote->atype == socks5::ADDRTYPE_IPV4) {
                resp.bnd_addr = (char*) malloc(4*sizeof(char));
                memcpy(resp.bnd_addr, remote->addr, 4);
                // проверка адреса и порта
                char ipv4_addr_buf[32];
                inet_ntop(AF_INET, resp.bnd_addr, ipv4_addr_buf, sizeof(ipv4_addr_buf));
                utils::msg("[CONNECTING] addr:port -> " + *(new string(ipv4_addr_buf)) +
                           ":" + to_string(ntohs(resp.bnd_port)));
            }
            if(remote->atype == socks5::ADDRTYPE_DOMAIN) {

            }
            if(remote->atype == socks5::ADDRTYPE_IPV6) {

            }

            auto resp_seq = (char*)&resp;
            utils::str_concat_char(client->output, resp_seq, 4+4+2);
            // подключение завершено
            std::cout << "Connected." << std::endl;
            conn->stage = socks5::STATUS_CONNETED;

            ev_io_stop(loop, watcher);

            // отправить ответ
            ev_io_start(loop, client->ww);


            utils::msg("remote_send_cb finish here(reply), fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));
            return; 
        }
        default: break;
    } // switch


    io::writeToFD(loop, watcher, fd, remote->output);

    utils::msg("remote_send_cb end here, fd: " + to_string(fd) + ", stage: " + to_string(conn->stage));
}
