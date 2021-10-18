
#ifndef GLORIOUSOCKS_UTILS_H
#define GLORIOUSOCKS_UTILS_H

#include "socks5.h"

#include <errno.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <netinet/tcp.h>
#include <netinet/in.h>

namespace utils {
    /*
	* Используется для завершения соединения, параметр loopable используется в функции cb как сигнал для завершения цикла
	* Нет операции, если параметры fd и conn равны nullptr или -1
	* Параметр msg используется для отображения информации, has_erro указывает, выводить ли errno
     */
    void close_conn(socks5::conn* conn, int fd,
                    const std::string& msg, bool has_errno,
                    bool* loopable);


    /*
     * Для печати информации
     */
    void msg(const string& msg);


    /*
     * Установка файлового дескриптора в неблокирубщее состояние
     */
    int setSocketNonBlocking(int fd);


    /*
     * Установка повторно используемого адреса
     */
    int setSocketReuseAddr(int fd);


    /*
     * Параметр CP_NODELAY
     * */
    int setTCPNoDelay(int fd);


    /*
     * Сложение строкового и символьного массива
     * */
    void str_concat_char(std::string& str, char* ch, const ssize_t size);
}


#endif //GLORIOUSOCKS_UTILS_H
