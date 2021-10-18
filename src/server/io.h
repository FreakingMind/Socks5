//
//
//

#ifndef GLORIOUSOCKS_IO_H
#define GLORIOUSOCKS_IO_H


#include "utils.h"
#include "socks5.h"

#include <cstdlib>

namespace io {

    // Читать из дескриптора в буфер
    void readFromFD(struct ev_loop *loop, struct ev_io *watcher,
                    int fd, std::string& input, bool stop_watcher=false);

    // Писать из буфера в дескриптор
    void writeToFD(struct ev_loop *loop, struct ev_io *watcher,
                   int fd, std::string& output);

}


#endif //GLORIOUSOCKS_IO_H
