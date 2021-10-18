
#include "io.h"


const int BUFFER_LEN = 256;     // Длина буфера по умолчанию


void io::readFromFD(struct ev_loop *loop, struct ev_io *watcher,
                    int fd, std::string& input, bool stop_watcher) {
    auto *conn = (socks5::conn *)watcher->data;
    char *buffer = (char*)malloc(BUFFER_LEN * sizeof(char));
    bool loopable = true;// Следует ли продолжать цикл
    do {
        ssize_t size = read(fd, buffer, BUFFER_LEN);
        if(size < 0) {
            utils::close_conn(conn, -1, "close conn.", true, &loopable);
        }
        else if(size == 0) {    // Чтение
            conn->stage = socks5::STATUS_CLOSING;
            if(stop_watcher) {
                ev_io_stop(loop, watcher);
                break;
            }
            else {
                utils::close_conn(conn, fd, "closed conn.", false, &loopable);
            }
        }
        else {
            utils::str_concat_char(input, buffer, size);
        }
    } while(loopable);

    free(buffer);
}


void io::writeToFD(struct ev_loop *loop, struct ev_io *watcher,
                   int fd, std::string& output) {
    auto *conn = (socks5::conn *)watcher->data;
    size_t idx = 0;
    bool loopable = true;
    do {
        // отправка, очистка буфера
        if(output.length()-idx <= 0) {
            output.clear();
            ev_io_stop(loop, watcher);
            break;
        }
        ssize_t size = write(fd, &output[idx], output.length()-idx);
        if (size < 0) {
            utils::close_conn(conn, fd, "close conn.", true, &loopable);
            break;
        }
        else {
            idx += size;
        }
    } while(loopable);
}
