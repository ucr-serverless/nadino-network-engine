#include <iostream>
#include <cstring>
#include <unistd.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <vector>
#include <cstdint>

#define MAX_EVENTS 10
#define PORT 8091

void handle_client(int client_fd) {
    uint32_t received_value;
    ssize_t bytes_received = recv(client_fd, &received_value, sizeof(received_value), 0);

    if (bytes_received <= 0) {
        if (bytes_received == 0) {
            std::cout << "Client disconnected.\n";
        } else {
            perror("recv");
        }
        close(client_fd);
        return;
    }

    // Convert from network byte order to host byte order
    received_value = ntohl(received_value);

    std::cout << "Received uint32_t: " << received_value << "\n";
}

int main() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd < 0) {
        perror("Socket creation failed");
        return 1;
    }

    // Configure server address
    sockaddr_in server_addr {};
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY;
    server_addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("Bind failed");
        close(server_fd);
        return 1;
    }

    if (listen(server_fd, SOMAXCONN) < 0) {
        perror("Listen failed");
        close(server_fd);
        return 1;
    }

    std::cout << "Server listening on port " << PORT << "\n";

    // Create epoll instance
    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("Epoll creation failed");
        close(server_fd);
        return 1;
    }

    // Register the server socket with epoll
    epoll_event event {};
    event.events = EPOLLIN;
    event.data.fd = server_fd;

    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, server_fd, &event) < 0) {
        perror("Epoll control failed");
        close(server_fd);
        close(epoll_fd);
        return 1;
    }

    std::vector<epoll_event> events(MAX_EVENTS);

    while (true) {
        int event_count = epoll_wait(epoll_fd, events.data(), MAX_EVENTS, -1);
        if (event_count < 0) {
            perror("Epoll wait failed");
            break;
        }

        for (int i = 0; i < event_count; ++i) {
            if (events[i].data.fd == server_fd) {
                // Accept new client
                sockaddr_in client_addr {};
                socklen_t client_len = sizeof(client_addr);
                int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &client_len);
                if (client_fd < 0) {
                    perror("Accept failed");
                    continue;
                }

                std::cout << "New client connected: " << inet_ntoa(client_addr.sin_addr) << "\n";

                // Add new client to epoll
                event.events = EPOLLIN;
                event.data.fd = client_fd;
                if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &event) < 0) {
                    perror("Failed to add client to epoll");
                    close(client_fd);
                }
            } else {
                // Handle data from existing client
                handle_client(events[i].data.fd);

            }
        }
    }

    close(server_fd);
    close(epoll_fd);

    return 0;
}

