/*
# Copyright 2025 University of California, Riverside
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#
# SPDX-License-Identifier: Apache-2.0
*/

/* Multi-threading TCP Client */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/epoll.h>
#include <pthread.h>

#define PORT 12345
#define SERVER_IP "127.0.0.1"
#define NUM_CLIENTS 4
#define MAX_EVENTS 1024
#define BUFFER_SIZE 16

void* client_thread_func(void* arg) {
    int thread_id = *(int*)arg;
    int client_fd = socket(AF_INET, SOCK_STREAM, 0);
    if (client_fd < 0) {
        perror("socket");
        pthread_exit(NULL);
    }

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    if (inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr) <= 0) {
        perror("inet_pton");
        close(client_fd);
        pthread_exit(NULL);
    }

    if (connect(client_fd, (struct sockaddr*)&server_addr, sizeof(server_addr)) < 0) {
        perror("connect");
        close(client_fd);
        pthread_exit(NULL);
    }

    int epoll_fd = epoll_create1(0);
    if (epoll_fd < 0) {
        perror("epoll_create1");
        close(client_fd);
        pthread_exit(NULL);
    }

    struct epoll_event ev, events[MAX_EVENTS];
    ev.events = EPOLLIN;
    ev.data.fd = client_fd;
    if (epoll_ctl(epoll_fd, EPOLL_CTL_ADD, client_fd, &ev) < 0) {
        perror("epoll_ctl");
        close(client_fd);
        close(epoll_fd);
        pthread_exit(NULL);
    }

    char buffer[BUFFER_SIZE];
    snprintf(buffer, BUFFER_SIZE, "Hello from %d", thread_id);

    if (write(client_fd, buffer, BUFFER_SIZE) < 0) {
        perror("write");
    }

    while (1) {
        int n = epoll_wait(epoll_fd, events, MAX_EVENTS, -1);
        if (n < 0) {
            perror("epoll_wait");
            break;
        }

        for (int i = 0; i < n; i++) {
            if (events[i].data.fd == client_fd) {
                ssize_t bytes_read = read(client_fd, buffer, BUFFER_SIZE);
                if (bytes_read <= 0) {
                    if (bytes_read == 0) {
                        printf("Server closed connection\n");
                    } else {
                        perror("read");
                    }
                    close(client_fd);
                    close(epoll_fd);
                    pthread_exit(NULL);
                }

                printf("Thread %d received: %s\n", thread_id, buffer);
            }
        }
    }

    close(client_fd);
    close(epoll_fd);
    pthread_exit(NULL);
}

int main() {
    pthread_t threads[NUM_CLIENTS];
    int thread_ids[NUM_CLIENTS];

    for (int i = 0; i < NUM_CLIENTS; i++) {
        thread_ids[i] = i;
        if (pthread_create(&threads[i], NULL, client_thread_func, &thread_ids[i]) != 0) {
            perror("pthread_create");
            exit(EXIT_FAILURE);
        }
    }

    for (int i = 0; i < NUM_CLIENTS; i++) {
        pthread_join(threads[i], NULL);
    }

    return 0;
}
