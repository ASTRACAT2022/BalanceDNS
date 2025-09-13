// ultra_fast_dns_server.cpp
#include <ares.h>
#include <iostream>
#include <vector>
#include <thread>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <cstring>
#include <chrono>
#include <mutex>
#include <unordered_map>
#include <queue>
#include <atomic>
#include <condition_variable>
#include <functional>
#include <memory>
#include <shared_mutex>

#define DNS_PORT 5311
#define BUF_SIZE 512
#define CACHE_SIZE 10000
#define CACHE_TTL 300 // 5 минут

// DNS RCODE значения
#define RCODE_NOERROR 0
#define RCODE_FORMERR 1
#define RCODE_SERVFAIL 2
#define RCODE_NXDOMAIN 3

// DNS заголовок
#pragma pack(push, 1)
struct DNSHeader {
    uint16_t id;
    uint16_t flags;
    uint16_t qdcount;
    uint16_t ancount;
    uint16_t nscount;
    uint16_t arcount;
};
#pragma pack(pop)

// Высокопроизводительный DNS-кэш
class UltraFastCache {
private:
    struct CacheEntry {
        std::vector<uint8_t> data;
        std::chrono::steady_clock::time_point expiry_time;
        uint64_t last_access;
        uint64_t access_count;
        
        CacheEntry(const std::vector<uint8_t>& d, std::chrono::steady_clock::time_point expiry)
            : data(d), expiry_time(expiry), last_access(0), access_count(0) {}
    };
    
    // Хэш-таблица для быстрого поиска
    std::unordered_map<std::string, std::unique_ptr<CacheEntry>> cache_map;
    
    // Очередь для LRU (Least Recently Used) eviction
    std::deque<std::pair<std::string, std::chrono::steady_clock::time_point>> lru_queue;
    
    // Мьютекс для потокобезопасности
    mutable std::shared_mutex cache_mutex;
    
    // Счетчики для статистики
    std::atomic<uint64_t> hits{0};
    std::atomic<uint64_t> misses{0};
    std::atomic<uint64_t> evictions{0};
    
    // Генератор временных меток
    std::atomic<uint64_t> timestamp_counter{0};

public:
    void put(const std::string& key, const std::vector<uint8_t>& data) {
        auto expiry = std::chrono::steady_clock::now() + std::chrono::seconds(CACHE_TTL);
        uint64_t timestamp = timestamp_counter.fetch_add(1);
        
        std::unique_lock<std::shared_mutex> lock(cache_mutex);
        
        // Если кэш переполнен, удаляем наименее используемые записи
        if (cache_map.size() >= CACHE_SIZE) {
            evict_expired_entries();
            if (cache_map.size() >= CACHE_SIZE) {
                evict_lru_entry();
            }
        }
        
        // Создаем новую запись
        auto entry = std::make_unique<CacheEntry>(data, expiry);
        entry->last_access = timestamp;
        entry->access_count = 1;
        
        cache_map[key] = std::move(entry);
        lru_queue.emplace_back(key, expiry);
    }

    std::vector<uint8_t> get(const std::string& key) {
        std::shared_lock<std::shared_mutex> lock(cache_mutex);
        
        auto it = cache_map.find(key);
        if (it != cache_map.end()) {
            auto now = std::chrono::steady_clock::now();
            
            // Проверяем, не истекло ли время жизни
            if (now < it->second->expiry_time) {
                // Обновляем метрики доступа
                uint64_t timestamp = timestamp_counter.fetch_add(1);
                it->second->last_access = timestamp;
                it->second->access_count++;
                hits.fetch_add(1, std::memory_order_relaxed);
                
                return it->second->data;
            } else {
                // Запись устарела
                misses.fetch_add(1, std::memory_order_relaxed);
            }
        } else {
            misses.fetch_add(1, std::memory_order_relaxed);
        }
        
        return {};
    }
    
    // Удаление устаревших записей
    void evict_expired_entries() {
        auto now = std::chrono::steady_clock::now();
        std::unique_lock<std::shared_mutex> lock(cache_mutex);
        
        for (auto it = cache_map.begin(); it != cache_map.end();) {
            if (now >= it->second->expiry_time) {
                it = cache_map.erase(it);
                evictions.fetch_add(1, std::memory_order_relaxed);
            } else {
                ++it;
            }
        }
    }
    
    // Удаление наименее используемой записи (LRU)
    void evict_lru_entry() {
        if (cache_map.empty()) return;
        
        std::unique_lock<std::shared_mutex> lock(cache_mutex);
        if (cache_map.empty()) return;
        
        // Находим запись с наименьшим счетчиком доступа и старой меткой времени
        auto lru_it = cache_map.begin();
        uint64_t min_access = lru_it->second->access_count;
        uint64_t oldest_timestamp = lru_it->second->last_access;
        
        for (auto it = cache_map.begin(); it != cache_map.end(); ++it) {
            if (it->second->access_count < min_access || 
                (it->second->access_count == min_access && it->second->last_access < oldest_timestamp)) {
                lru_it = it;
                min_access = it->second->access_count;
                oldest_timestamp = it->second->last_access;
            }
        }
        
        cache_map.erase(lru_it);
        evictions.fetch_add(1, std::memory_order_relaxed);
    }
    
    // Получение статистики
    struct CacheStats {
        uint64_t hits;
        uint64_t misses;
        uint64_t evictions;
        size_t size;
    };
    
    CacheStats get_stats() const {
        std::shared_lock<std::shared_mutex> lock(cache_mutex);
        return {
            hits.load(std::memory_order_relaxed),
            misses.load(std::memory_order_relaxed),
            evictions.load(std::memory_order_relaxed),
            cache_map.size()
        };
    }
    
    // Очистка всего кэша
    void clear() {
        std::unique_lock<std::shared_mutex> lock(cache_mutex);
        cache_map.clear();
        lru_queue.clear();
    }
};

// Пул потоков
class ThreadPool {
private:
    std::vector<std::thread> workers;
    std::queue<std::function<void()>> tasks;
    std::mutex queue_mutex;
    std::condition_variable condition;
    std::atomic<bool> stop{false};

public:
    ThreadPool(size_t threads) {
        for(size_t i = 0; i < threads; ++i) {
            workers.emplace_back([this] {
                while(true) {
                    std::function<void()> task;
                    {
                        std::unique_lock<std::mutex> lock(this->queue_mutex);
                        this->condition.wait(lock, [this]{ return this->stop.load() || !this->tasks.empty(); });
                        if(this->stop.load() && this->tasks.empty()) return;
                        task = std::move(this->tasks.front());
                        this->tasks.pop();
                    }
                    task();
                }
            });
        }
    }

    template<class F>
    void enqueue(F&& f) {
        {
            std::unique_lock<std::mutex> lock(queue_mutex);
            if(stop.load()) throw std::runtime_error("enqueue on stopped ThreadPool");
            tasks.emplace(std::forward<F>(f));
        }
        condition.notify_one();
    }

    ~ThreadPool() {
        stop.store(true);
        condition.notify_all();
        for(std::thread &worker: workers) worker.join();
    }
};

// Высокопроизводительный DNS-сервер
class UltraFastDNSServer {
private:
    int server_socket;
    UltraFastCache cache;
    std::unique_ptr<ThreadPool> thread_pool;
    std::atomic<uint64_t> queries_processed{0};
    std::atomic<uint64_t> errors_occurred{0};

public:
    UltraFastDNSServer() : server_socket(-1) {
        // Создаем пул потоков
        size_t thread_count = std::thread::hardware_concurrency();
        if (thread_count == 0) thread_count = 4;
        thread_pool = std::make_unique<ThreadPool>(thread_count);
        std::cout << "Thread pool initialized with " << thread_count << " threads" << std::endl;

        // Создаем сокет
        server_socket = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (server_socket < 0) {
            throw std::runtime_error("Failed to create socket");
        }

        // Увеличиваем размеры буферов
        int buffer_size = 4 * 1024 * 1024; // 4MB
        setsockopt(server_socket, SOL_SOCKET, SO_RCVBUF, &buffer_size, sizeof(buffer_size));
        setsockopt(server_socket, SOL_SOCKET, SO_SNDBUF, &buffer_size, sizeof(buffer_size));

        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = INADDR_ANY;
        addr.sin_port = htons(DNS_PORT);

        if (bind(server_socket, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
            close(server_socket);
            throw std::runtime_error("Failed to bind socket: " + std::to_string(errno));
        }

        std::cout << "Ultra Fast DNS Server started on port " << DNS_PORT << std::endl;
        std::cout << "Custom high-performance cache size: " << CACHE_SIZE << " entries" << std::endl;
        std::cout << "Cache TTL: " << CACHE_TTL << " seconds" << std::endl;
        
        // Запускаем поток для периодической очистки кэша
        start_cache_cleanup_thread();
    }

    ~UltraFastDNSServer() {
        if (server_socket >= 0) {
            close(server_socket);
        }
    }

    void run() {
        uint8_t buffer[BUF_SIZE];
        struct sockaddr_in client_addr;
        socklen_t client_len = sizeof(client_addr);

        std::cout << "Server is ready to handle requests..." << std::endl;

        while (true) {
            ssize_t bytes_received = recvfrom(server_socket, buffer, BUF_SIZE, 0,
                                              (struct sockaddr*)&client_addr, &client_len);
            
            if (bytes_received > 0) {
                // Копируем данные для передачи в пул потоков
                std::vector<uint8_t> data(buffer, buffer + bytes_received);
                
                // Отправляем задачу в пул потоков
                thread_pool->enqueue([this, data, client_addr, client_len]() {
                    handle_request(data, client_addr, client_len);
                });
            }
        }
    }

private:
    void start_cache_cleanup_thread() {
        std::thread cleanup_thread([this]() {
            while (true) {
                std::this_thread::sleep_for(std::chrono::seconds(60));
                
                // Очищаем устаревшие записи
                cache.evict_expired_entries();
                
                // Выводим статистику каждые 5 минут
                static int counter = 0;
                if (++counter % 5 == 0) {
                    auto stats = cache.get_stats();
                    std::cout << "[CACHE STATS] Size: " << stats.size 
                              << ", Hits: " << stats.hits 
                              << ", Misses: " << stats.misses
                              << ", Evictions: " << stats.evictions << std::endl;
                    
                    std::cout << "[SERVER STATS] Processed: " << queries_processed.load()
                              << ", Errors: " << errors_occurred.load() << std::endl;
                }
            }
        });
        cleanup_thread.detach();
    }

    std::string parse_domain_name(const std::vector<uint8_t>& data, size_t& offset) {
        std::string domain;
        if (offset >= data.size()) return "";

        while (offset < data.size() && data[offset] != 0) {
            if ((data[offset] & 0xC0) == 0xC0) {
                offset += 2;
                break;
            }
            uint8_t len = data[offset++];
            if (offset + len > data.size()) {
                return "";
            }
            if (!domain.empty()) domain += ".";
            domain.append(reinterpret_cast<const char*>(data.data() + offset), len);
            offset += len;
        }
        
        if (offset < data.size() && data[offset] == 0) {
            offset++;
        }

        return domain;
    }

    void handle_request(const std::vector<uint8_t>& data,
                       const struct sockaddr_in& client_addr, 
                       socklen_t client_len) {
        try {
            if (data.size() < sizeof(DNSHeader)) {
                return;
            }

            DNSHeader header;
            std::memcpy(&header, data.data(), sizeof(header));
            header.id = ntohs(header.id);
            header.flags = ntohs(header.flags);
            header.qdcount = ntohs(header.qdcount);

            // Проверяем, что это запрос
            if ((header.flags & 0x8000) != 0) {
                return;
            }

            size_t offset = sizeof(DNSHeader);
            std::string domain = parse_domain_name(data, offset);
            if (domain.empty() || offset + 4 > data.size()) {
                send_error_response(header.id, RCODE_FORMERR, client_addr, client_len);
                errors_occurred.fetch_add(1, std::memory_order_relaxed);
                return;
            }

            uint16_t qtype, qclass;
            std::memcpy(&qtype, data.data() + offset, 2);
            std::memcpy(&qclass, data.data() + offset + 2, 2);
            qtype = ntohs(qtype);
            qclass = ntohs(qclass);

            // Создаем ключ кэша
            std::string cache_key = domain + "_" + std::to_string(qtype);

            // Проверяем кэш
            auto cached_response = cache.get(cache_key);
            if (!cached_response.empty()) {
                // Восстанавливаем ID
                if (cached_response.size() >= 2) {
                    cached_response[0] = (header.id >> 8) & 0xFF;
                    cached_response[1] = header.id & 0xFF;
                }
                
                sendto(server_socket, cached_response.data(), cached_response.size(), 0,
                       (struct sockaddr*)&client_addr, client_len);
                queries_processed.fetch_add(1, std::memory_order_relaxed);
                return;
            }

            // Выполняем рекурсивный запрос
            auto response = perform_recursive_lookup(domain, qtype, qclass);
            
            if (!response.empty()) {
                // Сохраняем в кэш (без ID)
                std::vector<uint8_t> cache_data = response;
                if (cache_data.size() >= 2) {
                    cache_data[0] = 0;
                    cache_data[1] = 0;
                }
                cache.put(cache_key, cache_data);
                
                // Восстанавливаем ID
                if (response.size() >= 2) {
                    response[0] = (header.id >> 8) & 0xFF;
                    response[1] = header.id & 0xFF;
                }
                
                sendto(server_socket, response.data(), response.size(), 0,
                       (struct sockaddr*)&client_addr, client_len);
            } else {
                send_error_response(header.id, RCODE_SERVFAIL, client_addr, client_len);
                errors_occurred.fetch_add(1, std::memory_order_relaxed);
            }
            
            queries_processed.fetch_add(1, std::memory_order_relaxed);
            
        } catch (const std::exception& e) {
            std::cerr << "Error handling request: " << e.what() << std::endl;
            errors_occurred.fetch_add(1, std::memory_order_relaxed);
        }
    }

    std::vector<uint8_t> perform_recursive_lookup(const std::string& domain, 
                                                 uint16_t qtype, 
                                                 uint16_t qclass) {
        ares_channel channel;
        struct ares_options options = {};
        options.timeout = 2000; // 2 секунды
        options.tries = 2; // 2 попытки
        
        int status = ares_init_options(&channel, &options, 
                                      ARES_OPT_TIMEOUTMS | ARES_OPT_TRIES);
        if (status != ARES_SUCCESS) {
            std::cerr << "c-ares init failed: " << ares_strerror(status) << std::endl;
            return {};
        }

        // Настраиваем корневые сервера
        struct ares_addr_node root_servers[13];
        
        const char* root_ips[] = {
            "198.41.0.4",    // a.root-servers.net
            "199.9.14.201",  // b.root-servers.net
            "192.33.4.12",   // c.root-servers.net
            "199.7.91.13",   // d.root-servers.net
            "192.203.230.10", // e.root-servers.net
            "192.5.5.241",   // f.root-servers.net
            "192.112.36.4",  // g.root-servers.net
            "198.97.190.53", // h.root-servers.net
            "192.36.148.17", // i.root-servers.net
            "192.58.128.30", // j.root-servers.net
            "193.0.14.129",  // k.root-servers.net
            "199.7.83.42",   // l.root-servers.net
            "202.12.27.33"   // m.root-servers.net
        };
        
        for (int i = 0; i < 13; i++) {
            root_servers[i].next = (i < 12) ? &root_servers[i+1] : nullptr;
            root_servers[i].family = AF_INET;
            inet_pton(AF_INET, root_ips[i], &root_servers[i].addr.addr4);
        }
        
        ares_set_servers(channel, root_servers);

        std::vector<uint8_t> result;
        bool completed = false;

        ares_query(channel, domain.c_str(), qclass, qtype,
                  [](void* arg, int status, int timeouts, unsigned char* abuf, int alen) {
                      auto* result_vec = static_cast<std::vector<uint8_t>*>(arg);
                      
                      if (status == ARES_SUCCESS && abuf && alen > 0) {
                          result_vec->assign(abuf, abuf + alen);
                      }
                      // Отмечаем завершение
                      static bool dummy = true;
                      dummy = true;
                  }, 
                  &result);

        auto start_time = std::chrono::steady_clock::now();
        while (result.empty()) {
            fd_set readers, writers;
            FD_ZERO(&readers);
            FD_ZERO(&writers);
            
            int nfds = ares_fds(channel, &readers, &writers);
            if (nfds > 0) {
                struct timeval tv;
                tv.tv_sec = 0;
                tv.tv_usec = 50000; // 50ms
                
                if (select(nfds, &readers, &writers, NULL, &tv) >= 0) {
                    ares_process(channel, &readers, &writers);
                }
            } else {
                std::this_thread::sleep_for(std::chrono::milliseconds(1));
            }
            
            auto now = std::chrono::steady_clock::now();
            if (std::chrono::duration_cast<std::chrono::milliseconds>(now - start_time).count() > 3000) {
                break;
            }
        }

        ares_destroy(channel);
        return result;
    }

    void send_error_response(uint16_t id, uint16_t rcode,
                           const struct sockaddr_in& client_addr, 
                           socklen_t client_len) {
        std::vector<uint8_t> response(12, 0);
        
        uint16_t flags = 0x8000; // QR bit
        flags |= (rcode & 0x000F); // RCODE
        
        response[0] = (id >> 8) & 0xFF;
        response[1] = id & 0xFF;
        response[2] = (flags >> 8) & 0xFF;
        response[3] = flags & 0xFF;
        
        sendto(server_socket, response.data(), response.size(), 0,
               (struct sockaddr*)&client_addr, client_len);
    }
};

int main() {
    try {
        UltraFastDNSServer server;
        std::cout << "Ultra-fast DNS server features:" << std::endl;
        std::cout << "  - Custom LRU cache with " << CACHE_SIZE << " entries" << std::endl;
        std::cout << "  - Multi-threaded processing" << std::endl;
        std::cout << "  - Atomic counters for performance" << std::endl;
        std::cout << "  - Large socket buffers (4MB)" << std::endl;
        std::cout << "\nTest commands:" << std::endl;
        std::cout << "  dig @127.0.0.1 -p 5311 google.com" << std::endl;
        std::cout << "  dig @127.0.0.1 -p 5311 github.com" << std::endl;
        server.run();
    } catch (const std::exception& e) {
        std::cerr << "Error: " << e.what() << std::endl;
        return 1;
    }
    
    return 0;
}
