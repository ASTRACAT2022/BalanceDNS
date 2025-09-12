#include <iostream>
#include <unordered_map>
#include <string>
#include <chrono>
#include <thread>
#include <vector>
#include <cstring>
#include <memory>
#include <mutex>
#include <list>
#include <sqlite3.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <fcntl.h>
#include <poll.h>
#include <ldns/ldns.h>

using namespace std;

// === КОНФИГУРАЦИЯ ===
const int UDP_PORT = 5318;
const int TCP_PORT = 5318;
const string CACHE_DB = "dns_cache.db";
const size_t MAX_CACHE_SIZE = 10000;
const bool BIND_TO_LOCALHOST_ONLY = true; // Новое: Привязка только к 127.0.0.1 и ::1

// === LRU CACHE IMPLEMENTATION ===
template<typename Key, typename Value>
class LRUCache {
private:
    struct Node {
        Key key;
        Value value;
        time_t expiry;
        bool dnssec_valid;
        typename list<Key>::iterator list_it;
    };
    
    unordered_map<Key, shared_ptr<Node>> cache_map;
    list<Key> cache_list;
    size_t max_size;
    mutex cache_mutex;

public:
    LRUCache(size_t size) : max_size(size) {}
    
    bool get(const Key& key, Value& value, bool& valid) {
        lock_guard<mutex> lock(cache_mutex);
        
        auto it = cache_map.find(key);
        if (it == cache_map.end()) return false;
        
        auto node = it->second;
        if (time(nullptr) > node->expiry) {
            cache_list.erase(node->list_it);
            cache_map.erase(it);
            return false;
        }
        
        cache_list.erase(node->list_it);
        cache_list.push_front(key);
        node->list_it = cache_list.begin();
        
        value = node->value;
        valid = node->dnssec_valid;
        return true;
    }
    
    void put(const Key& key, const Value& value, time_t ttl, bool valid) {
        lock_guard<mutex> lock(cache_mutex);
        
        auto it = cache_map.find(key);
        if (it != cache_map.end()) {
            auto node = it->second;
            node->value = value;
            node->expiry = time(nullptr) + ttl;
            node->dnssec_valid = valid;
            
            cache_list.erase(node->list_it);
            cache_list.push_front(key);
            node->list_it = cache_list.begin();
        } else {
            if (cache_map.size() >= max_size) {
                Key old_key = cache_list.back();
                cache_list.pop_back();
                cache_map.erase(old_key);
            }
            
            auto node = make_shared<Node>();
            node->key = key;
            node->value = value;
            node->expiry = time(nullptr) + ttl;
            node->dnssec_valid = valid;
            
            cache_list.push_front(key);
            node->list_it = cache_list.begin();
            cache_map[key] = node;
        }
    }
    
    size_t size() {
        lock_guard<mutex> lock(cache_mutex);
        return cache_map.size();
    }
};

// === ГЛОБАЛЬНЫЕ ПЕРЕМЕННЫЕ ===
sqlite3* cache_db = nullptr;
LRUCache<string, string> lru_cache(MAX_CACHE_SIZE);
ldns_rr_list* trust_anchors = nullptr;

// === ИНИЦИАЛИЗАЦИЯ ===
void init_cache() {
    int rc = sqlite3_open(CACHE_DB.c_str(), &cache_db);
    if (rc) {
        cerr << "Can't open database: " << sqlite3_errmsg(cache_db) << endl;
        exit(1);
    }
    
    const char* create_table = R"(
        CREATE TABLE IF NOT EXISTS dns_cache (
            key TEXT PRIMARY KEY,
            data BLOB,
            expiry INTEGER,
            dnssec_valid INTEGER
        );
    )";
    
    char* errMsg = 0;
    rc = sqlite3_exec(cache_db, create_table, 0, 0, &errMsg);
    if (rc != SQLITE_OK) {
        cerr << "SQL error: " << errMsg << endl;
        sqlite3_free(errMsg);
        exit(1);
    }
    
    trust_anchors = ldns_rr_list_new();
    ldns_rr *root_ds;
    // RFC 5011 Trust Anchor
    ldns_status status = ldns_rr_new_frm_str(&root_ds,
        ". IN DS 20326 8 2 E06D44B80B8F1D39A95C0B0D7C65D08458E880409BBC683457104237C7F8EC8D",
        0, NULL, NULL);
    if (status == LDNS_STATUS_OK && root_ds) {
        ldns_rr_list_push_rr(trust_anchors, root_ds);
    } else {
        cerr << "Warning: Failed to create root DS record" << endl;
    }
}

// === РАБОТА С КЭШЕМ ===
void cache_store(const string& key, ldns_pkt* pkt, bool valid) {
    string wire_data;
    size_t wire_len = 0;
    uint8_t* wire = nullptr;
    ldns_status status = ldns_pkt2wire(&wire, pkt, &wire_len);
    if (status == LDNS_STATUS_OK && wire) {
        wire_data.assign((char*)wire, wire_len);
        LDNS_FREE(wire);
    }
    
    time_t ttl = 300;
    ldns_rr_list* answers = ldns_pkt_answer(pkt);
    if (answers && ldns_rr_list_rr_count(answers) > 0) {
        ldns_rr* first = ldns_rr_list_rr(answers, 0);
        ttl = ldns_rr_ttl(first);
    }
    
    lru_cache.put(key, wire_data, ttl, valid);
    
    sqlite3_stmt* stmt;
    const char* sql = "INSERT OR REPLACE INTO dns_cache (key, data, expiry, dnssec_valid) VALUES (?, ?, ?, ?)";
    int rc = sqlite3_prepare_v2(cache_db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_blob(stmt, 2, wire_data.data(), wire_data.size(), SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 3, time(nullptr) + ttl);
        sqlite3_bind_int(stmt, 4, valid ? 1 : 0);
        
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
}

ldns_pkt* cache_lookup(const string& key, bool& valid) {
    string wire_data;
    if (lru_cache.get(key, wire_data, valid)) {
        ldns_pkt* pkt = nullptr;
        ldns_wire2pkt(&pkt, (const uint8_t*)wire_data.data(), wire_data.size());
        return pkt;
    }
    
    sqlite3_stmt* stmt;
    const char* sql = "SELECT data, dnssec_valid FROM dns_cache WHERE key = ? AND expiry > ?";
    int rc = sqlite3_prepare_v2(cache_db, sql, -1, &stmt, NULL);
    if (rc == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, key.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_int64(stmt, 2, time(nullptr));
        
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const void* data = sqlite3_column_blob(stmt, 0);
            int data_len = sqlite3_column_bytes(stmt, 0);
            valid = sqlite3_column_int(stmt, 1);
            
            ldns_pkt* pkt = nullptr;
            ldns_wire2pkt(&pkt, (const uint8_t*)data, data_len);
            sqlite3_finalize(stmt);
            
            if (pkt) {
                string data_str((const char*)data, data_len);
                time_t ttl = 300;
                ldns_rr_list* answers = ldns_pkt_answer(pkt);
                if (answers && ldns_rr_list_rr_count(answers) > 0) {
                    ttl = ldns_rr_ttl(ldns_rr_list_rr(answers, 0));
                }
                lru_cache.put(key, data_str, ttl, valid);
            }
            
            return pkt;
        }
        sqlite3_finalize(stmt);
    }
    
    valid = false;
    return nullptr;
}

// === DNSSEC ВАЛИДАЦИЯ ===
bool validate_dnssec(ldns_pkt* pkt, const string& qname) {
    if (!trust_anchors || !pkt) return false;
    
    ldns_resolver* res = nullptr;
    ldns_resolver_new_frm_file(&res, NULL);
    if (!res) return false;
    
    ldns_resolver_set_dnssec(res, 1);
    ldns_resolver_set_dnssec_cd(res, 1); // Checking Disabled - мы проверяем сами
    ldns_resolver_set_dnssec_anchors(res, ldns_rr_list_clone(trust_anchors));
    
    ldns_rdf* qname_rdf = ldns_dname_new_frm_str(qname.c_str());
    if (!qname_rdf) {
        ldns_resolver_deep_free(res);
        return false;
    }
    
    // Запрашиваем DNSKEY для домена
    ldns_pkt* dnskey_response = ldns_resolver_query(res, qname_rdf, LDNS_RR_TYPE_DNSKEY, LDNS_RR_CLASS_IN, LDNS_RD);
    ldns_rr_list* dnskeys = nullptr;
    if (dnskey_response) {
        dnskeys = ldns_pkt_rr_list_by_type(dnskey_response, LDNS_RR_TYPE_DNSKEY, LDNS_SECTION_ANSWER);
    }
    
    // Получаем RRset для валидации
    ldns_rr_list* rrset = ldns_pkt_rr_list_by_name_and_type(pkt, 
        qname_rdf, 
        LDNS_RR_TYPE_ANY, 
        LDNS_SECTION_ANSWER);
    
    // Получаем RRSIG записи
    ldns_rr_list* rrsigs = ldns_pkt_rr_list_by_type(pkt, LDNS_RR_TYPE_RRSIG, LDNS_SECTION_ANSWER);
    
    ldns_rdf_deep_free(qname_rdf);
    
    if (!rrset || !rrsigs || ldns_rr_list_rr_count(rrsigs) == 0) {
        if(dnskey_response) ldns_pkt_free(dnskey_response);
        if(dnskeys) ldns_rr_list_deep_free(dnskeys);
        if(rrset) ldns_rr_list_deep_free(rrset);
        if(rrsigs) ldns_rr_list_deep_free(rrsigs);
        ldns_resolver_deep_free(res);
        return false;
    }
    
    // Проверяем каждую RRSIG запись
    bool all_valid = true;
    for (size_t i = 0; i < ldns_rr_list_rr_count(rrsigs); i++) {
        ldns_rr* rrsig = ldns_rr_list_rr(rrsigs, i);
        ldns_status status = ldns_verify_rrsig_keylist(rrset, rrsig, dnskeys, NULL);
        if (status != LDNS_STATUS_OK) {
            all_valid = false;
            // cout << "DNSSEC validation failed for " << qname << " with status: " << status << endl; // Для отладки
            break;
        }
    }
    
    ldns_rr_list_deep_free(rrset);
    ldns_rr_list_deep_free(rrsigs);
    if(dnskey_response) ldns_pkt_free(dnskey_response);
    if(dnskeys) ldns_rr_list_deep_free(dnskeys);
    ldns_resolver_deep_free(res);
    
    return all_valid;
}

// === ОТПРАВКА ЗАПРОСА ===
ldns_pkt* send_dns_query(const string& qname, ldns_rr_type qtype) {
    ldns_resolver* res = nullptr;
    ldns_rdf* domain = ldns_dname_new_frm_str(qname.c_str());
    
    ldns_resolver_new_frm_file(&res, NULL);
    if (!res) {
        if(domain) ldns_rdf_deep_free(domain);
        return nullptr;
    }
    
    ldns_resolver_set_dnssec(res, 1);
    ldns_resolver_set_dnssec_cd(res, 1); // Checking Disabled
    
    ldns_pkt* pkt = ldns_resolver_query(res, domain, qtype, LDNS_RR_CLASS_IN, LDNS_RD);
    
    ldns_rdf_deep_free(domain);
    ldns_resolver_deep_free(res);
    
    return pkt;
}

// === ОБРАБОТКА ЗАПРОСА ===
ldns_pkt* handle_dns_query(const string& qname, ldns_rr_type qtype, bool& dnssec_valid) {
    string cache_key = qname + "_" + to_string(qtype);
    
    ldns_pkt* cached = cache_lookup(cache_key, dnssec_valid);
    if (cached) {
        cout << "[CACHE HIT] " << qname << " type " << qtype << endl;
        return cached;
    }
    
    cout << "[QUERYING] " << qname << " type " << qtype << endl;
    
    ldns_pkt* response = send_dns_query(qname, qtype);
    if (!response) return nullptr;
    
    dnssec_valid = validate_dnssec(response, qname);
    
    cache_store(cache_key, response, dnssec_valid);
    
    return response;
}

// === UDP ОБРАБОТЧИК ===
void handle_udp_request(int sockfd, bool is_ipv6 = false) {
    char buffer[4096];
    struct sockaddr_storage client_addr{};
    socklen_t len = is_ipv6 ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
    
    int n = recvfrom(sockfd, buffer, sizeof(buffer), 0, 
                     (struct sockaddr*)&client_addr, &len);
    if (n <= 0) return;
    
    ldns_pkt* query = nullptr;
    ldns_status status = ldns_wire2pkt(&query, (uint8_t*)buffer, n);
    if (status != LDNS_STATUS_OK || !query) {
        cerr << "Failed to parse incoming UDP packet" << endl;
        return;
    }
    
    ldns_rr_list* questions = ldns_pkt_question(query);
    if (!questions || ldns_rr_list_rr_count(questions) == 0) {
        ldns_pkt_free(query);
        return;
    }
    
    ldns_rr* question = ldns_rr_list_rr(questions, 0);
    ldns_rdf* qname_rdf = ldns_rr_owner(question);
    ldns_rr_type qtype = ldns_rr_get_type(question);
    
    char* qname_cstr = ldns_rdf2str(qname_rdf);
    string qname(qname_cstr ? qname_cstr : "");
    if(qname_cstr) free(qname_cstr);
    
    if(qname.empty()) {
        ldns_pkt_free(query);
        return;
    }
    
    bool dnssec_valid = false;
    ldns_pkt* response = handle_dns_query(qname, qtype, dnssec_valid);
    
    if (response) {
        ldns_pkt_set_id(response, ldns_pkt_id(query));
        
        if (dnssec_valid) {
            ldns_pkt_set_ad(response, 1);
        }
        
        size_t wire_len = 0;
        uint8_t* wire_data = nullptr;
        ldns_pkt2wire(&wire_data, response, &wire_len);
        
        if (wire_data && wire_len <= 512) {
            sendto(sockfd, wire_data, wire_len, 0, 
                   (struct sockaddr*)&client_addr, len);
        } else {
            ldns_pkt* truncated = ldns_pkt_new();
            ldns_pkt_set_id(truncated, ldns_pkt_id(query));
            ldns_pkt_set_tc(truncated, 1);
            
            size_t trunc_len = 0;
            uint8_t* trunc_data = nullptr;
            ldns_pkt2wire(&trunc_data, truncated, &trunc_len);
            
            if (trunc_data) {
                sendto(sockfd, trunc_data, trunc_len, 0,
                       (struct sockaddr*)&client_addr, len);
                LDNS_FREE(trunc_data);
            }
            ldns_pkt_free(truncated);
        }
        
        if (wire_data) LDNS_FREE(wire_data);
        ldns_pkt_free(response);
    } else {
        cerr << "No response for " << qname << " type " << qtype << endl;
    }
    
    ldns_pkt_free(query);
}

// === TCP ОБРАБОТЧИК ===
void handle_tcp_request(int client_fd, bool is_ipv6 = false) {
    uint16_t len_nbo;
    if (recv(client_fd, &len_nbo, 2, MSG_WAITALL) != 2) {
        close(client_fd);
        return;
    }
    
    uint16_t len = ntohs(len_nbo);
    if (len > 4096) {
        close(client_fd);
        return;
    }
    
    vector<uint8_t> buffer(len);
    if (recv(client_fd, buffer.data(), len, MSG_WAITALL) != len) {
        close(client_fd);
        return;
    }
    
    ldns_pkt* query = nullptr;
    ldns_status status = ldns_wire2pkt(&query, buffer.data(), len);
    if (status != LDNS_STATUS_OK || !query) {
        cerr << "Failed to parse incoming TCP packet" << endl;
        close(client_fd);
        return;
    }
    
    ldns_rr_list* questions = ldns_pkt_question(query);
    if (!questions || ldns_rr_list_rr_count(questions) == 0) {
        ldns_pkt_free(query);
        close(client_fd);
        return;
    }
    
    ldns_rr* question = ldns_rr_list_rr(questions, 0);
    ldns_rdf* qname_rdf = ldns_rr_owner(question);
    ldns_rr_type qtype = ldns_rr_get_type(question);
    
    char* qname_cstr = ldns_rdf2str(qname_rdf);
    string qname(qname_cstr ? qname_cstr : "");
    if(qname_cstr) free(qname_cstr);
    
    if(qname.empty()) {
        ldns_pkt_free(query);
        close(client_fd);
        return;
    }
    
    bool dnssec_valid = false;
    ldns_pkt* response = handle_dns_query(qname, qtype, dnssec_valid);
    
    if (response) {
        ldns_pkt_set_id(response, ldns_pkt_id(query));
        
        if (dnssec_valid) {
            ldns_pkt_set_ad(response, 1);
        }
        
        size_t wire_len = 0;
        uint8_t* wire_data = nullptr;
        ldns_pkt2wire(&wire_data, response, &wire_len);
        
        if (wire_data) {
            uint16_t send_len = htons(wire_len);
            send(client_fd, &send_len, 2, 0);
            send(client_fd, wire_data, wire_len, 0);
            LDNS_FREE(wire_data);
        }
        
        ldns_pkt_free(response);
    } else {
        cerr << "No response for " << qname << " type " << qtype << " (TCP)" << endl;
    }
    
    ldns_pkt_free(query);
    close(client_fd);
}

// === СОЗДАНИЕ И НАСТРОЙКА СОКЕТОВ ===
bool setup_socket(int& sock, int domain, int type, int port, bool is_loopback) {
    sock = socket(domain, type, 0);
    if (sock < 0) {
        perror(type == SOCK_DGRAM ? "UDP socket" : "TCP socket");
        return false;
    }
    
    // Разрешить повторное использование адреса
    int opt = 1;
    if (setsockopt(sock, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt)) < 0) {
        perror("setsockopt SO_REUSEADDR");
        close(sock);
        return false;
    }
    
    if (domain == AF_INET6) {
        // Для IPv6 также разрешаем повторное использование
        if (setsockopt(sock, IPPROTO_IPV6, IPV6_V6ONLY, &opt, sizeof(opt)) < 0) {
            perror("setsockopt IPV6_V6ONLY");
            close(sock);
            return false;
       }
    }

    struct sockaddr_storage addr_storage = {};
    socklen_t addr_len;

    if (domain == AF_INET) {
        struct sockaddr_in* addr_v4 = (struct sockaddr_in*)&addr_storage;
        addr_v4->sin_family = AF_INET;
        addr_v4->sin_port = htons(port);
        if (is_loopback) {
            addr_v4->sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        } else {
            addr_v4->sin_addr.s_addr = INADDR_ANY;
        }
        addr_len = sizeof(*addr_v4);
    } else { // AF_INET6
        struct sockaddr_in6* addr_v6 = (struct sockaddr_in6*)&addr_storage;
        addr_v6->sin6_family = AF_INET6;
        addr_v6->sin6_port = htons(port);
        if (is_loopback) {
            addr_v6->sin6_addr = in6addr_loopback;
        } else {
            addr_v6->sin6_addr = in6addr_any;
        }
        addr_len = sizeof(*addr_v6);
    }

    if (bind(sock, (struct sockaddr*)&addr_storage, addr_len) < 0) {
        string type_str = (type == SOCK_DGRAM) ? "UDP" : "TCP";
        string ip_str = (domain == AF_INET) ? "IPv4" : "IPv6";
        string addr_str = is_loopback ? (domain == AF_INET ? "127.0.0.1" : "::1") : "all interfaces";
        perror((type_str + " " + ip_str + " bind on " + addr_str).c_str());
        close(sock);
        return false;
    }

    if (type == SOCK_STREAM) {
        if (listen(sock, 100) < 0) {
            perror("TCP listen");
            close(sock);
            return false;
        }
        int flags = fcntl(sock, F_GETFL, 0);
        fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    }

    return true;
}


// === ОСНОВНОЙ ЦИКЛ СЕРВЕРА ===
int main() {
    cout << "Initializing DNS server on port " << UDP_PORT << " (localhost only)..." << endl;
    
    init_cache();
    
    int udp_sock_v4, udp_sock_v6, tcp_sock_v4, tcp_sock_v6;
    
    if (!setup_socket(udp_sock_v4, AF_INET, SOCK_DGRAM, UDP_PORT, BIND_TO_LOCALHOST_ONLY)) return 1;
    if (!setup_socket(udp_sock_v6, AF_INET6, SOCK_DGRAM, UDP_PORT, BIND_TO_LOCALHOST_ONLY)) return 1;
    if (!setup_socket(tcp_sock_v4, AF_INET, SOCK_STREAM, TCP_PORT, BIND_TO_LOCALHOST_ONLY)) return 1;
    if (!setup_socket(tcp_sock_v6, AF_INET6, SOCK_STREAM, TCP_PORT, BIND_TO_LOCALHOST_ONLY)) return 1;
    
    cout << "DNS server listening on UDP/TCP ports " << UDP_PORT << " (127.0.0.1 and ::1)" << endl;
    
    struct pollfd fds[4];
    fds[0].fd = udp_sock_v4;
    fds[0].events = POLLIN;
    fds[1].fd = udp_sock_v6;
    fds[1].events = POLLIN;
    fds[2].fd = tcp_sock_v4;
    fds[2].events = POLLIN;
    fds[3].fd = tcp_sock_v6;
    fds[3].events = POLLIN;
    
    while (true) {
        int ret = poll(fds, 4, -1);
        if (ret < 0) {
            perror("poll");
            break;
        }
        
        if (fds[0].revents & POLLIN) {
            handle_udp_request(udp_sock_v4, false);
        }
        
        if (fds[1].revents & POLLIN) {
            handle_udp_request(udp_sock_v6, true);
        }
        
        if (fds[2].revents & POLLIN) {
            struct sockaddr_in6 client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(tcp_sock_v4, (struct sockaddr*)&client_addr, &client_len);
            if (client_fd >= 0) {
                thread(handle_tcp_request, client_fd, false).detach();
            }
        }
        
        if (fds[3].revents & POLLIN) {
            struct sockaddr_in6 client_addr;
            socklen_t client_len = sizeof(client_addr);
            int client_fd = accept(tcp_sock_v6, (struct sockaddr*)&client_addr, &client_len);
            if (client_fd >= 0) {
                thread(handle_tcp_request, client_fd, true).detach();
            }
        }
    }
    
    close(udp_sock_v4);
    close(udp_sock_v6);
    close(tcp_sock_v4);
    close(tcp_sock_v6);
    sqlite3_close(cache_db);
    if(trust_anchors) ldns_rr_list_deep_free(trust_anchors);
    
    return 0;
}
