/*
 * NetShield v1.2 (Production Hardened)
 * Tier-4 ARP Spoofing Detection & Response System
 * Author: Praveen M
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pcap.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <time.h>
#include <signal.h>
#include <sys/wait.h>
#include <curl/curl.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

#define VERSION "NetShield v1.2"
#define LOG_FILE "/var/log/netshield_arp.log"
#define ENV_FILE ".env"

/* ================= Detection Config ================= */
#define MAX_TRACKED 256
#define ALERT_THRESHOLD 3
#define TIME_WINDOW 10 // seconds

typedef struct
{
    char ip[16];
    char mac[18];
    int count;
    time_t first_seen;
    int blocked;
} arp_entry_t;

/* ================= Globals ================= */
static arp_entry_t table[MAX_TRACKED];
static int table_size = 0;
static pcap_t *pcap_handle = NULL;

/* ================= Email Config ================= */
static const char *SMTP_USER;
static const char *SMTP_PASS;
static const char *MAIL_FROM;
static const char *MAIL_TO;
static const char *SMTP_URL = "smtp://smtp.gmail.com:587";
static const char *CA_CERT = "/etc/ssl/certs/ca-certificates.crt";

typedef struct
{
    char ip[16];
    int syn_count;
    int udp_count;
    int icmp_count;
    int total_packets;
    time_t window_start;
    int blocked;
} ddos_entry_t;

/* ================= DDoS Detection Config ================= */
#define MAX_DDOS_TRACKED 512
#define DDOS_WINDOW 3     // seconds
#define PPS_THRESHOLD 500 // packets per second
#define SYN_THRESHOLD 30
#define UDP_THRESHOLD 30
#define ICMP_THRESHOLD 30

static ddos_entry_t ddos_table[MAX_DDOS_TRACKED];
static int ddos_size = 0;

/* ================= UI ================= */
void print_version()
{
    printf("\n=============================================\n");
    printf("               NetShield IDS                 \n");
    printf("       ARP Spoofing Detection Engine          \n");
    printf("               %s                     \n", VERSION);
    printf("=============================================\n");
}

void print_help(const char *bin)
{
    printf("\nUsage: %s [OPTIONS]\n", bin);
    printf(" -i <iface>   Start ARP monitoring\n");
    printf(" -l           List network interfaces\n");
    printf(" -v           Show version\n");
    printf(" -h           Show help\n");
}

void list_interfaces()
{
    pcap_if_t *alldevs, *d;
    char errbuf[PCAP_ERRBUF_SIZE];

    if (pcap_findalldevs(&alldevs, errbuf) != 0)
    {
        printf("Error: %s\n", errbuf);
        return;
    }

    int i = 1;
    for (d = alldevs; d; d = d->next)
        printf(" %d. %s\n", i++, d->name);

    pcap_freealldevs(alldevs);
}

/* ================= Logging ================= */

void log_raw(const char *tag, const char *msg)
{
    FILE *f = fopen(LOG_FILE, "a");
    if (!f)
        return;

    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(f, "[%s] [%s] %s\n", ts, tag, msg);
    fclose(f);
}

void log_event(const char *msg)
{
    FILE *f = fopen(LOG_FILE, "a");
    if (!f)
        return;

    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));
    fprintf(f, "[%s] %s\n", ts, msg);
    fclose(f);
}

void log_packet(const char *src_ip, const char *src_mac,
                const char *dst_ip, const char *dst_mac)
{
    FILE *f = fopen(LOG_FILE, "a");
    if (!f)
        return;

    time_t now = time(NULL);
    char ts[64];
    strftime(ts, sizeof(ts), "%Y-%m-%d %H:%M:%S", localtime(&now));

    fprintf(f,
            "[%s] ARP PACKET | SRC %s (%s) -> DST %s (%s)\n",
            ts, src_ip, src_mac, dst_ip, dst_mac);

    fclose(f);
}

/* ================= ENV Loader ================= */
void load_env()
{
    FILE *f = fopen(ENV_FILE, "r");
    if (!f)
    {
        perror("Missing .env");
        exit(1);
    }

    char line[256];
    while (fgets(line, sizeof(line), f))
    {
        if (line[0] == '#' || strlen(line) < 3)
            continue;
        line[strcspn(line, "\n")] = 0;
        char *eq = strchr(line, '=');
        if (!eq)
            continue;
        *eq = 0;
        setenv(line, eq + 1, 1);
    }
    fclose(f);

    SMTP_USER = getenv("NETSHIELD_SMTP_USER");
    SMTP_PASS = getenv("NETSHIELD_SMTP_PASS");
    MAIL_FROM = getenv("NETSHIELD_MAIL_FROM");
    MAIL_TO = getenv("NETSHIELD_ADMIN_EMAIL");

    if (!SMTP_USER || !SMTP_PASS || !MAIL_FROM || !MAIL_TO)
    {
        fprintf(stderr, "Missing email configuration in .env\n");
        exit(1);
    }
}

/* ================= Cleanup ================= */
void cleanup(int sig)
{
    log_event("NetShield shutting down");
    if (pcap_handle)
        pcap_close(pcap_handle);
    curl_global_cleanup();
    exit(0);
}

/* ================= IP Blocking ================= */
void block_ip(const char *ip)
{
    if (fork() == 0)
    {
        execl("/sbin/iptables", "iptables",
              "-I", "INPUT", "-s", ip, "-j", "DROP", NULL);
        exit(0);
    }
    wait(NULL);
}

/* ================= Email Alert ================= */
struct upload_status
{
    int idx;
    const char *payload[6];
};

static size_t payload_cb(void *ptr, size_t size, size_t nmemb, void *userp)
{
    struct upload_status *u = userp;
    const char *data = u->payload[u->idx];
    if (!data)
        return 0;
    size_t len = strlen(data);
    memcpy(ptr, data, len);
    u->idx++;
    return len;
}

void send_email_alert(const char *ip, const char *mac)
{
    CURL *curl = curl_easy_init();
    if (!curl)
        return;

    struct curl_slist *recipients = NULL;
    struct curl_slist *headers = NULL;
    curl_mime *mime;
    curl_mimepart *part;

    char subject[128];
    snprintf(subject, sizeof(subject),
             "Subject: NetShield ARP Spoof Alert\r\n");

    headers = curl_slist_append(headers, subject);
    headers = curl_slist_append(headers, "Mime-Version: 1.0");

    recipients = curl_slist_append(recipients, MAIL_TO);

    mime = curl_mime_init(curl);

    /* ---- Email Body ---- */
    part = curl_mime_addpart(mime);
    curl_mime_data(part,
                   "ARP Spoofing Detected\n\n"
                   "IP Address: ",
                   CURL_ZERO_TERMINATED);
    curl_mime_data(part, ip, CURL_ZERO_TERMINATED);
    curl_mime_data(part, "\nMAC Address: ", CURL_ZERO_TERMINATED);
    curl_mime_data(part, mac, CURL_ZERO_TERMINATED);
    curl_mime_data(part,
                   "\n\nAction Taken: IP Blocked\n\n"
                   "Log file attached.\n",
                   CURL_ZERO_TERMINATED);

    curl_mime_type(part, "text/plain");

    /* ---- Log File Attachment ---- */
    part = curl_mime_addpart(mime);
    curl_mime_filedata(part, LOG_FILE);
    curl_mime_filename(part, "netshield_arp.log");
    curl_mime_type(part, "text/plain");
    curl_mime_encoder(part, "base64");

    /* ---- SMTP Config ---- */
    curl_easy_setopt(curl, CURLOPT_USERNAME, SMTP_USER);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, SMTP_PASS);
    curl_easy_setopt(curl, CURLOPT_URL, SMTP_URL);
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_CAINFO, CA_CERT);
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, MAIL_FROM);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

    CURLcode res = curl_easy_perform(curl);

    log_event(res == CURLE_OK
                  ? "Email alert sent with log attachment"
                  : "Email alert FAILED");

    curl_slist_free_all(recipients);
    curl_slist_free_all(headers);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
}

void send_ddos_email_alert(const char *ip, const char *type)
{
    CURL *curl = curl_easy_init();
    if (!curl)
        return;

    struct curl_slist *recipients = NULL;
    struct curl_slist *headers = NULL;
    curl_mime *mime;
    curl_mimepart *part;

    /* ---- Email Subject ---- */
    char subject[128];
    snprintf(subject, sizeof(subject),
             "Subject: NetShield DDoS Alert\r\n");

    headers = curl_slist_append(headers, subject);
    headers = curl_slist_append(headers, "Mime-Version: 1.0");

    recipients = curl_slist_append(recipients, MAIL_TO);

    mime = curl_mime_init(curl);

    /* ---- Email Body ---- */
    part = curl_mime_addpart(mime);
    curl_mime_data(part,
                   "DDoS Attack Detected\n\n"
                   "Source IP: ",
                   CURL_ZERO_TERMINATED);
    curl_mime_data(part, ip, CURL_ZERO_TERMINATED);
    curl_mime_data(part, "\nAttack Type: ", CURL_ZERO_TERMINATED);
    curl_mime_data(part, type, CURL_ZERO_TERMINATED);
    curl_mime_data(part,
                   "\n\nAction Taken: IP Blocked\n\n"
                   "Log file attached.\n",
                   CURL_ZERO_TERMINATED);
    curl_mime_type(part, "text/plain");

    /* ---- Log File Attachment ---- */
    part = curl_mime_addpart(mime);
    curl_mime_filedata(part, LOG_FILE);
    curl_mime_filename(part, "netshield_arp.log");
    curl_mime_type(part, "text/plain");
    curl_mime_encoder(part, "base64");

    /* ---- SMTP Config ---- */
    curl_easy_setopt(curl, CURLOPT_USERNAME, SMTP_USER);
    curl_easy_setopt(curl, CURLOPT_PASSWORD, SMTP_PASS);
    curl_easy_setopt(curl, CURLOPT_URL, SMTP_URL);
    curl_easy_setopt(curl, CURLOPT_USE_SSL, CURLUSESSL_ALL);
    curl_easy_setopt(curl, CURLOPT_CAINFO, CA_CERT);
    curl_easy_setopt(curl, CURLOPT_MAIL_FROM, MAIL_FROM);
    curl_easy_setopt(curl, CURLOPT_MAIL_RCPT, recipients);
    curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers);
    curl_easy_setopt(curl, CURLOPT_MIMEPOST, mime);

    /* ---- Send the email ---- */
    CURLcode res = curl_easy_perform(curl);

    log_event(res == CURLE_OK
                  ? "Email alert sent for DDoS attack"
                  : "Email alert FAILED for DDoS attack");

    curl_slist_free_all(recipients);
    curl_slist_free_all(headers);
    curl_mime_free(mime);
    curl_easy_cleanup(curl);
}

/* ================= Detection ================= */
void detect_arp(const char *ip, const char *mac)
{
    time_t now = time(NULL);

    for (int i = 0; i < table_size; i++)
    {
        if (!strcmp(table[i].ip, ip))
        {
            // If already blocked, ignore silently
            if (table[i].blocked)
                return;

            // Reset window
            if (difftime(now, table[i].first_seen) > TIME_WINDOW)
            {
                table[i].count = 1;
                table[i].first_seen = now;
                strcpy(table[i].mac, mac);
                return;
            }

            // MAC changed → possible spoof
            if (strcmp(table[i].mac, mac))
            {
                table[i].count++;

                if (table[i].count >= ALERT_THRESHOLD)
                {
                    table[i].blocked = 1;

                    char warn[256];
                    snprintf(warn, sizeof(warn),
                             "WARNING: ARP SPOOF DETECTED | IP=%s MAC=%s | ACTION=BLOCKED",
                             ip, mac);

                    printf("\n%s\n", warn);
                    log_event(warn);

                    block_ip(ip);
                    send_email_alert(ip, mac);
                }
            }
            return;
        }
    }

    // New IP entry
    if (table_size >= MAX_TRACKED)
    {
        log_event("ARP table full");
        return;
    }

    strcpy(table[table_size].ip, ip);
    strcpy(table[table_size].mac, mac);
    table[table_size].count = 1;
    table[table_size].first_seen = now;
    table[table_size].blocked = 0;
    table_size++;
}

int is_ip_blocked(const char *ip)
{
    for (int i = 0; i < table_size; i++)
        if (!strcmp(table[i].ip, ip) && table[i].blocked)
            return 1;

    for (int i = 0; i < ddos_size; i++)
        if (!strcmp(ddos_table[i].ip, ip) && ddos_table[i].blocked)
            return 1;

    return 0;
}

ddos_entry_t *get_ddos_entry(const char *ip)
{
    for (int i = 0; i < ddos_size; i++)
    {
        if (!strcmp(ddos_table[i].ip, ip))
            return &ddos_table[i];
    }

    if (ddos_size >= MAX_DDOS_TRACKED)
        return NULL;

    strcpy(ddos_table[ddos_size].ip, ip);
    ddos_table[ddos_size].syn_count = 0;
    ddos_table[ddos_size].udp_count = 0;
    ddos_table[ddos_size].icmp_count = 0;
    ddos_table[ddos_size].total_packets = 0;
    ddos_table[ddos_size].window_start = time(NULL);
    ddos_table[ddos_size].blocked = 0;

    return &ddos_table[ddos_size++];
}

void trigger_ddos_block(ddos_entry_t *e, const char *type)
{
    if (e->blocked)
        return;

    e->blocked = 1;

    char warn[256];
    snprintf(warn, sizeof(warn),
             "DDoS ATTACK DETECTED | TYPE=%s | SOURCE IP=%s | ACTION=BLOCKED",
             type, e->ip);

    printf("\n%s\n", warn);
    log_event(warn);

    block_ip(e->ip);
    send_ddos_email_alert(e->ip, type);
}

void detect_ddos(const char *ip, int protocol, const u_char *packet)
{
    ddos_entry_t *e = get_ddos_entry(ip);
    if (!e || e->blocked)
        return;

    time_t now = time(NULL);

    if (difftime(now, e->window_start) >= DDOS_WINDOW)
    {
        e->syn_count = 0;
        e->udp_count = 0;
        e->icmp_count = 0;
        e->total_packets = 0;
        e->window_start = now;
    }

    e->total_packets++;

    if (protocol == IPPROTO_TCP)
    {
        struct tcphdr *tcp = (struct tcphdr *)packet;

        if (tcp->syn && !tcp->ack)
            e->syn_count++;

        if (e->syn_count >= SYN_THRESHOLD &&
            e->syn_count > e->total_packets * 0.7)
        {

            trigger_ddos_block(e, "TCP SYN FLOOD");
        }
    }
    else if (protocol == IPPROTO_UDP)
    {
        e->udp_count++;
        if (e->udp_count >= UDP_THRESHOLD)
        {

            trigger_ddos_block(e, "UDP FLOOD");
        }
    }
    else if (protocol == IPPROTO_ICMP)
    {
        struct icmphdr *icmp = (struct icmphdr *)packet;
        if (icmp->type == ICMP_ECHO)
            e->icmp_count++;

        if (e->icmp_count >= ICMP_THRESHOLD)
        {

            trigger_ddos_block(e, "ICMP FLOOD");
        }
    }

    if (e->total_packets >= PPS_THRESHOLD)
    {

        trigger_ddos_block(e, "GENERIC PPS FLOOD");
    }

    char buf[128];
    snprintf(buf, sizeof(buf),
             "%s SYN=%d TOTAL=%d", e->ip, e->syn_count, e->total_packets);

    printf("[DDOS] %s\n", buf);
    log_raw("DDOS", buf);
}

/* ================= Packet Handler ================= */
void packet_handler(u_char *a, const struct pcap_pkthdr *h, const u_char *p)
{
    struct ether_header *eth = (struct ether_header *)p;

    /* ================= ARP ================= */
    if (ntohs(eth->ether_type) == ETHERTYPE_ARP)
    {
        struct ether_arp *arp = (struct ether_arp *)(p + sizeof(*eth));
        char ip[16], mac[18], tip[16], tmac[18];

        snprintf(ip, sizeof(ip), "%d.%d.%d.%d",
                 arp->arp_spa[0], arp->arp_spa[1],
                 arp->arp_spa[2], arp->arp_spa[3]);

        snprintf(mac, sizeof(mac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
                 arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);

        if (is_ip_blocked(ip))
            return;

        snprintf(tip, sizeof(tip), "%d.%d.%d.%d",
                 arp->arp_tpa[0], arp->arp_tpa[1],
                 arp->arp_tpa[2], arp->arp_tpa[3]);

        snprintf(tmac, sizeof(tmac), "%02x:%02x:%02x:%02x:%02x:%02x",
                 arp->arp_tha[0], arp->arp_tha[1], arp->arp_tha[2],
                 arp->arp_tha[3], arp->arp_tha[4], arp->arp_tha[5]);

        char buf[256];
        snprintf(buf, sizeof(buf),
                 "%s (%s) -> %s (%s)", ip, mac, tip, tmac);

        printf("[ARP] %s\n", buf);
        log_raw("ARP", buf);

        log_packet(ip, mac, tip, tmac);
        detect_arp(ip, mac);
        return;
    }

    /* ================= IP / DDoS ================= */
    if (ntohs(eth->ether_type) == ETHERTYPE_IP)
    {
        struct iphdr *ip_hdr = (struct iphdr *)(p + sizeof(*eth));
        char src_ip[16];

        snprintf(src_ip, sizeof(src_ip), "%d.%d.%d.%d",
                 ((unsigned char *)&ip_hdr->saddr)[0],
                 ((unsigned char *)&ip_hdr->saddr)[1],
                 ((unsigned char *)&ip_hdr->saddr)[2],
                 ((unsigned char *)&ip_hdr->saddr)[3]);

        if (is_ip_blocked(src_ip))
            return;

        detect_ddos(src_ip, ip_hdr->protocol,
                    p + sizeof(struct ether_header) + (ip_hdr->ihl * 4));
    }
}

/* ================= Main ================= */
int main(int argc, char *argv[])
{
    if (getuid() != 0)
    {
        printf("Run NetShield as root.\n");
        return 1;
    }

    signal(SIGINT, cleanup);
    signal(SIGTERM, cleanup);
    signal(SIGQUIT, cleanup);
    signal(SIGTSTP, cleanup); // Ctrl + Z

    load_env();
    curl_global_init(CURL_GLOBAL_ALL);

    if (argc < 2)
    {
        print_help(argv[0]);
        return 0;
    }

    if (!strcmp(argv[1], "-v"))
    {
        print_version();
        return 0;
    }

    if (!strcmp(argv[1], "-h"))
    {
        print_help(argv[0]);
        return 0;
    }

    if (!strcmp(argv[1], "-l"))
    {
        list_interfaces();
        return 0;
    }

    if (!strcmp(argv[1], "-i") && argc == 3)
    {
        char errbuf[PCAP_ERRBUF_SIZE];
        pcap_handle = pcap_open_live(argv[2], BUFSIZ, 1, 1000, errbuf);
        if (!pcap_handle)
        {
            printf("pcap error: %s\n", errbuf);
            return 1;
        }

        struct bpf_program fp;
        pcap_compile(pcap_handle, &fp, "arp or ip", 0, PCAP_NETMASK_UNKNOWN);
        pcap_setfilter(pcap_handle, &fp);

        print_version();
        log_event("NetShield started");
        pcap_loop(pcap_handle, -1, packet_handler, NULL);
    }

    print_help(argv[0]);
    return 0;
}
