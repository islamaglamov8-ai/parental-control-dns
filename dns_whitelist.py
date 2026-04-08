import dnslib.server
from dnslib import RR, QTYPE, A, AAAA, RCODE
import dns.resolver
import json
import sys
import os
import time
import ctypes
print("ADMIN", ctypes.windll.shell32.IsUserAnAdmin())

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
WHITELIST_FILE = os.path.join(BASE_DIR, "whitelist.json")

# Явно используем внешний DNS, а не системный resolver,
# чтобы не уйти в рекурсию после переключения системы на 127.0.0.1
UPSTREAM_DNS = ["1.1.1.1", "8.8.8.8"]


def load_whitelist():
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            data = json.load(f)
            if isinstance(data, list):
                return [str(x).strip().lower() for x in data if str(x).strip()]
    except Exception:
        pass

    return ["ya.ru", "foxford.ru", "scratch.mit.edu"]


def query_upstream(name: str, record_type: str):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = UPSTREAM_DNS
    resolver.timeout = 3
    resolver.lifetime = 3

    answers = resolver.resolve(name, record_type)
    return [r.to_text() for r in answers]


class WhitelistResolver(dnslib.server.BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".").lower()
        qtype = QTYPE[request.q.qtype]

        whitelist = load_whitelist()
        allowed = any(qname == domain or qname.endswith("." + domain) for domain in whitelist)

        if not allowed:
            # Для заблокированных доменов отвечаем "пусто"
            if qtype == "A":
                reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=30))
            elif qtype == "AAAA":
                reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA("::"), ttl=30))
            else:
                reply.header.rcode = RCODE.NXDOMAIN
            return reply

        try:
            if qtype == "A":
                ips = query_upstream(qname, "A")
                if not ips:
                    reply.header.rcode = RCODE.NXDOMAIN
                    return reply

                for ip in ips:
                    reply.add_answer(RR(qname, QTYPE.A, rdata=A(ip), ttl=60))
                return reply

            if qtype == "AAAA":
                try:
                    ips6 = query_upstream(qname, "AAAA")
                    if not ips6:
                        reply.header.rcode = RCODE.NXDOMAIN
                        return reply

                    for ip6 in ips6:
                        reply.add_answer(RR(qname, QTYPE.AAAA, rdata=AAAA(ip6), ttl=60))
                except Exception:
                    reply.header.rcode = RCODE.NXDOMAIN
                return reply

            # Остальные типы записей не обслуживаем
            reply.header.rcode = RCODE.NXDOMAIN
            return reply

        except Exception:
            reply.header.rcode = RCODE.SERVFAIL
            return reply


if __name__ == "__main__":
    try:
        udp_server = dnslib.server.DNSServer(
            WhitelistResolver(),
            port=53,
            address="127.0.0.1",
            tcp=False
        )
        tcp_server = dnslib.server.DNSServer(
            WhitelistResolver(),
            port=53,
            address="127.0.0.1",
            tcp=True
        )

        udp_server.start_thread()
        tcp_server.start_thread()

        print("DNS whitelist запущен на 127.0.0.1:53 (UDP/TCP)")

        while True:
            time.sleep(1)

    except PermissionError:
        print("Ошибка: для запуска DNS требуется администратор!")
        sys.exit(1)
    except OSError as e:
        print(f"Ошибка при запуске DNS: {e}")
        sys.exit(1)