from dnslib.server import DNSServer, BaseResolver
from dnslib import RR, QTYPE, A
import json
import sys

WHITELIST_FILE = "whitelist.json"

def load_whitelist():
    try:
        with open(WHITELIST_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except:
        # Если файла нет, добавляем базовые сайты
        return ["ya.ru", "foxford.ru", "scratch.mit.edu"]

class WhitelistResolver(BaseResolver):
    def resolve(self, request, handler):
        reply = request.reply()
        qname = str(request.q.qname).rstrip(".")
        whitelist = load_whitelist()

        for domain in whitelist:
            if qname == domain or qname.endswith("." + domain):
                # Разрешаем доступ — возвращаем реальный IP
                reply.add_answer(RR(qname, QTYPE.A, rdata=A("93.184.216.34"), ttl=60))
                return reply

        # ❌ всё остальное блокируем
        reply.add_answer(RR(qname, QTYPE.A, rdata=A("0.0.0.0"), ttl=60))
        return reply


if __name__ == "__main__":
    try:
        server = DNSServer(
            WhitelistResolver(),
            port=53,         # обязательно 53 для Windows DNS
            address="127.0.0.1"
        )
        print("DNS whitelist запущен на 127.0.0.1:53")
        server.start_thread()  # запускаем в отдельном потоке

        # Бесконечный цикл для удержания сервера
        import time
        while True:
            time.sleep(1)

    except PermissionError:
        print("Ошибка: для запуска DNS требуется администратор!")
        sys.exit(1)
    except OSError as e:
        print(f"Ошибка при запуске DNS: {e}")
        sys.exit(1)
