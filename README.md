# parental-control-dns

Для работы родительского контроля потребуется Python 3.11, также необходимо прописать эти команды в командной строке или Powershell:

pip install dnslib      # Для работы DNS-сервера

pip install psutil      # Для управления процессами

netsh interface ip set dns "Ethernet" static 127.0.0.1

netsh advfirewall firewall add rule name="Block External DNS" dir=out action=block protocol=UDP remoteport=53

netsh advfirewall firewall add rule name="Block External DNS" dir=out action=block protocol=UDP remoteport=53


ВАЖНО ЗАПУСКАТЬ parental_control.py ОТ ИМЕНИ АДМИНИСТРАТОРА, ИНАЧЕ ПРОГРАММА НЕ БУДЕТ РАБОТАТЬ!!!
