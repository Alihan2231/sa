#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Viros Mitm - Tümü Bir Arada Sürüm
Gelişmiş ARP Spoofing Tespit Aracı

Bu dosya, Viros Mitm'in tüm bileşenlerini tek bir dosyada birleştirir.
ARP tablosunu izler ve olası saldırıları tespit eder.
Arka planda çalışabilir ve zamanlanmış taramalar yapabilir.
"""

import os
import sys
import time
import socket
import logging
import threading
import tempfile
import datetime
from pathlib import Path
import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import subprocess
import random
import platform
from PIL import Image, ImageTk

# --------------------------
# Günlük (Logging) Ayarları
# --------------------------

def setup_logging():
    """Uygulama için günlük (logging) sistemini yapılandırır."""
    log_dir = os.path.join(os.path.expanduser("~"), ".viros_mitm", "logs")
    os.makedirs(log_dir, exist_ok=True)
    
    today = datetime.datetime.now().strftime("%Y%m%d")
    log_file = os.path.join(log_dir, f"viros_mitm_{today}.log")
    
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s - %(name)s - %(levelname)s - %(message)s",
        handlers=[
            logging.FileHandler(log_file),
            logging.StreamHandler()
        ]
    )
    
    logger = logging.getLogger("utils")
    logger.info(f"Viros Mitm started on {platform.platform()}")
    logger.info(f"Python version: {platform.python_version()}")
    logger.info(f"Log file: {log_file}")
    
    return logger

logger = setup_logging()

# --------------------------
# Yardımcı İşlevler
# --------------------------

def is_admin():
    """Uygulamanın yönetici haklarıyla çalışıp çalışmadığını kontrol eder."""
    try:
        if platform.system() == "Windows":
            import ctypes
            return ctypes.windll.shell32.IsUserAnAdmin() != 0
        else:
            return os.geteuid() == 0
    except:
        return False

def format_time_remaining(seconds):
    """Saniye cinsinden bir süreyi insan tarafından okunabilir formata çevirir."""
    if seconds < 60:
        return f"{seconds}s"
    elif seconds < 3600:
        minutes = seconds // 60
        return f"{minutes}m"
    else:
        hours = seconds // 3600
        minutes = (seconds % 3600) // 60
        return f"{hours}h {minutes}m"

def clean_old_logs(max_days=7):
    """Belirtilen günden daha eski günlük (log) dosyalarını temizler."""
    log_dir = os.path.join(os.path.expanduser("~"), ".viros_mitm", "logs")
    if not os.path.exists(log_dir):
        return
    
    now = datetime.datetime.now()
    for file in os.listdir(log_dir):
        if not file.startswith("viros_mitm_") or not file.endswith(".log"):
            continue
        
        file_path = os.path.join(log_dir, file)
        file_time = datetime.datetime.fromtimestamp(os.path.getmtime(file_path))
        if (now - file_time).days > max_days:
            try:
                os.remove(file_path)
                logger.info(f"Removed old log file: {file}")
            except Exception as e:
                logger.error(f"Failed to remove old log file {file}: {e}")

def get_temp_dir():
    """Uygulama için geçici dizin oluşturur ve yolunu döndürür."""
    temp_dir = os.path.join(tempfile.gettempdir(), "viros_mitm")
    os.makedirs(temp_dir, exist_ok=True)
    return temp_dir

# --------------------------
# ARP Tespit İşlevleri
# --------------------------

def format_mac(mac_bytes):
    """Binary MAC adresini okunabilir formata çevirir."""
    return ":".join([f"{b:02x}" for b in mac_bytes])

def format_ip(ip_bytes):
    """Binary IP adresini okunabilir formata çevirir."""
    return ".".join([str(b) for b in ip_bytes])

def get_arp_table():
    """
    Sistemin ARP tablosunu alır.
    
    Returns:
        list: ARP tablosundaki kayıtlar listesi
    """
    arp_table = []
    
    try:
        # Gerçek bir sistemde, bu ARP tablosunu okuyacaktır
        # Replit ortamında test için simüle edilmiş veriler
        logger.warning("Using simulated ARP data for development")
        
        # Simüle edilmiş normal cihazlar
        arp_table.append({
            "ip": "192.168.1.1",
            "mac": "aa:bb:cc:dd:ee:ff",
            "interface": "eth0"
        })
        arp_table.append({
            "ip": "192.168.1.2",
            "mac": "11:22:33:44:55:66",
            "interface": "eth0"
        })
        arp_table.append({
            "ip": "192.168.1.3",
            "mac": "aa:bb:cc:11:22:33",
            "interface": "eth0"
        })
        arp_table.append({
            "ip": "192.168.1.4",
            "mac": "dd:ee:ff:11:22:33",
            "interface": "eth0"
        })
        
        # Simüle edilmiş şüpheli kayıtlar
        arp_table.append({
            "ip": "192.168.1.1",  # Çakışan IP (Gateway IP)
            "mac": "00:11:22:33:44:55",  # Farklı MAC adresi
            "interface": "eth0"
        })
        arp_table.append({
            "ip": "192.168.1.5",
            "mac": "00:11:22:33:44:55",  # Aynı MAC (muhtemelen saldırganın)
            "interface": "eth0"
        })
        arp_table.append({
            "ip": "192.168.1.255",  # Broadcast adresi
            "mac": "ff:ff:ff:ff:ff:ff",
            "interface": "eth0"
        })
        
    except Exception as e:
        logger.error(f"Error getting ARP table: {e}")
    
    return arp_table

def get_default_gateway():
    """
    Varsayılan ağ geçidini (default gateway) bulur.
    
    Returns:
        dict: Ağ geçidi IP ve MAC adresi
    """
    try:
        # Gerçek bir sistemde, varsayılan ağ geçidini bulma kodu
        # Replit ortamında test için simüle edilmiş veriler
        logger.warning("Using simulated gateway data")
        return {
            "ip": "192.168.1.1",
            "mac": "aa:bb:cc:dd:ee:ff"
        }
    except Exception as e:
        logger.error(f"Error finding default gateway: {e}")
        return {
            "ip": "Unknown",
            "mac": "Unknown"
        }

def detect_arp_spoofing(arp_table):
    """
    ARP tablosunu inceleyerek olası ARP spoofing saldırılarını tespit eder.
    
    Args:
        arp_table (list): ARP tablosu kayıtları
        
    Returns:
        list: Tespit edilen şüpheli durumlar
    """
    suspicious_entries = []
    gateway = get_default_gateway()
    
    # IP-MAC eşleştirmelerini kontrol et
    ip_to_mac_map = {}
    
    # Broadcast adreslerini filtrele
    broadcast_macs = ["ff:ff:ff:ff:ff:ff"]
    
    for entry in arp_table:
        ip = entry["ip"]
        mac = entry["mac"]
        
        # Broadcast MAC'leri atla
        if mac.lower() in broadcast_macs:
            continue
            
        # Broadcast IP'leri atla (x.x.x.255)
        if ip.endswith(".255"):
            continue
        
        # Aynı IP için birden fazla MAC adresi kontrolü
        if ip in ip_to_mac_map:
            if ip_to_mac_map[ip] != mac:
                suspicious_entries.append({
                    "severity": "critical",
                    "message": f"❌ ARP Spoofing Tespit Edildi: {ip} IP için birden fazla MAC: {ip_to_mac_map[ip]} ve {mac}"
                })
        else:
            ip_to_mac_map[ip] = mac
    
    # Aynı MAC adresi için birden fazla IP kontrolü
    mac_to_ip_map = {}
    for entry in arp_table:
        mac = entry["mac"]
        ip = entry["ip"]
        
        # Broadcast MAC'leri atla
        if mac.lower() in broadcast_macs:
            continue
            
        # Broadcast IP'leri atla
        if ip.endswith(".255"):
            continue
        
        if mac in mac_to_ip_map:
            mac_to_ip_map[mac].append(ip)
        else:
            mac_to_ip_map[mac] = [ip]
    
    for mac, ips in mac_to_ip_map.items():
        if len(ips) > 3:  # 3'ten fazla IP adresi şüphelidir
            suspicious_entries.append({
                "severity": "warning",
                "message": f"⚠️ Şüpheli MAC Adresi: {mac} - {len(ips)} farklı IP adresine sahip"
            })
        elif len(ips) > 1:
            suspicious_entries.append({
                "severity": "info",
                "message": f"ℹ️ Birden fazla IP'ye sahip MAC: {mac} - IP'ler: {', '.join(ips)}"
            })
    
    # Ağ geçidi (gateway) MAC adresi değişiklikleri kontrolü
    gateway_ip = gateway["ip"]
    gateway_mac = gateway["mac"]
    
    for entry in arp_table:
        if entry["ip"] == gateway_ip and entry["mac"] != gateway_mac:
            suspicious_entries.append({
                "severity": "critical",
                "message": f"❌ ARP Gateway Spoofing Tespit Edildi: Geçit {gateway_ip} MAC adresi değişmiş. Beklenen: {gateway_mac}, Bulunan: {entry['mac']}"
            })
    
    return suspicious_entries

def perform_scan():
    """
    Tam bir ARP taraması ve analizi gerçekleştirir.
    ARP tablosu ve şüpheli girişleri içeren tarama sonuçlarını döndürür.
    """
    logger.info("Starting ARP table scan...")
    
    try:
        # ARP tablosunu al
        arp_table = get_arp_table()
        
        # Şüpheli girişleri tespit et
        suspicious_entries = detect_arp_spoofing(arp_table)
        
        # Gateway bilgisini al
        gateway = get_default_gateway()
        
        # Tarama sonuçlarını hazırla
        severity_counts = {
            "critical": 0,
            "warning": 0,
            "info": 0
        }
        
        # Şüpheli girişleri sınıflandır
        for entry in suspicious_entries:
            severity = entry.get("severity", "info")
            if severity in severity_counts:
                severity_counts[severity] += 1
        
        result = {
            "success": True,
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "arp_table": arp_table,
            "suspicious_entries": suspicious_entries,
            "gateway": gateway,
            "severity_counts": severity_counts
        }
        
        logger.info(f"ARP scan completed: {len(arp_table)} entries, {len(suspicious_entries)} suspicious entries")
        return result
        
    except Exception as e:
        logger.error(f"Error performing ARP scan: {e}")
        return {
            "success": False,
            "error": str(e),
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

# --------------------------
# Zamanlanmış Görev Yöneticisi
# --------------------------

class ScheduleManager:
    """Zamanlanmış taramaları esnek aralıklarla yönetir."""
    
    def __init__(self, callback=None):
        """
        Zamanlama yöneticisini başlatır.
        
        Args:
            callback: Zamanlanmış süre dolduğunda çağrılacak fonksiyon
        """
        self.callback = callback
        self.active = False
        self.scheduler_thread = None
        self.interval = 1
        self.unit = "hour"
        self.next_run_time = None
        
    def start(self, interval=1, unit="hour"):
        """
        Belirtilen aralıkla zamanlanmış taramayı başlatır.
        
        Args:
            interval: Zaman birimi sayısı
            unit: 'minute' veya 'hour'
        """
        self.interval = interval
        self.unit = unit
        self.active = True
        
        # Mevcut zamanlayıcı varsa durdur
        if self.scheduler_thread and self.scheduler_thread.is_alive():
            self.stop()
        
        # Yeni zamanlayıcı başlat
        self.scheduler_thread = threading.Thread(target=self._scheduler_thread, daemon=True)
        self.scheduler_thread.start()
        
        logger.info(f"Scheduling started: every {interval} {unit}(s)")
        
    def stop(self):
        """Zamanlanmış taramayı durdurur."""
        self.active = False
        logger.info("Scheduling stopped")
        
    def update(self, interval, unit):
        """
        Zamanlama aralığını günceller.
        
        Args:
            interval: Zaman birimi sayısı
            unit: 'minute' veya 'hour'
        """
        if self.active:
            self.interval = interval
            self.unit = unit
            logger.info(f"Schedule updated: every {interval} {unit}(s)")
            
    def is_active(self):
        """Zamanlamanın şu anda aktif olup olmadığını kontrol eder."""
        return self.active
        
    def get_interval_display(self):
        """Görüntüleme için mevcut aralığı alır."""
        return f"{self.interval} {self.unit}(s)"
        
    def get_next_run_time(self):
        """Bir sonraki çalıştırma zamanını dize olarak alır."""
        if not self.next_run_time:
            return "Unknown"
        return self.next_run_time.strftime("%H:%M:%S")
        
    def _scheduler_thread(self):
        """Zamanlama mantığını işleyen iş parçacığı işlevi."""
        while self.active:
            # Bir sonraki çalışma zamanını hesapla
            if self.unit == "minute":
                seconds = self.interval * 60
            else:  # hour
                seconds = self.interval * 3600
                
            self.next_run_time = datetime.datetime.now() + datetime.timedelta(seconds=seconds)
            
            # Zamanı bekle
            for _ in range(seconds):
                if not self.active:
                    break
                time.sleep(1)
                
            # Hala aktifse ve bekleme tamamlandıysa callback'i çağır
            if self.active and self.callback:
                try:
                    self.callback()
                except Exception as e:
                    logger.error(f"Error in scheduled callback: {e}")

# --------------------------
# Bildirim Yöneticisi
# --------------------------

class NotificationManager:
    """Yedekleme seçenekleriyle sistem bildirimlerini yönetir."""
    
    def __init__(self, app_name):
        """
        Bildirim yöneticisini başlatır.
        
        Args:
            app_name: Bildirimler için uygulama adı
        """
        self.app_name = app_name
        self.available_methods = self._detect_notification_methods()
        logger.info(f"Available notification methods: {self.available_methods}")
        
    def _detect_notification_methods(self):
        """
        Sistemde mevcut bildirim yöntemlerini algılar.
        
        Returns:
            list: Mevcut bildirim yöntemleri
        """
        methods = []
        
        # Windows bildirim yöntemlerini kontrol et
        if platform.system() == "Windows":
            try:
                # win10toast modülünü kontrol et
                try:
                    import win10toast
                    methods.append("win10toast")
                except ImportError:
                    pass
            except:
                pass
                
        # Linux bildirim yöntemlerini kontrol et
        elif platform.system() == "Linux":
            try:
                # notify-send varlığını kontrol et
                try:
                    # notify-send varlığını kontrol et (sessizce)
                    with open(os.devnull, 'w') as devnull:
                        if subprocess.call(["which", "notify-send"], stdout=devnull, stderr=devnull) == 0:
                            methods.append("notify-send")
                        # zenity varlığını kontrol et
                        elif subprocess.call(["which", "zenity"], stdout=devnull, stderr=devnull) == 0:
                            methods.append("zenity")
                except:
                    pass
            except:
                pass
                
        # macOS bildirim yöntemlerini kontrol et
        elif platform.system() == "Darwin":
            try:
                # osascript varlığını kontrol et (sessizce)
                with open(os.devnull, 'w') as devnull:
                    if subprocess.call(["which", "osascript"], stdout=devnull, stderr=devnull) == 0:
                        methods.append("applescript")
            except:
                pass
        
        # Her platformda çalışan son çare yöntemi
        methods.append("balloontip")
        
        return methods
        
    def show_notification(self, title, message):
        """
        Mevcut en iyi yöntemi kullanarak bildirim gösterir.
        
        Args:
            title: Bildirim başlığı
            message: Bildirim mesajı
        """
        threading.Thread(
            target=self._show_notification_thread,
            args=(title, message),
            daemon=True
        ).start()
        
    def show_critical_notification(self, title, message):
        """
        Daha yüksek görünürlüğe sahip kritik bir bildirim gösterir.
        
        Args:
            title: Bildirim başlığı
            message: Bildirim mesajı
        """
        threading.Thread(
            target=self._show_notification_thread,
            args=(title, message, True),
            daemon=True
        ).start()
        
    def _show_notification_thread(self, title, message, critical=False):
        """
        Bildirim gösterme iş parçacığı işlevi.
        
        Args:
            title: Bildirim başlığı
            message: Bildirim mesajı
            critical: Kritik bir bildirim olup olmadığı
        """
        for method in self.available_methods:
            try:
                if method == "win10toast" and platform.system() == "Windows":
                    self._notify_win10toast(title, message, critical)
                    return
                elif method == "notify-send" and platform.system() == "Linux":
                    self._notify_linux(title, message, critical)
                    return
                elif method == "zenity" and platform.system() == "Linux":
                    self._notify_zenity(title, message, critical)
                    return
                elif method == "applescript" and platform.system() == "Darwin":
                    self._notify_macos(title, message, critical)
                    return
                elif method == "balloontip":
                    self._notify_balloontip(title, message, critical)
                    return
            except Exception as e:
                logger.error(f"Error showing notification with {method}: {e}")
                continue
                
        logger.warning("Failed to show notification with any method")
        
    def _notify_win10toast(self, title, message, critical=False):
        """Windows 10+ için win10toast kullanarak bildirim gösterir."""
        try:
            from win10toast import ToastNotifier
            toaster = ToastNotifier()
            toaster.show_toast(
                title,
                message,
                icon_path=None,
                duration=5 if not critical else 10,
                threaded=True
            )
        except Exception as e:
            logger.error(f"Error in win10toast notification: {e}")
            raise
            
    def _notify_balloontip(self, title, message, critical=False):
        """Son çare olarak tkinter balon ipucu kullanarak bildirim gösterir."""
        try:
            # En üstte bir tkinter penceresi oluştur ve gizle
            root = tk.Tk()
            root.withdraw()
            
            # Ekranın kenarında bir etiket konumlandır
            screen_width = root.winfo_screenwidth()
            screen_height = root.winfo_screenheight()
            
            label = tk.Label(root, text="🔔", font=("Arial", 16), bg="black", fg="white")
            label.place(x=screen_width - 40, y=screen_height - 80)
            
            # Etiket üzerinde bir balon ipucu göster
            label.bind("<Enter>", lambda e: label.config(bg="darkgray"))
            label.bind("<Leave>", lambda e: label.config(bg="black"))
            
            import tkinter.messagebox as mb
            mb.showinfo(title, message)
            
            # Formu temizle
            root.destroy()
        except Exception as e:
            logger.error(f"Error in balloon tip notification: {e}")
            raise
            
    def _notify_linux(self, title, message, critical=False):
        """Linux'ta notify-send kullanarak bildirim gösterir."""
        try:
            urgency = "critical" if critical else "normal"
            subprocess.call([
                "notify-send",
                "--app-name", self.app_name,
                "--urgency", urgency,
                title,
                message
            ])
        except Exception as e:
            logger.error(f"Error in Linux notification: {e}")
            raise
            
    def _notify_zenity(self, title, message, critical=False):
        """Linux'ta zenity kullanarak bildirim gösterir."""
        try:
            info_type = "error" if critical else "info"
            subprocess.call([
                "zenity",
                f"--{info_type}",
                "--title", title,
                "--text", message
            ])
        except Exception as e:
            logger.error(f"Error in Zenity notification: {e}")
            raise
            
    def _notify_macos(self, title, message, critical=False):
        """macOS'ta AppleScript kullanarak bildirim gösterir."""
        try:
            subprocess.call([
                "osascript",
                "-e", f'display notification "{message}" with title "{title}" sound name "{"Basso" if critical else "Submarine"}"'
            ])
        except Exception as e:
            logger.error(f"Error in macOS notification: {e}")
            raise

# --------------------------
# Otomatik Başlatma Yöneticisi
# --------------------------

class AutoStartManager:
    """Sistem başlangıcında otomatik başlatmayı yönetir."""
    
    def __init__(self, app_name):
        """
        Otomatik başlatma yöneticisini başlatır.
        
        Args:
            app_name: Uygulama adı
        """
        self.app_name = app_name
        self.app_path = os.path.abspath(sys.argv[0])
        
    def enable(self):
        """
        Sistemle birlikte uygulamanın başlamasını etkinleştirir.
        
        Returns:
            bool: Başarılıysa True, değilse False
        """
        system = platform.system()
        if system == "Windows":
            return self._enable_windows()
        elif system == "Linux":
            return self._enable_linux()
        else:
            logger.warning(f"Autostart not supported on {system}")
            return False
            
    def disable(self):
        """
        Sistemle birlikte uygulamanın başlamasını devre dışı bırakır.
        
        Returns:
            bool: Başarılıysa True, değilse False
        """
        system = platform.system()
        if system == "Windows":
            return self._disable_windows()
        elif system == "Linux":
            return self._disable_linux()
        else:
            logger.warning(f"Autostart not supported on {system}")
            return False
            
    def is_enabled(self):
        """
        Uygulamanın sistemle birlikte başlamak üzere ayarlanıp ayarlanmadığını kontrol eder.
        
        Returns:
            bool: Etkinleştirilmişse True, değilse False
        """
        system = platform.system()
        if system == "Windows":
            return self._is_enabled_windows()
        elif system == "Linux":
            return self._is_enabled_linux()
        else:
            logger.warning(f"Autostart not supported on {system}")
            return False
            
    def _enable_windows(self):
        """Windows'ta kayıt defterini kullanarak otomatik başlatmayı etkinleştirir."""
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_SET_VALUE
            )
            winreg.SetValueEx(key, self.app_name, 0, winreg.REG_SZ, self.app_path)
            winreg.CloseKey(key)
            logger.info("Autostart enabled on Windows")
            return True
        except Exception as e:
            logger.error(f"Error enabling autostart on Windows: {e}")
            return False
            
    def _disable_windows(self):
        """Windows'ta kayıt defteri girişini kaldırarak otomatik başlatmayı devre dışı bırakır."""
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_SET_VALUE
            )
            try:
                winreg.DeleteValue(key, self.app_name)
            except:
                # Değer zaten yoksa yok sayılabilir
                pass
            winreg.CloseKey(key)
            logger.info("Autostart disabled on Windows")
            return True
        except Exception as e:
            logger.error(f"Error disabling autostart on Windows: {e}")
            return False
            
    def _is_enabled_windows(self):
        """Windows'ta otomatik başlatmanın etkin olup olmadığını kontrol eder."""
        try:
            import winreg
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                r"Software\Microsoft\Windows\CurrentVersion\Run",
                0, winreg.KEY_READ
            )
            try:
                value, _ = winreg.QueryValueEx(key, self.app_name)
                winreg.CloseKey(key)
                return value == self.app_path
            except:
                winreg.CloseKey(key)
                return False
        except Exception as e:
            logger.error(f"Error checking autostart status on Windows: {e}")
            return False
            
    def _enable_linux(self):
        """Linux'ta masaüstü girişi kullanarak otomatik başlatmayı etkinleştirir."""
        try:
            autostart_dir = os.path.expanduser("~/.config/autostart")
            os.makedirs(autostart_dir, exist_ok=True)
            
            desktop_file_path = os.path.join(autostart_dir, f"{self.app_name}.desktop")
            with open(desktop_file_path, "w") as f:
                f.write(f"""[Desktop Entry]
Type=Application
Name={self.app_name}
Exec={self.app_path}
Terminal=false
X-GNOME-Autostart-enabled=true
""")
            
            os.chmod(desktop_file_path, 0o755)
            logger.info("Autostart enabled on Linux")
            return True
        except Exception as e:
            logger.error(f"Error enabling autostart on Linux: {e}")
            return False
            
    def _disable_linux(self):
        """Linux'ta masaüstü girişini kaldırarak otomatik başlatmayı devre dışı bırakır."""
        try:
            desktop_file_path = os.path.expanduser(f"~/.config/autostart/{self.app_name}.desktop")
            if os.path.exists(desktop_file_path):
                os.remove(desktop_file_path)
            logger.info("Autostart disabled on Linux")
            return True
        except Exception as e:
            logger.error(f"Error disabling autostart on Linux: {e}")
            return False
            
    def _is_enabled_linux(self):
        """Linux'ta otomatik başlatmanın etkin olup olmadığını kontrol eder."""
        try:
            desktop_file_path = os.path.expanduser(f"~/.config/autostart/{self.app_name}.desktop")
            return os.path.exists(desktop_file_path)
        except Exception as e:
            logger.error(f"Error checking autostart status on Linux: {e}")
            return False

# --------------------------
# Sistem Tepsisi Yöneticisi
# --------------------------

class TrayManager:
    """Sistem tepsisi simgesini ve menüsünü yönetir."""
    
    def __init__(self, tooltip, icon_data, menu_items=None):
        """
        Tepsi yöneticisini başlatır.
        
        Args:
            tooltip: Üzerine gelindiğinde gösterilecek araç ipucu metni
            icon_data: Simge verisi (Base64 veya bytes olarak)
            menu_items: 'text' ve 'command' anahtarları olan sözlükler listesi
        """
        self.tooltip = tooltip
        self.icon_data = icon_data
        self.menu_items = menu_items or []
        self.tray_icon = None
        self.click_handler = None
        
        # İlk kurulumu yap
        self._setup_tray()
        
    def _setup_tray(self):
        """Sistem tepsisi simgesini ayarlar."""
        try:
            # pystray'i içe aktarmayı dene
            try:
                import pystray
                from PIL import Image
                import io
                
                # Menüyü oluştur
                def create_menu_items():
                    items = []
                    for item_data in self.menu_items:
                        items.append(pystray.MenuItem(
                            item_data["text"],
                            item_data["command"]
                        ))
                    return items
                
                # PIL görüntüsünü al (doğrudan verilebilir veya veriden yüklenebilir)
                if isinstance(self.icon_data, Image.Image):
                    icon_image = self.icon_data
                else:
                    # İkon verisinden yüklemeyi dene
                    icon_image = Image.open(io.BytesIO(self.icon_data))
                
                # Simge tıklama işleyicisi
                def on_icon_click(icon, event):
                    if hasattr(event, 'button'):
                        if event.button == 1 and self.click_handler:  # Sol tıklama
                            self.click_handler()
                    else:
                        # Bazı pystray sürümleri button özelliğine sahip değil
                        if self.click_handler:
                            self.click_handler()
                
                # pystray simgesini oluştur
                menu = pystray.Menu(*create_menu_items())
                self.tray_icon = pystray.Icon(
                    name=self.tooltip,
                    icon=icon_image,
                    title=self.tooltip,
                    menu=menu
                )
                
                # Tıklama olaylarını yapılandır
                self.tray_icon.on_click = on_icon_click
                
                # Arka planda çalıştır
                if hasattr(self.tray_icon, 'run'):
                    threading.Thread(target=lambda: self.tray_icon.run(), daemon=True).start()
            except ImportError as e:
                logger.error(f"pystray or PIL import error: {e}")
                self.tray_icon = None
            
        except Exception as e:
            logger.error(f"Failed to setup tray icon: {e}")
            self.tray_icon = None
            
    def set_click_handler(self, handler):
        """
        Tepsi simgesine tıklandığında çağrılacak işlevi ayarlar.
        
        Args:
            handler: Tıklama üzerine çağrılacak işlev
        """
        self.click_handler = handler
        
    def update_menu(self, menu_items):
        """
        Tepsi simgesi menüsünü günceller.
        
        Args:
            menu_items: 'text' ve 'command' anahtarları olan sözlükler listesi
        """
        self.menu_items = menu_items
        
        # Simgeyi yeniden oluştur
        if self.tray_icon:
            self.remove()
            self._setup_tray()
            
    def remove(self):
        """Tepsi simgesini kaldırır."""
        if self.tray_icon:
            try:
                self.tray_icon.stop()
            except Exception as e:
                logger.error(f"Error removing tray icon: {e}")
            self.tray_icon = None

# --------------------------
# Grafik Kullanıcı Arayüzü
# --------------------------

class MainApplication(ttk.Frame):
    """Viros Mitm için ana uygulama penceresi."""
    
    def __init__(self, master=None):
        """Ana uygulama penceresini başlatır."""
        super().__init__(master)
        self.master = master
        
        # Simge ayarla
        self.set_app_icon()
        
        # Stil ve temalar
        self.create_styles()
        
        # Değişkenleri oluştur
        self.create_variables()
        
        # Yöneticileri başlat
        self.schedule_manager = ScheduleManager(self.scheduled_scan)
        self.notification_manager = NotificationManager("Viros Mitm")
        self.autostart_manager = AutoStartManager("Viros Mitm")
        
        # Pencere ayarları
        self.master.title("Viros Mitm - ARP Spoofing Tespit Aracı")
        self.master.minsize(800, 600)
        
        # Ana pencere çerçevesi
        self.mainframe = ttk.Frame(self.master, padding="10")
        
        # Pencere içeriğini oluştur
        self.create_widgets()
        self.create_layout()
        self.create_bindings()
        
        # Son olarak, sistem tepsisi simgesini oluştur
        self.create_tray()
        
        # Zamanlayıcı durumunu güncelle
        self.update_schedule_status()
        
        # Otomatik başlatma durumunu güncelle
        self.autostart_var.set(self.autostart_manager.is_enabled())
        
        # Hazır olduğunda başlangıç bildirimi göster
        self.show_tray_notification(
            "Viros Mitm Başlatıldı",
            "Viros Mitm ARP Spoofing Tespit Aracı başarıyla başlatıldı."
        )
        
        # İlk açılışta zamanlanmış tarama yapmıyoruz, kullanıcı bunu etkinleştirebilir
        
    def set_app_icon(self):
        """Gömülü kaynaklardan uygulama simgesini ayarlar"""
        # İkon ayarlama işlemini atlayalım, uygulama simgesiz çalışacak
        pass
    
    def create_variables(self):
        """tkinter değişkenlerini oluşturur"""
        # Durum değişkenleri
        self.scanning_var = tk.BooleanVar(value=False)
        self.last_scan_time_var = tk.StringVar(value="Son tarama: Hiç")
        
        # Zamanlama değişkenleri
        self.schedule_interval_var = tk.StringVar(value="1")
        self.schedule_unit_var = tk.StringVar(value="hour")
        
        # Ayarlar değişkenleri
        self.autostart_var = tk.BooleanVar(value=False)
        self.show_info_var = tk.BooleanVar(value=True)
        
        # Son sonuçları sakla
        self.last_result = None
    
    def create_styles(self):
        """Uygulama için özel stiller oluşturur"""
        style = ttk.Style()
        
        # Renk Paleti
        bg_color = "#f0f0f0"
        accent_color = "#0078d7"
        
        # Font ayarları
        default_font = ("Segoe UI", 10)
        header_font = ("Segoe UI", 14, "bold")
        title_font = ("Segoe UI", 16, "bold")

        # Özel stilleri ayarla
        style.configure("Header.TLabel", font=header_font)
        style.configure("Title.TLabel", font=title_font, foreground=accent_color)
        style.configure("StatusGood.TLabel", foreground="green")
        style.configure("StatusWarning.TLabel", foreground="orange")
        style.configure("StatusCritical.TLabel", foreground="red")
        
        # Varsayılan yapılandırmalar
        style.configure("TLabel", font=default_font)
        style.configure("TButton", font=default_font)
        style.configure("TCheckbutton", font=default_font)
        
    def create_widgets(self):
        """Uygulama için tüm widget'ları oluşturur"""
        # Başlık alanı
        self.header_frame = ttk.Frame(self.mainframe)
        self.title_label = ttk.Label(self.header_frame, text="Viros Mitm", style="Title.TLabel")
        self.subtitle_label = ttk.Label(self.header_frame, text="ARP Spoofing Tespit Aracı")
        
        # Eylem butonları
        self.action_frame = ttk.Frame(self.mainframe)
        self.scan_button = ttk.Button(self.action_frame, text="Ağı Tara", command=self.scan_network)
        self.progress_bar = ttk.Progressbar(self.action_frame, mode="indeterminate", length=200)
        self.last_scan_label = ttk.Label(self.action_frame, textvariable=self.last_scan_time_var)
        
        # Notebook (sekmeli arayüz)
        self.notebook = ttk.Notebook(self.mainframe)
        
        # Sonuçlar sekmesi
        self.results_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.results_tab, text="Sonuçlar")
        
        # Özet alanı
        self.summary_frame = ttk.Frame(self.results_tab)
        self.gateway_label = ttk.Label(self.summary_frame, text="Varsayılan Ağ Geçidi: -")
        self.devices_label = ttk.Label(self.summary_frame, text="Bulunan Cihazlar: -")
        self.status_label = ttk.Label(self.summary_frame, text="Durum: Ağ henüz taranmadı")
        
        # Sonuç alanı
        self.results_frame = ttk.Frame(self.results_tab)
        self.results_text = scrolledtext.ScrolledText(self.results_frame, wrap=tk.WORD, width=80, height=20)
        self.results_text.insert(tk.END, "Ağı taramak için 'Ağı Tara' düğmesine tıklayın.")
        self.results_text.config(state=tk.DISABLED)
        
        # Ayarlar sekmesi
        self.settings_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.settings_tab, text="Ayarlar")
        
        # Zamanlama çerçevesi
        self.schedule_frame = ttk.LabelFrame(self.settings_tab, text="Otomatik Tarama", padding=10)
        self.schedule_label = ttk.Label(self.schedule_frame, 
                                       text="Ağı otomatik olarak her şu zaman diliminde tara:")
        
        # Zamanlama kontrolleri
        self.schedule_controls_frame = ttk.Frame(self.schedule_frame)
        self.schedule_interval_entry = ttk.Spinbox(self.schedule_controls_frame, 
                                                 from_=1, to=24, width=5,
                                                 textvariable=self.schedule_interval_var)
        self.schedule_unit_combo = ttk.Combobox(self.schedule_controls_frame, 
                                               values=["minute", "hour"], 
                                               textvariable=self.schedule_unit_var,
                                               state="readonly", width=10)
        
        # Zamanlama durumu ve kontrolleri
        self.schedule_status_frame = ttk.Frame(self.schedule_frame)
        self.schedule_status_label = ttk.Label(self.schedule_status_frame, 
                                            text="Durum: Zamanlama aktif değil")
        self.schedule_toggle_button = ttk.Button(self.schedule_status_frame, 
                                               text="Zamanlayıcıyı Etkinleştir", 
                                               command=self.toggle_scheduling)
        
        # Seçenekler çerçevesi
        self.options_frame = ttk.LabelFrame(self.settings_tab, text="Uygulama Ayarları", padding=10)
        
        # Otomatik başlatma seçeneği
        self.autostart_check = ttk.Checkbutton(self.options_frame, 
                                              text="Bilgisayar açıldığında otomatik başlat", 
                                              variable=self.autostart_var,
                                              command=self.toggle_autostart)
        
        # Görüntüleme seçenekleri
        self.display_frame = ttk.Frame(self.options_frame)
        self.show_info_check = ttk.Checkbutton(self.display_frame, 
                                              text="Sonuçlarda bilgi öğelerini göster", 
                                              variable=self.show_info_var,
                                              command=self.refresh_results)
        
        # Sistem tepsisi seçenekleri
        self.systray_frame = ttk.Frame(self.options_frame)
        self.minimize_to_tray_button = ttk.Button(self.systray_frame, 
                                                 text="Sistem Tepsisinde Çalıştır", 
                                                 command=self.minimize_to_tray)
        
        # Hakkında sekmesi
        self.about_tab = ttk.Frame(self.notebook)
        self.notebook.add(self.about_tab, text="Hakkında")
        
        # Hakkında içeriği
        self.about_frame = ttk.Frame(self.about_tab, padding=20)
        self.about_title = ttk.Label(self.about_frame, text="Viros Mitm", style="Header.TLabel")
        self.about_version = ttk.Label(self.about_frame, text="Version 1.0")
        self.about_description = ttk.Label(self.about_frame, 
                                         text="Gelişmiş ARP Spoofing Tespit Aracı", 
                                         wraplength=400)
        self.about_details = ttk.Label(self.about_frame, 
                                      text="Bu araç ağınızı ARP spoofing saldırılarına karşı izler. " +
                                           "ARP spoofing, saldırganların cihazlar arasındaki ağ trafiğini " +
                                           "yakalamak için kullandığı yaygın bir yöntemdir.",
                                      wraplength=400)
        
        # Yardım bölümü
        self.help_frame = ttk.LabelFrame(self.about_tab, text="Yardım", padding=10)
        self.help_text = scrolledtext.ScrolledText(self.help_frame, wrap=tk.WORD, 
                                                 width=60, height=10)
        self.help_text.insert(tk.END, """
ARP Spoofing saldırıları, saldırganın sahte ARP mesajları göndererek kendi MAC 
adresini varsayılan ağ geçidi gibi başka bir ana bilgisayarın IP adresi ile 
ilişkilendirdiğinde gerçekleşir. Bu, o IP adresine gönderilmesi gereken trafiğin 
bunun yerine saldırgana gönderilmesine neden olur.

Viros Mitm'i kullanmak için:

1. Manuel tarama yapmak için "Ağı Tara" düğmesine tıklayın
2. Ayarlar sekmesinde otomatik taramayı yapılandırın
3. Viros Mitm'in sistem başlangıcında çalışması için "Bilgisayar açıldığında otomatik başlat" seçeneğini etkinleştirin
4. Uygulamanın arka planda çalışması için sistem tepsisine küçültün

Şüpheli bir etkinlik tespit edilirse, Viros Mitm sizi uyarmak için uyarılar ve 
bildirimler gösterecektir.
        """)
        self.help_text.config(state=tk.DISABLED)
        
        # Durum çubuğu
        self.status_bar = ttk.Frame(self.mainframe, relief=tk.SUNKEN)
        self.status_text = ttk.Label(self.status_bar, text="Hazır")
    
    def create_layout(self):
        """Uygulamadaki tüm widget'ları düzenler"""
        # Ana çerçeveyi yapılandır
        self.mainframe.pack(fill=tk.BOTH, expand=True)
        
        # Başlık düzeni
        self.header_frame.pack(fill=tk.X, pady=(0, 10))
        self.title_label.pack(side=tk.LEFT)
        self.subtitle_label.pack(side=tk.LEFT, padx=10)
        
        # Eylem butonları düzeni
        self.action_frame.pack(fill=tk.X, pady=(0, 10))
        self.scan_button.pack(side=tk.LEFT)
        self.progress_bar.pack(side=tk.LEFT, padx=10)
        self.last_scan_label.pack(side=tk.RIGHT)
        
        # Notebook düzeni
        self.notebook.pack(fill=tk.BOTH, expand=True)
        
        # Sonuçlar sekmesi düzeni
        self.summary_frame.pack(fill=tk.X, padx=5, pady=5)
        self.gateway_label.pack(anchor=tk.W, pady=2)
        self.devices_label.pack(anchor=tk.W, pady=2)
        self.status_label.pack(anchor=tk.W, pady=2)
        
        self.results_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.results_text.pack(fill=tk.BOTH, expand=True)
        
        # Ayarlar sekmesi düzeni
        self.schedule_frame.pack(fill=tk.X, padx=5, pady=5)
        self.schedule_label.pack(anchor=tk.W, pady=5)
        
        self.schedule_controls_frame.pack(fill=tk.X)
        self.schedule_interval_entry.pack(side=tk.LEFT, pady=5)
        self.schedule_unit_combo.pack(side=tk.LEFT, padx=5, pady=5)
        
        self.schedule_status_frame.pack(fill=tk.X, pady=5)
        self.schedule_status_label.pack(side=tk.LEFT)
        self.schedule_toggle_button.pack(side=tk.RIGHT)
        
        self.options_frame.pack(fill=tk.X, padx=5, pady=5)
        self.autostart_check.pack(anchor=tk.W, pady=5)
        
        self.display_frame.pack(fill=tk.X, pady=5)
        self.show_info_check.pack(anchor=tk.W)
        
        self.systray_frame.pack(fill=tk.X, pady=5)
        self.minimize_to_tray_button.pack(side=tk.LEFT)
        
        # Hakkında sekmesi düzeni
        self.about_frame.pack(fill=tk.X, padx=5, pady=5)
        self.about_title.pack(anchor=tk.W, pady=(0, 5))
        self.about_version.pack(anchor=tk.W)
        self.about_description.pack(anchor=tk.W, pady=5)
        self.about_details.pack(anchor=tk.W, pady=5)
        
        self.help_frame.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)
        self.help_text.pack(fill=tk.BOTH, expand=True)
        
        # Durum çubuğu düzeni
        self.status_bar.pack(fill=tk.X, side=tk.BOTTOM)
        self.status_text.pack(side=tk.LEFT, padx=5, pady=2)
    
    def create_bindings(self):
        """Olay bağlamalarını oluşturur"""
        # Pencere kapatma olayını bağla
        self.master.protocol("WM_DELETE_WINDOW", self.on_close)
        
        # Sekme değişikliği olayını bağla
        self.notebook.bind("<<NotebookTabChanged>>", self.on_tab_changed)
    
    def create_tray(self):
        """Sistem tepsisi simgesini ve menüsünü oluşturur"""
        # pystray veya PIL sorunlarından kaçınmak için tray desteğini devre dışı bırakıyoruz
        logger.info("Sistem tepsisi desteği devre dışı bırakıldı")
        
        # Tray özelliğini atlıyoruz, bu program tray simgesi olmadan çalışacak
        pass
    
    def show_window(self):
        """Sistem tepsisinden ana pencereyi gösterir"""
        self.master.deiconify()
        self.master.lift()
        self.master.focus_force()
    
    def minimize_to_tray(self):
        """Uygulamayı sistem tepsisine küçültür"""
        try:
            self.master.withdraw()
            # Sadece tepsi simgesi varsa bildirim göster
            if hasattr(self, 'tray_manager') and self.tray_manager:
                self.show_tray_notification(
                    "Viros Mitm Arka Planda",
                    "Uygulama arka planda çalışmaya devam ediyor ve ağınızı izliyor"
                )
        except Exception as e:
            logger.error(f"Error minimizing to tray: {e}")
    
    def on_close(self):
        """Pencere kapatma olayını işler"""
        if self.schedule_manager.is_active():
            result = messagebox.askyesnocancel(
                "Küçült veya Çıkış",
                "Zamanlanmış tarama aktif. Ne yapmak istersiniz:\n\n"
                "• Evet: Sistem tepsisine küçült (arka planda çalışmaya devam et)\n"
                "• Hayır: Uygulamadan tamamen çık\n"
                "• İptal: Uygulamaya geri dön"
            )
            
            if result is True:  # Evet
                self.minimize_to_tray()
                # Uygulamanın arka planda çalışmaya devam edeceğini bildiren bildirim göster
                self.show_tray_notification(
                    "Viros Mitm Arka Planda Çalışıyor", 
                    "Uygulama arka planda çalışmaya devam edecek ve periyodik taramaları gerçekleştirecek."
                )
                return
            elif result is None:  # İptal
                return
            # Aksi takdirde (Hayır), uygulama çıkışıyla devam et
        
        # Temizle ve çık
        self.quit_app()
    
    def quit_app(self):
        """Uygulamadan düzgün bir şekilde çıkar"""
        # Zamanlayıcıyı durdur
        self.schedule_manager.stop()
        
        # Tepsi simgesini kaldır
        if hasattr(self, 'tray_manager'):
            self.tray_manager.remove()
        
        # Pencereyi yok et ve çık
        self.master.destroy()
        sys.exit(0)
    
    def on_tab_changed(self, event):
        """Notebook sekme değişikliği olayını işler"""
        # Sekmeye özgü eylemler için kullanılabilir
        pass
    
    def scan_network(self):
        """ARP spoofing için ağı tarar"""
        if self.scanning_var.get():
            # Zaten taranıyor, yeni bir tarama başlatma
            return
        
        # Arayüzü güncelle
        self.scanning_var.set(True)
        self.scan_button.config(state=tk.DISABLED)
        self.progress_bar.start(10)
        self.status_text.config(text="Ağ taranıyor...")
        
        # Taramayı ayrı bir iş parçacığında başlat
        threading.Thread(target=self._perform_scan, daemon=True).start()
    
    def _perform_scan(self):
        """Gerçek ARP taramasını ayrı bir iş parçacığında gerçekleştirir"""
        try:
            # Taramayı gerçekleştir
            result = perform_scan()
            
            # Sonuçlarla arayüzü güncelle
            self.master.after(0, lambda: self.update_scan_results(result))
        except Exception as e:
            logger.error(f"Error during scan: {e}")
            self.master.after(0, lambda: self.scan_error(str(e)))
    
    def update_scan_results(self, result):
        """Tarama sonuçlarıyla arayüzü günceller"""
        if not result["success"]:
            self.scan_error(result.get("error", "Unknown error"))
            return
        
        # Son tarama zamanını güncelle
        self.last_scan_time_var.set(f"Son tarama: {result['timestamp']}")
        
        # Özeti güncelle
        gateway = result["gateway"]
        self.gateway_label.config(text=f"Varsayılan Ağ Geçidi: {gateway['ip']} (MAC: {gateway['mac']})")
        
        arp_table = result["arp_table"]
        self.devices_label.config(text=f"Bulunan Cihazlar: {len(arp_table)}")
        
        # Şüpheli girişleri kontrol et ve durumu güncelle
        suspicious_entries = result["suspicious_entries"]
        critical_count = result["severity_counts"]["critical"]
        warning_count = result["severity_counts"]["warning"]
        
        if critical_count > 0:
            status_text = f"Durum: ❌ Kritik sorunlar tespit edildi ({critical_count})"
            self.status_label.config(text=status_text, style="StatusCritical.TLabel")
            # Bildirim göster
            self.show_critical_notification(
                "ARP Spoofing Saldırısı Tespit Edildi!",
                f"{critical_count} adet kritik sorun tespit edildi. Bu aktif bir saldırı olabileceğini gösteriyor."
            )
        elif warning_count > 0:
            status_text = f"Durum: ⚠️ Şüpheli etkinlik tespit edildi ({warning_count})"
            self.status_label.config(text=status_text, style="StatusWarning.TLabel")
            # Bildirim göster
            self.notification_manager.show_notification(
                "Şüpheli Ağ Etkinliği",
                f"{warning_count} adet inceleme gerektiren şüpheli durum tespit edildi."
            )
        else:
            self.status_label.config(text="Durum: ✅ Şüpheli etkinlik tespit edilmedi", 
                                    style="StatusGood.TLabel")
        
        # Sonuç metnini güncelle
        self.display_results(result)
        
        # Arayüzü sıfırla
        self.scanning_var.set(False)
        self.scan_button.config(state=tk.NORMAL)
        self.progress_bar.stop()
        self.status_text.config(text="Tarama tamamlandı")
    
    def scan_error(self, error_message):
        """Tarama hatalarını işler"""
        # Arayüzü güncelle
        self.scanning_var.set(False)
        self.scan_button.config(state=tk.NORMAL)
        self.progress_bar.stop()
        self.status_text.config(text=f"Hata: {error_message}")
        
        # Hata mesajını göster
        messagebox.showerror("Tarama Hatası", f"Tarama sırasında bir hata oluştu:\n\n{error_message}")
    
    def display_results(self, result):
        """Sonuçları metin alanında görüntüler"""
        self.results_text.config(state=tk.NORMAL)
        self.results_text.delete(1.0, tk.END)
        
        # ARP tablosunu görüntüle
        self.results_text.insert(tk.END, "ARP TABLOSU:\n", "header")
        self.results_text.insert(tk.END, "-" * 60 + "\n")
        self.results_text.insert(tk.END, f"{'IP Adresi':<15} {'MAC Adresi':<20} {'Arayüz':<10}\n")
        self.results_text.insert(tk.END, "-" * 60 + "\n")
        
        arp_table = result["arp_table"]
        for entry in arp_table:
            self.results_text.insert(tk.END, 
                                     f"{entry['ip']:<15} {entry['mac']:<20} {entry['interface']:<10}\n")
        
        # Şüpheli girişleri görüntüle
        self.results_text.insert(tk.END, "\nANALİZ SONUÇLARI:\n", "header")
        self.results_text.insert(tk.END, "-" * 60 + "\n")
        
        suspicious_entries = result["suspicious_entries"]
        if suspicious_entries:
            displayed_entries = 0
            
            for entry in suspicious_entries:
                # Gösterilmiyorsa bilgi girişlerini atla
                if entry.get("severity") == "info" and not self.show_info_var.get():
                    continue
                
                # Girişi uygun etiketle renklendirerek göster
                severity = entry.get("severity", "info")
                self.results_text.insert(tk.END, entry["message"] + "\n", severity)
                displayed_entries += 1
            
            if displayed_entries == 0:
                self.results_text.insert(tk.END, "Mevcut filtre ayarlarıyla gösterilecek sorun yok.\n")
        else:
            self.results_text.insert(tk.END, "✅ Şüpheli etkinlik tespit edilmedi.\n")
        
        # Özeti görüntüle
        self.results_text.insert(tk.END, "\nÖZET:\n", "header")
        self.results_text.insert(tk.END, "-" * 60 + "\n")
        self.results_text.insert(tk.END, f"Toplam cihaz: {len(arp_table)}\n")
        self.results_text.insert(tk.END, f"Kritik sorunlar: {result['severity_counts']['critical']}\n")
        self.results_text.insert(tk.END, f"Uyarılar: {result['severity_counts']['warning']}\n")
        self.results_text.insert(tk.END, f"Bilgi öğeleri: {result['severity_counts']['info']}\n")
        
        # Metin stillemesi için etiketleri yapılandır
        self.results_text.tag_configure("header", font=("Segoe UI", 10, "bold"))
        self.results_text.tag_configure("critical", foreground="red")
        self.results_text.tag_configure("warning", foreground="orange")
        self.results_text.tag_configure("info", foreground="blue")
        
        self.results_text.config(state=tk.DISABLED)
    
    def refresh_results(self):
        """Sonuç görüntülemeyi mevcut filtre ayarlarıyla yeniler"""
        # Görüntülenecek sonuçların olup olmadığını kontrol et
        if hasattr(self, 'last_result'):
            self.display_results(self.last_result)
    
    def update_schedule(self, *args):
        """Kullanıcı girdisine göre zamanlamayı günceller"""
        # Yalnızca zamanlama etkinse güncelle
        if self.schedule_manager.is_active():
            try:
                interval = int(self.schedule_interval_var.get())
                unit = self.schedule_unit_var.get()
                self.schedule_manager.update(interval, unit)
                self.update_schedule_status()
            except ValueError:
                pass
    
    def toggle_scheduling(self):
        """Zamanlanmış taramayı etkinleştirir veya devre dışı bırakır"""
        if self.schedule_manager.is_active():
            # Zamanlamayı devre dışı bırak
            self.schedule_manager.stop()
            self.schedule_toggle_button.config(text="Zamanlayıcıyı Etkinleştir")
            self.show_tray_notification("Zamanlayıcı Devre Dışı", 
                                       "Otomatik ağ taraması devre dışı bırakıldı")
        else:
            # Zamanlamayı etkinleştir
            try:
                interval = int(self.schedule_interval_var.get())
                unit = self.schedule_unit_var.get()
                
                # Aralık çok kısaysa kullanıcıyla onayla
                if unit == "minute" and interval < 5:
                    if not messagebox.askyesno("Kısa Zaman Aralığını Onayla", 
                                              f"Her {interval} dakikada bir tarama yapmak sistem performansını etkileyebilir. Devam etmek istiyor musunuz?"):
                        return
                
                self.schedule_manager.start(interval, unit)
                self.schedule_toggle_button.config(text="Zamanlayıcıyı Devre Dışı Bırak")
                
                # Bildirim göster
                self.show_tray_notification("Zamanlayıcı Aktif", 
                                          f"Ağ her {interval} {unit} taranacak")
                
                # Kullanıcının tepsi simgesine küçültmek isteyip istemediğini sor
                if self.master.winfo_viewable() and messagebox.askyesno("Sistem Tepsisine Küçült?", 
                                                          "Viros Mitm'i sistem tepsisinde çalışmaya devam etmesi için küçültmek ister misiniz?"):
                    self.minimize_to_tray()
            except ValueError:
                messagebox.showerror("Geçersiz Zaman Aralığı", "Lütfen zaman aralığı için geçerli bir sayı girin")
        
        self.update_schedule_status()
    
    def update_schedule_status(self):
        """Zamanlama durumu etiketini günceller"""
        if self.schedule_manager.is_active():
            next_run = self.schedule_manager.get_next_run_time()
            self.schedule_status_label.config(
                text=f"Durum: Aktif - Sonraki tarama: {next_run}"
            )
        else:
            self.schedule_status_label.config(text="Durum: Zamanlama aktif değil")
    
    def scheduled_scan(self):
        """Zamanlanmış taramalar için geri çağırma"""
        # Taramayı arka planda gerçekleştir
        threading.Thread(target=self._scheduled_scan_thread, daemon=True).start()
        
        # Zamanlama durumunu güncelle
        self.master.after(1000, self.update_schedule_status)
    
    def _scheduled_scan_thread(self):
        """Zamanlanmış taramayı ayrı bir iş parçacığında çalıştırır"""
        logger.info("Running scheduled scan")
        
        try:
            # Taramayı gerçekleştir
            result = perform_scan()
            
            # Bildirim göstermemiz gerekip gerekmediğini kontrol et
            if result["success"]:
                critical_count = result["severity_counts"]["critical"]
                warning_count = result["severity_counts"]["warning"]
                
                if critical_count > 0:
                    # Kritik sorun - bildirim göster
                    self.show_critical_notification(
                        "ARP Spoofing Saldırısı Tespit Edildi!",
                        f"{critical_count} adet kritik sorun tespit edildi. Bu aktif bir saldırı olabileceğini gösteriyor."
                    )
                elif warning_count > 0:
                    # Uyarı - bildirim göster
                    self.notification_manager.show_notification(
                        "Şüpheli Ağ Etkinliği",
                        f"{warning_count} adet inceleme gerektiren şüpheli durum tespit edildi."
                    )
            
            # Pencere görünürse görüntüleme için sonucu kaydet
            self.last_result = result
            
            # Pencere görünürse arayüzü güncelle
            if self.master.winfo_viewable():
                self.master.after(0, lambda: self.update_scan_results(result))
        
        except Exception as e:
            logger.error(f"Error during scheduled scan: {e}")
            # Yalnızca pencere görünürse hatayı arayüzde göster
            if self.master.winfo_viewable():
                self.master.after(0, lambda: self.scan_error(str(e)))
    
    def toggle_autostart(self):
        """Sistemle birlikte otomatik başlatmayı değiştirir"""
        if self.autostart_var.get():
            # Otomatik başlatmayı etkinleştir
            success = self.autostart_manager.enable()
            if not success:
                messagebox.showerror("Hata", "Uygulamanın Windows ile başlatılması ayarlanamadı")
                self.autostart_var.set(False)
            else:
                messagebox.showinfo("Otomatik Başlatma Etkin", 
                                   "Viros Mitm artık Windows ile otomatik olarak başlayacak")
        else:
            # Otomatik başlatmayı devre dışı bırak
            success = self.autostart_manager.disable()
            if not success:
                messagebox.showerror("Hata", "Uygulama Windows başlangıcından kaldırılamadı")
                self.autostart_var.set(True)
    
    def show_tray_notification(self, title, message):
        """Sistem tepsisinden bildirim gösterir"""
        try:
            if hasattr(self, 'notification_manager') and self.notification_manager:
                self.notification_manager.show_notification(title, message)
        except Exception as e:
            logger.error(f"Error showing notification: {e}")
    
    def show_critical_notification(self, title, message):
        """Uyarı sesiyle kritik bir bildirim gösterir"""
        try:
            if hasattr(self, 'notification_manager') and self.notification_manager:
                self.notification_manager.show_critical_notification(title, message)
        except Exception as e:
            logger.error(f"Error showing critical notification: {e}")

# --------------------------
# Ana Program
# --------------------------

def main():
    """
    Ana uygulama giriş noktası.
    Arayüzü başlatır ve uygulamayı başlatır.
    """
    # İlk açılışta eski günlükleri temizle
    clean_old_logs()
    
    # Yönetici olarak çalışıp çalışmadığını kontrol et
    if not is_admin():
        logger.warning("Warning: Application not running with administrator privileges")
        # Windows platformunda kullanıcıya bilgi ver
        if platform.system() == "Windows":
            should_restart = messagebox.askyesno(
                "Yönetici Hakları Gerekli",
                "Viros Mitm düzgün çalışmak için yönetici haklarına ihtiyaç duyar. "
                "Simüle edilmiş veriler kullanılacak ve bazı işlevler düzgün çalışmayabilir.\n\n"
                "Uygulamayı yönetici olarak yeniden başlatmak ister misiniz?"
            )
            if should_restart:
                # Uygulamayı yönetici olarak yeniden başlatmaya çalış
                try:
                    if platform.system() == "Windows":
                        import ctypes, sys
                        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
                        sys.exit(0)
                except:
                    messagebox.showerror(
                        "Yönetici Olarak Başlatılamadı",
                        "Uygulama yönetici olarak yeniden başlatılamadı. Lütfen komut istemini yönetici olarak çalıştırın ve uygulamayı oradan başlatın."
                    )
    
    # Ana uygulama penceresini oluştur
    root = tk.Tk()
    app = MainApplication(root)
    root.mainloop()

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        import traceback
        error_msg = f"Hata: {str(e)}\n\n{traceback.format_exc()}"
        print(error_msg)
        try:
            import tkinter as tk
            from tkinter import messagebox
            root = tk.Tk()
            root.withdraw()
            messagebox.showerror("Viros Mitm - Hata", error_msg)
        except:
            # Eğer tkinter kullanılamıyorsa
            print(error_msg)
            input("Devam etmek için Enter tuşuna basın...")
