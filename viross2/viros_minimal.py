#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Viros Mitm - Minimal Sürüm
ARP Spoofing tespiti için minimalist araç
Bu basit sürüm, herhangi bir dış bağımlılık olmadan çalışmak üzere tasarlanmıştır
"""

import os
import sys
import time
import platform
import datetime
import subprocess
import threading
import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox

# ----- Basit Günlük (Logging) -----
def log_message(message, level="INFO"):
    """Basit bir günlük fonksiyonu"""
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"{timestamp} - {level} - {message}")

# ----- ARP Tespit İşlevleri -----
def get_arp_table():
    """Sistemin ARP tablosunu alır (simüle edilmiş veriler)."""
    log_message("Simüle edilmiş ARP verileri kullanılıyor")
    
    # Simüle edilmiş normal cihazlar
    arp_table = [
        {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "interface": "eth0"},
        {"ip": "192.168.1.2", "mac": "11:22:33:44:55:66", "interface": "eth0"},
        {"ip": "192.168.1.3", "mac": "aa:bb:cc:11:22:33", "interface": "eth0"},
        {"ip": "192.168.1.4", "mac": "dd:ee:ff:11:22:33", "interface": "eth0"},
        # Simüle edilmiş şüpheli kayıtlar
        {"ip": "192.168.1.1", "mac": "00:11:22:33:44:55", "interface": "eth0"}, # Çakışan IP
        {"ip": "192.168.1.5", "mac": "00:11:22:33:44:55", "interface": "eth0"}, # Aynı MAC
        {"ip": "192.168.1.255", "mac": "ff:ff:ff:ff:ff:ff", "interface": "eth0"} # Broadcast
    ]
    
    return arp_table

def get_default_gateway():
    """Varsayılan ağ geçidini döndürür (simüle edilmiş)."""
    return {
        "ip": "192.168.1.1",
        "mac": "aa:bb:cc:dd:ee:ff"
    }

def detect_arp_spoofing(arp_table):
    """ARP tablosunu inceleyerek olası ARP spoofing saldırılarını tespit eder."""
    suspicious_entries = []
    gateway = get_default_gateway()
    
    # IP-MAC eşleştirmelerini kontrol et
    ip_to_mac_map = {}
    
    # Broadcast filtreleme
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
        
        # Aynı IP için birden fazla MAC kontrolü
        if ip in ip_to_mac_map:
            if ip_to_mac_map[ip] != mac:
                suspicious_entries.append({
                    "severity": "critical",
                    "message": f"❌ ARP Spoofing Tespit Edildi: {ip} IP için birden fazla MAC: {ip_to_mac_map[ip]} ve {mac}"
                })
        else:
            ip_to_mac_map[ip] = mac
    
    # Aynı MAC için birden fazla IP kontrolü
    mac_to_ip_map = {}
    for entry in arp_table:
        mac = entry["mac"]
        ip = entry["ip"]
        
        # Broadcast atla
        if mac.lower() in broadcast_macs or ip.endswith(".255"):
            continue
        
        if mac in mac_to_ip_map:
            mac_to_ip_map[mac].append(ip)
        else:
            mac_to_ip_map[mac] = [ip]
    
    for mac, ips in mac_to_ip_map.items():
        if len(ips) > 3:  # 3'ten fazla IP şüpheli
            suspicious_entries.append({
                "severity": "warning",
                "message": f"⚠️ Şüpheli MAC Adresi: {mac} - {len(ips)} farklı IP adresine sahip"
            })
        elif len(ips) > 1:
            suspicious_entries.append({
                "severity": "info",
                "message": f"ℹ️ Birden fazla IP'ye sahip MAC: {mac} - IP'ler: {', '.join(ips)}"
            })
    
    # Gateway MAC değişiklik kontrolü
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
    """Tam ARP taraması ve analizi gerçekleştirir."""
    log_message("ARP taraması başlıyor...")
    
    try:
        # ARP tablosunu al ve şüpheli girişleri tespit et
        arp_table = get_arp_table()
        suspicious_entries = detect_arp_spoofing(arp_table)
        gateway = get_default_gateway()
        
        # İstatistikleri hesapla
        severity_counts = {"critical": 0, "warning": 0, "info": 0}
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
        
        log_message(f"ARP taraması tamamlandı: {len(arp_table)} kayıt, {len(suspicious_entries)} şüpheli")
        return result
        
    except Exception as e:
        log_message(f"ARP taraması sırasında hata: {e}", "ERROR")
        return {
            "success": False,
            "error": str(e),
            "timestamp": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

# ----- Ana Uygulama Sınıfı -----
class SimpleApp:
    """Basitleştirilmiş Viros Mitm uygulaması"""
    
    def __init__(self, master):
        """Ana pencereyi başlatır"""
        self.master = master
        master.title("Viros Mitm - Minimal Sürüm")
        master.minsize(700, 500)
        
        # Ana çerçeve
        self.mainframe = ttk.Frame(master, padding=10)
        self.mainframe.pack(fill=tk.BOTH, expand=True)
        
        # Başlık
        self.header_frame = ttk.Frame(self.mainframe)
        self.header_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.title_label = ttk.Label(
            self.header_frame, 
            text="Viros Mitm", 
            font=("Segoe UI", 16, "bold")
        )
        self.title_label.pack(side=tk.LEFT)
        
        self.subtitle_label = ttk.Label(
            self.header_frame, 
            text="ARP Spoofing Tespit Aracı", 
            font=("Segoe UI", 10)
        )
        self.subtitle_label.pack(side=tk.LEFT, padx=10)
        
        # Kontrol butonları
        self.control_frame = ttk.Frame(self.mainframe)
        self.control_frame.pack(fill=tk.X, pady=(0, 10))
        
        self.scan_button = ttk.Button(
            self.control_frame, 
            text="Ağı Tara",
            command=self.scan_network
        )
        self.scan_button.pack(side=tk.LEFT)
        
        self.progress_bar = ttk.Progressbar(
            self.control_frame, 
            mode="indeterminate", 
            length=200
        )
        self.progress_bar.pack(side=tk.LEFT, padx=10)
        
        self.status_label = ttk.Label(
            self.control_frame,
            text="Hazır"
        )
        self.status_label.pack(side=tk.LEFT, padx=10)
        
        # Sonuç alanı
        self.results_frame = ttk.LabelFrame(
            self.mainframe, 
            text="Tarama Sonuçları", 
            padding=10
        )
        self.results_frame.pack(fill=tk.BOTH, expand=True)
        
        self.results_text = scrolledtext.ScrolledText(
            self.results_frame, 
            wrap=tk.WORD, 
            width=80, 
            height=20
        )
        self.results_text.pack(fill=tk.BOTH, expand=True)
        self.results_text.insert(tk.END, "Ağı taramak için 'Ağı Tara' düğmesine tıklayın.")
        
        # Alt çubuk
        self.footer_frame = ttk.Frame(self.mainframe)
        self.footer_frame.pack(fill=tk.X, pady=(10, 0))
        
        self.copyright_label = ttk.Label(
            self.footer_frame,
            text="Viros Mitm v1.0 - Minimal Sürüm",
            font=("Segoe UI", 8)
        )
        self.copyright_label.pack(side=tk.RIGHT)
        
        # Hız değişkeni
        self.scanning = False
    
    def scan_network(self):
        """ARP spoofing için ağı tarar"""
        if self.scanning:
            return
            
        self.scanning = True
        self.scan_button.config(state=tk.DISABLED)
        self.status_label.config(text="Ağ taranıyor...")
        self.progress_bar.start(10)
        
        # Taramayı ayrı bir iş parçacığında gerçekleştir
        threading.Thread(target=self._perform_scan, daemon=True).start()
    
    def _perform_scan(self):
        """Gerçek ARP taramasını ayrı bir iş parçacığında gerçekleştirir"""
        try:
            # Taramayı gerçekleştir
            result = perform_scan()
            
            # Sonuçlarla arayüzü güncelle (güvenli bir şekilde)
            self.master.after(0, lambda: self._update_results(result))
        except Exception as e:
            # Hatayı göster
            self.master.after(0, lambda: self._show_error(str(e)))
    
    def _update_results(self, result):
        """Tarama sonuçlarıyla arayüzü günceller"""
        try:
            if not result["success"]:
                self._show_error(result.get("error", "Bilinmeyen hata"))
                return
                
            # Sonuç metnini temizle
            self.results_text.delete(1.0, tk.END)
            
            # Özet bilgileri görüntüle
            self.results_text.insert(tk.END, "TARAMA SONUÇLARI:\n", "header")
            self.results_text.insert(tk.END, "-" * 60 + "\n")
            self.results_text.insert(tk.END, f"Tarama zamanı: {result['timestamp']}\n")
            self.results_text.insert(tk.END, f"Varsayılan Ağ Geçidi: {result['gateway']['ip']} (MAC: {result['gateway']['mac']})\n")
            self.results_text.insert(tk.END, f"Bulunan cihaz sayısı: {len(result['arp_table'])}\n\n")
            
            # ARP tablosunu göster
            self.results_text.insert(tk.END, "ARP TABLOSU:\n", "header")
            self.results_text.insert(tk.END, "-" * 60 + "\n")
            self.results_text.insert(tk.END, f"{'IP Adresi':<15} {'MAC Adresi':<20} {'Arayüz':<10}\n")
            self.results_text.insert(tk.END, "-" * 60 + "\n")
            
            for entry in result["arp_table"]:
                self.results_text.insert(tk.END, 
                                      f"{entry['ip']:<15} {entry['mac']:<20} {entry['interface']:<10}\n")
            
            # Şüpheli girişleri göster
            self.results_text.insert(tk.END, "\nTESPİT EDİLEN ŞÜPHELİ DURUMLAR:\n", "header")
            self.results_text.insert(tk.END, "-" * 60 + "\n")
            
            suspicious_entries = result["suspicious_entries"]
            if suspicious_entries:
                for entry in suspicious_entries:
                    severity = entry.get("severity", "info")
                    
                    if severity == "critical":
                        tag = "critical"
                    elif severity == "warning":
                        tag = "warning"
                    else:
                        tag = "info"
                        
                    self.results_text.insert(tk.END, entry["message"] + "\n", tag)
            else:
                self.results_text.insert(tk.END, "✅ Şüpheli etkinlik tespit edilmedi.\n")
            
            # Özet göster
            self.results_text.insert(tk.END, "\nÖZET:\n", "header")
            self.results_text.insert(tk.END, "-" * 60 + "\n")
            self.results_text.insert(tk.END, f"Kritik sorunlar: {result['severity_counts']['critical']}\n")
            self.results_text.insert(tk.END, f"Uyarılar: {result['severity_counts']['warning']}\n")
            self.results_text.insert(tk.END, f"Bilgi öğeleri: {result['severity_counts']['info']}\n")
            
            # Etiketleri yapılandır
            self.results_text.tag_configure("header", font=("Segoe UI", 10, "bold"))
            self.results_text.tag_configure("critical", foreground="red")
            self.results_text.tag_configure("warning", foreground="orange")
            self.results_text.tag_configure("info", foreground="blue")
            
            # Arayüzü güncelle
            severity_counts = result["severity_counts"]
            if severity_counts["critical"] > 0:
                self.status_label.config(text=f"❌ Kritik sorunlar tespit edildi ({severity_counts['critical']})")
            elif severity_counts["warning"] > 0:
                self.status_label.config(text=f"⚠️ Uyarılar tespit edildi ({severity_counts['warning']})")
            else:
                self.status_label.config(text="✅ Şüpheli etkinlik tespit edilmedi")
                
        except Exception as e:
            self._show_error(f"Sonuçlar görüntülenirken hata oluştu: {e}")
        finally:
            # Arayüzü sıfırla
            self.scanning = False
            self.scan_button.config(state=tk.NORMAL)
            self.progress_bar.stop()
    
    def _show_error(self, error_message):
        """Hata mesajını gösterir"""
        self.scanning = False
        self.scan_button.config(state=tk.NORMAL)
        self.progress_bar.stop()
        self.status_label.config(text=f"Hata oluştu")
        
        messagebox.showerror("Hata", f"Tarama sırasında bir hata oluştu:\n\n{error_message}")

# ----- Ana Program -----
def main():
    """Ana program giriş noktası"""
    try:
        # Uygulama penceresini oluştur
        root = tk.Tk()
        app = SimpleApp(root)
        
        # Pencereyi merkeze yerleştir
        window_width = 800
        window_height = 600
        screen_width = root.winfo_screenwidth()
        screen_height = root.winfo_screenheight()
        center_x = int(screen_width/2 - window_width/2)
        center_y = int(screen_height/2 - window_height/2)
        root.geometry(f'{window_width}x{window_height}+{center_x}+{center_y}')
        
        # Pencere kapatma olayını işle
        root.protocol("WM_DELETE_WINDOW", root.destroy)
        
        # Uygulamayı başlat
        log_message("Viros Mitm başlatıldı")
        root.mainloop()
        
    except Exception as e:
        log_message(f"Uygulama başlatılırken hata: {e}", "ERROR")
        print(f"HATA: {e}")
        
        # Hata durumunda Windows'ta bir mesaj kutusu göster
        try:
            import ctypes
            ctypes.windll.user32.MessageBoxW(0, f"Uygulama başlatılırken hata oluştu:\n\n{e}", "Viros Mitm - Hata", 0)
        except:
            pass

if __name__ == "__main__":
    # Hata yakalama ile ana fonksiyonu çağır
    try:
        main()
    except Exception as e:
        print(f"Kritik hata: {e}")
        input("Devam etmek için Enter tuşuna basın...")
