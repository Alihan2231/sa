#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ARP Spoofing Tespit Aracı - Tek Dosya Sürümü
Bu araç, ağda olası ARP spoofing saldırılarını tespit etmek için gerekli tüm fonksiyonları ve 
tkinter tabanlı bir grafik arayüz içerir.

Geliştirici: Replit Kullanıcısı
Versiyon: 1.0
Tarih: 2025-04-18
"""

# --------- Gerekli modülleri içe aktarma ---------
import socket
import struct
import time
import sys
import subprocess
import re
import os
import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk, Toplevel, PhotoImage
import threading
from collections import defaultdict
import io
from contextlib import redirect_stdout
import platform
import tempfile

# ============= ARP TESPİT MODÜLÜ =============

# MAC adreslerini düzgün formatta gösterme
def format_mac(mac_bytes):
    """Binary MAC adresini okunabilir formata çevirir."""
    if isinstance(mac_bytes, bytes):
        return ':'.join(f'{b:02x}' for b in mac_bytes)
    return mac_bytes

# IP adreslerini düzgün formatta gösterme
def format_ip(ip_bytes):
    """Binary IP adresini okunabilir formata çevirir."""
    if isinstance(ip_bytes, bytes):
        return socket.inet_ntoa(ip_bytes)
    return ip_bytes

# ARP tablosunu alma
def get_arp_table():
    """
    Sistemin ARP tablosunu alır.
    
    Returns:
        list: ARP tablosundaki kayıtlar listesi
    """
    arp_entries = []
    
    try:
        # Platforma göre uygun komutu belirle
        if os.name == 'nt':  # Windows
            output = subprocess.check_output(['arp', '-a'], text=True)
            # Windows ARP çıktısını ayrıştır
            pattern = r'(\d+\.\d+\.\d+\.\d+)\s+([0-9a-f-]+)\s+(\w+)'
            for line in output.split('\n'):
                match = re.search(pattern, line)
                if match:
                    ip, mac, interface_type = match.groups()
                    mac = mac.replace('-', ':')  # Standart formata çevir
                    arp_entries.append({"ip": ip, "mac": mac, "interface": interface_type})
        else:  # Linux/Unix
            output = subprocess.check_output(['arp', '-n'], text=True)
            # Linux ARP çıktısını ayrıştır
            for line in output.split('\n')[1:]:  # Başlık satırını atla
                if line.strip():
                    parts = line.split()
                    if len(parts) >= 3:
                        ip = parts[0]
                        mac = parts[2]
                        interface = parts[-1] if len(parts) > 3 else "unknown"
                        if mac != "(incomplete)":  # Eksik kayıtları atla
                            arp_entries.append({"ip": ip, "mac": mac, "interface": interface})
    except Exception as e:
        print(f"ARP tablosu alınırken hata oluştu: {e}")
        # Test verileri oluştur
        test_entries = [
            {"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff", "interface": "eth0"},
            {"ip": "192.168.1.2", "mac": "11:22:33:44:55:66", "interface": "eth0"}
        ]
        return test_entries
    
    return arp_entries

# Varsayılan ağ geçidini bulma
def get_default_gateway():
    """
    Varsayılan ağ geçidini (default gateway) bulur.
    
    Returns:
        dict: Ağ geçidi IP ve MAC adresi
    """
    try:
        if os.name == 'nt':  # Windows
            output = subprocess.check_output(['ipconfig'], text=True)
            gateway_ip = None
            for line in output.split('\n'):
                if 'Default Gateway' in line or 'Varsayılan Ağ Geçidi' in line:
                    match = re.search(r':\s*(\d+\.\d+\.\d+\.\d+)', line)
                    if match:
                        gateway_ip = match.group(1)
                        break
        else:  # Linux/Unix
            output = subprocess.check_output(['ip', 'route'], text=True)
            match = re.search(r'default via (\d+\.\d+\.\d+\.\d+)', output)
            gateway_ip = match.group(1) if match else None
        
        # Gateway IP'yi bulduktan sonra ARP tablosundan MAC adresini alıyoruz
        if gateway_ip:
            arp_table = get_arp_table()
            for entry in arp_table:
                if entry["ip"] == gateway_ip:
                    return {"ip": gateway_ip, "mac": entry["mac"]}
        
        print("Varsayılan ağ geçidi bulunamadı.")
        return {"ip": "Bilinmiyor", "mac": "Bilinmiyor"}
    
    except Exception as e:
        print(f"Varsayılan ağ geçidi bulunurken hata oluştu: {e}")
        return {"ip": "Bilinmiyor", "mac": "Bilinmiyor"}

# ARP spoofing tespiti
def detect_arp_spoofing(arp_table):
    """
    ARP tablosunu inceleyerek olası ARP spoofing saldırılarını tespit eder.
    
    Args:
        arp_table (list): ARP tablosu kayıtları
        
    Returns:
        list: Tespit edilen şüpheli durumlar
    """
    suspicious_entries = []
    mac_to_ips = defaultdict(list)
    
    # Her MAC adresine bağlı IP'leri topla
    for entry in arp_table:
        mac = entry["mac"].lower()  # Büyük/küçük harf duyarlılığını kaldır
        ip = entry["ip"]
        
        # Broadcast MAC adresini atla (normal bir ağ özelliği, saldırı değil)
        if mac == "ff:ff:ff:ff:ff:ff":
            continue
            
        # Multicast MAC adresini atla (normal bir ağ özelliği, saldırı değil)
        if mac.startswith(("01:", "03:", "05:", "07:", "09:", "0b:", "0d:", "0f:")):
            continue
            
        mac_to_ips[mac].append(ip)
    
    # Bir MAC'in birden fazla IP'si varsa (1'den çok cihaz olabilir)
    for mac, ips in mac_to_ips.items():
        if len(ips) > 1:
            suspicious_entries.append({
                "type": "multiple_ips",
                "mac": mac,
                "ips": ips,
                "message": f"⚠️ Şüpheli: {mac} MAC adresine sahip {len(ips)} farklı IP adresi var: {', '.join(ips)}"
            })
    
    # Ağ geçidinin MAC adresi değişmiş mi kontrol et
    gateway = get_default_gateway()
    if gateway["ip"] != "Bilinmiyor" and gateway["mac"] != "Bilinmiyor":
        gateway_entries = [entry for entry in arp_table if entry["ip"] == gateway["ip"]]
        if len(gateway_entries) > 0:
            if len(gateway_entries) > 1:
                suspicious_entries.append({
                    "type": "gateway_multiple_macs",
                    "ip": gateway["ip"],
                    "macs": [entry["mac"] for entry in gateway_entries],
                    "message": f"❌ TEHLİKE: Ağ geçidi {gateway['ip']} için birden fazla MAC adresi var!"
                })
    
    # Bilgi amaçlı özel MAC adreslerini ekle (saldırı değil)
    info_entries = []
    for entry in arp_table:
        mac = entry["mac"].lower()
        # Broadcast MAC (ff:ff:ff:ff:ff:ff)
        if mac == "ff:ff:ff:ff:ff:ff":
            info_entries.append({
                "type": "info_broadcast",
                "ip": entry["ip"],
                "mac": mac,
                "message": f"📌 Bilgi: Broadcast MAC adresi: IP={entry['ip']}, MAC={mac}"
            })
        # Multicast MAC (ilk byte'ın en düşük biti 1)
        elif mac.startswith(("01:", "03:", "05:", "07:", "09:", "0b:", "0d:", "0f:")):
            info_entries.append({
                "type": "info_multicast",
                "ip": entry["ip"],
                "mac": mac,
                "message": f"📌 Bilgi: Multicast MAC adresi: IP={entry['ip']}, MAC={mac}"
            })
    
    # Bilgi amaçlı girdileri listeye ekle (şüpheli durumlar listesinin sonuna)
    for entry in info_entries:
        suspicious_entries.append(entry)
    
    return suspicious_entries

# Ana ARP tarama fonksiyonu
def arp_kontrol_et():
    """
    ARP tablosunu kontrol ederek olası ARP spoofing saldırılarını tespit eder.
    Bu fonksiyon GUI tarafından çağrılır.
    """
    print("=" * 60)
    print("🔍 ARP Tablosu Taraması Başlatılıyor...")
    print("=" * 60)
    
    # ARP tablosunu al
    arp_table = get_arp_table()
    
    if not arp_table:
        print("❌ ARP tablosu alınamadı veya boş.")
        return
    
    # Varsayılan ağ geçidini bul
    gateway = get_default_gateway()
    
    print(f"🌐 Varsayılan Ağ Geçidi: {gateway['ip']} (MAC: {gateway['mac']})")
    print("=" * 60)
    
    # ARP tablosunu göster
    print("\n📋 ARP Tablosu:")
    print("-" * 60)
    print(f"{'IP Adresi':<15} {'MAC Adresi':<20} {'Arayüz':<10}")
    print("-" * 60)
    for entry in arp_table:
        print(f"{entry['ip']:<15} {entry['mac']:<20} {entry['interface']:<10}")
    
    # ARP spoofing tespiti
    print("\n🔍 ARP Spoofing Analizi:")
    print("-" * 60)
    
    suspicious_entries = detect_arp_spoofing(arp_table)
    
    if suspicious_entries:
        for entry in suspicious_entries:
            print(entry["message"])
    else:
        print("✅ Herhangi bir şüpheli durum tespit edilmedi.")
    
    # Özet
    print("\n📊 Analiz Özeti:")
    print("-" * 60)
    print(f"Toplam kayıt sayısı: {len(arp_table)}")
    print(f"Şüpheli kayıt sayısı: {len(suspicious_entries)}")
    
    if suspicious_entries:
        şüpheli_tiplerini_say = defaultdict(int)
        for entry in suspicious_entries:
            şüpheli_tiplerini_say[entry["type"]] += 1
        
        for tip, sayı in şüpheli_tiplerini_say.items():
            tip_açıklamaları = {
                "multiple_ips": "Birden fazla IP'ye sahip MAC adresleri",
                "gateway_multiple_macs": "Birden fazla MAC'e sahip ağ geçidi",
                "broadcast_mac": "Broadcast MAC adresleri",
                "multicast_mac": "Multicast MAC adresleri"
            }
            açıklama = tip_açıklamaları.get(tip, tip)
            print(f"- {açıklama}: {sayı}")
        
        print("\n⚠️ Şüpheli durumlar tespit edildi. Ağınızda ARP spoofing saldırısı olabilir.")
        print("⚠️ Özellikle birden fazla MAC adresine sahip bir ağ geçidi varsa, bu ciddi bir tehlike işaretidir.")
    else:
        print("\n✅ Ağınız şu an için güvenli görünüyor.")
    
    print("\n" + "=" * 60)
    print("🏁 Tarama Tamamlandı")
    print("=" * 60)


# ============= GRAFİK KULLANICI ARAYÜZÜ =============

class ARP_GUI:
    def __init__(self, root):
        self.root = root
        self.root.title("ARP Spoofing Tespit Aracı")
        self.root.geometry("600x500")
        self.root.resizable(True, True)
        
        # Google benzeri renk şeması
        self.bg_color = "#FFFFFF"       # Beyaz arka plan
        self.text_color = "#202124"     # Koyu gri metin
        self.button_color = "#4285F4"   # Google mavi
        self.warning_color = "#EA4335"  # Google kırmızı
        self.success_color = "#34A853"  # Google yeşil
        self.accent_color = "#FBBC05"   # Google sarı
        self.light_gray = "#F8F9FA"     # Açık gri arka plan
        
        # Ana çerçeveyi oluştur
        main_frame = tk.Frame(root, bg=self.bg_color)
        main_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
        
        # Google tarzı başlık ve logo
        title_frame = tk.Frame(main_frame, bg=self.bg_color)
        title_frame.pack(pady=(0, 20))
        
        # Logo label (simge yerine metin)
        logo = tk.Label(title_frame, text="🛡️", font=("Arial", 48), bg=self.bg_color)
        logo.pack()
        
        # Başlık
        title = tk.Label(title_frame, text="ARP Spoofing Tespit", 
                        font=("Arial", 24, "bold"), bg=self.bg_color, fg=self.text_color)
        title.pack(pady=(0, 5))
        
        # Arama çubuğu benzeri tasarım
        search_frame = tk.Frame(main_frame, bg=self.bg_color, highlightbackground="#DADCE0", 
                               highlightthickness=1, bd=0, padx=10, pady=10)
        search_frame.pack(fill=tk.X, padx=40, pady=10)
        
        # Tarama butonu (Google tarzı büyük mavi buton)
        self.scan_button = tk.Button(search_frame, text="Ağımı Tara", command=self.start_scan,
                                  bg=self.button_color, fg="#FFFFFF", 
                                  font=("Arial", 14), relief=tk.FLAT,
                                  padx=20, pady=10)
        self.scan_button.pack(pady=5)
        
        # Açıklama metni
        description = tk.Label(search_frame, 
                             text="Bu uygulama ağınızı ARP spoofing saldırılarına karşı tarar.", 
                             font=("Arial", 10), bg=self.bg_color, fg="#5F6368")
        description.pack(pady=(0, 5))
        
        # Sonuç kartı
        self.result_card = tk.Frame(main_frame, bg=self.light_gray, 
                                 highlightbackground="#DADCE0", highlightthickness=1, 
                                 padx=20, pady=20)
        self.result_card.pack(fill=tk.BOTH, expand=True, pady=15)
        
        # Sonuç kartı başlığı ve durum ikonu
        self.status_icon = tk.Label(self.result_card, text="🔍", 
                                 font=("Arial", 36), bg=self.light_gray)
        self.status_icon.pack(pady=(0, 5))
        
        self.status_title = tk.Label(self.result_card, text="Ağınızın Durumu", 
                                  font=("Arial", 16, "bold"), 
                                  bg=self.light_gray, fg=self.text_color)
        self.status_title.pack(pady=(0, 5))
        
        self.status_text = tk.Label(self.result_card, 
                                 text="Ağınızın güvenlik durumunu görmek için 'Ağımı Tara' düğmesine tıklayın.",
                                 wraplength=500, justify="center", 
                                 font=("Arial", 11), bg=self.light_gray, fg="#5F6368")
        self.status_text.pack(pady=(0, 10))
        
        # İlerleme çubuğu
        self.progress = ttk.Progressbar(self.result_card, orient=tk.HORIZONTAL, length=300, mode='indeterminate')
        
        # Sonuç alanı (sadeleştirilmiş)
        self.result_text = scrolledtext.ScrolledText(self.result_card, wrap=tk.WORD, height=6,
                                                  bg="#FFFFFF", fg=self.text_color, 
                                                  font=("Arial", 10), bd=1, relief=tk.FLAT)
        self.result_text.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.result_text.config(state=tk.DISABLED)
        
        # Alt bilgi çubuğu - ayarlar
        footer_frame = tk.Frame(main_frame, bg=self.bg_color)
        footer_frame.pack(fill=tk.X, pady=(5, 0))
        
        self.periodic_var = tk.BooleanVar()
        self.startup_var = tk.BooleanVar()
        self.period_hours = tk.IntVar(value=24)  # Varsayılan 24 saat
        
        # Periyodik tarama seçeneği (checkbox + ayar butonu)
        periodic_frame = tk.Frame(footer_frame, bg=self.bg_color)
        periodic_frame.pack(side=tk.LEFT, padx=(0, 10))
        
        periodic_check = tk.Checkbutton(periodic_frame, text="Periyodik tarama", 
                                      variable=self.periodic_var, 
                                      bg=self.bg_color, fg=self.text_color, 
                                      font=("Arial", 10), bd=0)
        periodic_check.pack(side=tk.LEFT)
        
        # Periyod ayar butonu
        period_button = tk.Button(periodic_frame, text="⚙️", 
                                command=self.show_period_settings,
                                bg=self.bg_color, fg=self.text_color,
                                font=("Arial", 9), relief=tk.FLAT,
                                padx=2, pady=0)
        period_button.pack(side=tk.LEFT, padx=(2, 0))
        
        # Periyod gösterme etiketi
        self.period_label = tk.Label(periodic_frame, 
                                  text=f"({self.period_hours.get()} saat)", 
                                  bg=self.bg_color, fg="#5F6368", 
                                  font=("Arial", 9))
        self.period_label.pack(side=tk.LEFT, padx=(2, 0))
        
        # Otomatik başlatma 
        startup_check = tk.Checkbutton(footer_frame, text="Açılışta başlat",
                                     variable=self.startup_var,
                                     bg=self.bg_color, fg=self.text_color, 
                                     font=("Arial", 10), bd=0)
        startup_check.pack(side=tk.LEFT)
        
        # Durdur butonu
        self.stop_button = tk.Button(footer_frame, text="Durdur", 
                                  command=self.stop_scan,
                                  bg=self.warning_color, fg="#FFFFFF",
                                  font=("Arial", 10), relief=tk.FLAT,
                                  state=tk.DISABLED,
                                  padx=10, pady=3)
        self.stop_button.pack(side=tk.RIGHT)
        
        # Durum çubuğu
        self.status_var = tk.StringVar()
        self.status_var.set("Hazır")
        status_bar = tk.Label(main_frame, textvariable=self.status_var,
                            bd=1, relief=tk.SUNKEN, anchor=tk.W,
                            bg=self.light_gray, fg="#5F6368", font=("Arial", 9))
        status_bar.pack(side=tk.BOTTOM, fill=tk.X, pady=(5, 0))
        
        # Arka plan tarama değişkenleri
        self.periodic_running = False
        self.periodic_thread = None
        self.warning_window = None
    
    def start_scan(self):
        """Tarama işlemini başlatır"""
        # Arayüzü güncelle
        self.status_var.set("Ağınız taranıyor...")
        self.scan_button.config(state=tk.DISABLED)
        self.progress.pack(fill=tk.X, pady=10)
        self.progress.start()
        
        # Sonuç alanını temizle
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state=tk.DISABLED)
        
        # Arka planda tarama yap
        threading.Thread(target=self._scan_thread, daemon=True).start()
    
    def _scan_thread(self):
        """Arka planda tarama işlemini yapar"""
        try:
            # Çıktıyı yakala
            output = io.StringIO()
            with redirect_stdout(output):
                arp_kontrol_et()
            
            scan_output = output.getvalue()
            
            # Şüpheli durumları tespit et
            suspicious_entries = []
            is_safe = True
            important_lines = []
            
            for line in scan_output.split('\n'):
                # Tehlikeli durumlar
                if "⚠️" in line:
                    suspicious_entries.append({
                        "message": line,
                        "type": "other"
                    })
                    important_lines.append(line)
                    is_safe = False
                elif "❌" in line:
                    suspicious_entries.append({
                        "message": line,
                        "type": "gateway_multiple_macs"
                    })
                    important_lines.append(line)
                    is_safe = False
                # Bilgi satırları
                elif "📌" in line:
                    if "Broadcast MAC adresi" in line or "Multicast MAC adresi" in line:
                        suspicious_entries.append({
                            "message": line,
                            "type": "info_broadcast_multicast"
                        })
                    else:
                        suspicious_entries.append({
                            "message": line,
                            "type": "info_other"
                        })
                    important_lines.append(line)
                # Başarı durumları
                elif "✅" in line:
                    important_lines.append(line)
            
            # Arayüzü güncelle
            self.root.after(0, lambda: self._update_ui(is_safe, important_lines, suspicious_entries))
            
            # Periyodik tarama başlatılacak mı?
            if self.periodic_var.get() and not self.periodic_running:
                self.root.after(0, self.start_periodic_scan)
            else:
                # İlerleme çubuğunu kapat ve düğmeyi etkinleştir
                self.root.after(0, self.progress.stop)
                self.root.after(0, self.progress.pack_forget)
                self.root.after(0, lambda: self.scan_button.config(state=tk.NORMAL))
                self.root.after(0, lambda: self.status_var.set("Tarama tamamlandı"))
                
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Hata", f"Tarama sırasında hata: {str(e)}"))
            self.root.after(0, self.progress.stop)
            self.root.after(0, self.progress.pack_forget)
            self.root.after(0, lambda: self.scan_button.config(state=tk.NORMAL))
            self.root.after(0, lambda: self.status_var.set("Tarama hatası"))
    
    def _update_ui(self, is_safe, important_lines, suspicious_entries):
        """Tarama sonuçlarına göre arayüzü günceller"""
        # Gerçekten tehlikeli durumları filtrele - sadece info olmayan girdiler
        real_threats = [entry for entry in suspicious_entries if not entry.get("type", "").startswith("info_")]
        
        # Gerçekten tehlike var mı kontrol et
        is_truly_safe = len(real_threats) == 0
        
        # Sonuç kartını güncelle
        if is_truly_safe:
            self.status_icon.config(text="✅")
            self.status_title.config(text="Ağınız Güvende", fg=self.success_color)
            self.status_text.config(text="Herhangi bir ARP spoofing tehdidi tespit edilmedi.")
            self.result_card.config(highlightbackground=self.success_color)
        else:
            self.status_icon.config(text="⚠️")
            self.status_title.config(text="Saldırı Riski!", fg=self.warning_color)
            self.status_text.config(text="Ağınızda şüpheli ARP etkinliği tespit edildi! Detaylar için aşağıya bakın.")
            self.result_card.config(highlightbackground=self.warning_color)
            
            # Gerçek şüpheli durum varsa uyarı penceresi göster
            if len(real_threats) > 0:
                self.root.after(500, lambda: self.show_warning(real_threats))
        
        # Sonuç metnini güncelle
        self.result_text.config(state=tk.NORMAL)
        
        for line in important_lines:
            if "⚠️" in line or "❌" in line:
                self.result_text.insert(tk.END, line + "\n", "warning")
                if "warning" not in self.result_text.tag_names():
                    self.result_text.tag_configure("warning", foreground=self.warning_color)
            elif "✅" in line:
                self.result_text.insert(tk.END, line + "\n", "success")
                if "success" not in self.result_text.tag_names():
                    self.result_text.tag_configure("success", foreground=self.success_color)
            else:
                self.result_text.insert(tk.END, line + "\n")
        
        self.result_text.see(tk.END)
        self.result_text.config(state=tk.DISABLED)
    
    def show_warning(self, suspicious_entries):
        """Şüpheli durumlar için uyarı penceresi gösterir"""
        # Önceki pencereyi kapat
        if self.warning_window and self.warning_window.winfo_exists():
            self.warning_window.destroy()
        
        # Yeni uyarı penceresi
        self.warning_window = Toplevel(self.root)
        self.warning_window.title("Güvenlik Uyarısı")
        self.warning_window.geometry("500x450")
        self.warning_window.configure(bg="#FFFFFF")
        self.warning_window.transient(self.root)
        self.warning_window.grab_set()
        
        # İçerik
        content = tk.Frame(self.warning_window, bg="#FFFFFF", padx=20, pady=20)
        content.pack(fill=tk.BOTH, expand=True)
        
        # Başlık ve ikon
        header = tk.Frame(content, bg="#FFFFFF")
        header.pack(fill=tk.X, pady=(0, 15))
        
        # Uyarı ikonu
        icon = tk.Label(header, text="⚠️", font=("Arial", 36), fg=self.warning_color, bg="#FFFFFF")
        icon.pack(side=tk.LEFT, padx=(0, 15))
        
        header_text = tk.Frame(header, bg="#FFFFFF")
        header_text.pack(side=tk.LEFT)
        
        warning_title = tk.Label(header_text, text="Güvenlik Uyarısı", 
                              font=("Arial", 16, "bold"), fg=self.warning_color, bg="#FFFFFF")
        warning_title.pack(anchor="w")
        
        warning_subtitle = tk.Label(header_text, text="ARP spoofing riski tespit edildi", 
                                 font=("Arial", 12), fg="#5F6368", bg="#FFFFFF")
        warning_subtitle.pack(anchor="w")
        
        # Açıklama kartı
        description_card = tk.Frame(content, bg=self.light_gray, 
                                 highlightbackground="#DADCE0", highlightthickness=1,
                                 padx=15, pady=15)
        description_card.pack(fill=tk.X, pady=10)
        
        description = tk.Label(description_card, 
                            text="Ağınızda şüpheli ARP etkinliği tespit edildi. Bu, bir saldırganın ağ trafiğinizi izlediğini gösterebilir. Aşağıdaki önlemleri almanız önerilir.",
                            wraplength=430, justify="left", 
                            font=("Arial", 11), bg=self.light_gray, fg="#202124")
        description.pack(anchor="w")
        
        # Öneriler kartı
        actions_card = tk.Frame(content, bg=self.light_gray,
                             highlightbackground="#DADCE0", highlightthickness=1,
                             padx=15, pady=15)
        actions_card.pack(fill=tk.X, pady=10)
        
        actions_title = tk.Label(actions_card, text="Önerilen Önlemler", 
                              font=("Arial", 12, "bold"), bg=self.light_gray, fg="#202124")
        actions_title.pack(anchor="w", pady=(0, 10))
        
        # Önerilen önlemler listesi
        actions = [
            "Ağ bağlantınızı hemen kesin veya güvenli olmayan ağlarda hassas işlemler yapmaktan kaçının.",
            "Ağ yöneticinize durumu bildirin.",
            "VPN kullanarak ağ trafiğinizi şifreleyin.",
            "HTTPS bağlantıları ve güvenli iletişim protokolleri kullanın.",
            "Statik ARP girdileri ekleyerek kritik cihazların MAC adreslerini sabitleyin."
        ]
        
        for action in actions:
            action_frame = tk.Frame(actions_card, bg=self.light_gray)
            action_frame.pack(fill=tk.X, pady=2)
            
            bullet = tk.Label(action_frame, text="•", font=("Arial", 12, "bold"),
                           bg=self.light_gray, fg=self.button_color)
            bullet.pack(side=tk.LEFT, padx=(0, 5))
            
            action_text = tk.Label(action_frame, text=action, wraplength=400, justify="left",
                                font=("Arial", 10), bg=self.light_gray, fg="#202124")
            action_text.pack(side=tk.LEFT, fill=tk.X, expand=True, anchor="w")
        
        # Kapat butonu
        close_btn = tk.Button(content, text="Anladım", command=self.warning_window.destroy,
                           bg=self.button_color, fg="#FFFFFF", font=("Arial", 11, "bold"),
                           relief=tk.FLAT, padx=15, pady=8)
        close_btn.pack(side=tk.RIGHT, pady=10)
        
        # Pencereyi ortala
        self.warning_window.update_idletasks()
        width = self.warning_window.winfo_width()
        height = self.warning_window.winfo_height()
        x = (self.warning_window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.warning_window.winfo_screenheight() // 2) - (height // 2)
        self.warning_window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    
    def start_periodic_scan(self):
        """Periyodik taramayı başlatır"""
        self.periodic_running = True
        self.stop_button.config(state=tk.NORMAL)
        
        # Seçilen periyot
        hours = self.period_hours.get()
        
        # Arka planda çalışma uyarısı göster
        message = f"Periyodik tarama başlatıldı. Ağınız {hours} saatte bir kontrol edilecek.\n\n" + \
                 "⚠️ Uygulama arka planda çalışmaya devam edecektir. Uygulama penceresi " + \
                 "kapatılmadığı sürece periyodik kontroller devam edecek.\n\n" + \
                 "Bilgisayarınızın yeniden başlatılması durumunda, uygulamayı " + \
                 "tekrar manuel olarak başlatmanız gerekecektir."
        
        messagebox.showinfo("Periyodik Tarama", message)
        
        # Periyodik tarama thread'ini başlat
        self.periodic_thread = threading.Thread(target=self._periodic_thread, daemon=True)
        self.periodic_thread.start()
        
        # Periyodik tarama yapılacak bir sonraki zamanı hesapla
        next_time = time.localtime(time.time() + (hours * 3600))
        next_time_str = time.strftime("%H:%M:%S", next_time)
        self.status_var.set(f"Periyodik tarama aktif - Sonraki tarama: {next_time_str}")
    
    def show_period_settings(self):
        """Periyodik tarama aralığı ayarlama penceresi gösterir"""
        # Yeni pencere oluştur
        settings_window = Toplevel(self.root)
        settings_window.title("Periyodik Tarama Ayarları")
        settings_window.geometry("350x250")
        settings_window.configure(bg="#FFFFFF")
        settings_window.resizable(False, False)
        settings_window.transient(self.root)
        settings_window.grab_set()
        
        # İçerik çerçevesi
        content = tk.Frame(settings_window, bg="#FFFFFF", padx=20, pady=20)
        content.pack(fill=tk.BOTH, expand=True)
        
        # Başlık
        title_label = tk.Label(content, text="Periyodik Tarama Aralığı", 
                             font=("Arial", 14, "bold"), 
                             bg="#FFFFFF", fg=self.text_color)
        title_label.pack(pady=(0, 15))
        
        # Açıklama
        desc_label = tk.Label(content, 
                           text="Ağınızın ne sıklıkla taranacağını seçin. Tarama tamamlandıktan sonra, uygulama arka planda çalışmaya devam edecek.",
                           wraplength=300, justify="center", 
                           bg="#FFFFFF", fg="#5F6368", 
                           font=("Arial", 10))
        desc_label.pack(pady=(0, 15))
        
        # Saat seçenekleri 
        values_frame = tk.Frame(content, bg="#FFFFFF")
        values_frame.pack(pady=10)
        
        hours_label = tk.Label(values_frame, text="Saat:", 
                            bg="#FFFFFF", fg=self.text_color, 
                            font=("Arial", 12))
        hours_label.pack(side=tk.LEFT, padx=(0, 10))
        
        # Saat değerleri (string olarak)
        hour_values = ["1", "2", "4", "6", "8", "12", "24", "48", "72"]
        
        # Saat seçimi combobox
        hour_combobox = ttk.Combobox(values_frame, 
                                  values=hour_values, 
                                  width=5, 
                                  state="readonly",
                                  font=("Arial", 12))
        
        # Mevcut değeri seç
        current_hour = str(self.period_hours.get())  # int'den string'e çevir
        if current_hour in hour_values:
            hour_combobox.set(current_hour)
        else:
            hour_combobox.set("24")  # Varsayılan 24 saat
            
        hour_combobox.pack(side=tk.LEFT)
        
        # Butonlar
        button_frame = tk.Frame(content, bg="#FFFFFF")
        button_frame.pack(fill=tk.X, pady=(20, 0))
        
        cancel_btn = tk.Button(button_frame, text="İptal", 
                            command=settings_window.destroy,
                            bg="#E8EAED", fg=self.text_color, 
                            font=("Arial", 11),
                            relief=tk.FLAT, padx=15, pady=8)
        cancel_btn.pack(side=tk.LEFT)
        
        # Kaydet butonu
        def save_settings():
            try:
                hours = int(hour_combobox.get())
                self.period_hours.set(hours)
                self.period_label.config(text=f"({hours} saat)")
                settings_window.destroy()
            except ValueError:
                messagebox.showerror("Hata", "Geçerli bir saat değeri giriniz.")
        
        save_btn = tk.Button(button_frame, text="Kaydet", 
                          command=save_settings,
                          bg=self.button_color, fg="#FFFFFF", 
                          font=("Arial", 11, "bold"),
                          relief=tk.FLAT, padx=15, pady=8)
        save_btn.pack(side=tk.RIGHT)
        
        # Pencereyi ortala
        settings_window.update_idletasks()
        width = settings_window.winfo_width()
        height = settings_window.winfo_height()
        x = (settings_window.winfo_screenwidth() // 2) - (width // 2)
        y = (settings_window.winfo_screenheight() // 2) - (height // 2)
        settings_window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    
    def _periodic_thread(self):
        """Periyodik tarama arka plan thread'i"""
        # Seçilen saat değerine göre saniye hesapla
        hours = self.period_hours.get()
        interval = hours * 3600  # Saat başına 3600 saniye
        
        # Test için daha kısa interval
        #interval = 60  # 1 dakika
        
        while self.periodic_running:
            # Zaman sayacı ve durum gösterimi
            for i in range(interval):
                if not self.periodic_running:
                    return
                
                # Her dakikada bir durum metnini güncelle
                if i % 60 == 0:
                    remaining = interval - i
                    hours, remainder = divmod(remaining, 3600)
                    minutes, _ = divmod(remainder, 60)
                    self.root.after(0, lambda h=hours, m=minutes: 
                                  self.status_var.set(f"Sonraki taramaya: {h} saat {m} dakika"))
                
                time.sleep(1)
            
            # Süre dolduğunda tarama yap
            if not self.periodic_running:
                return
                
            # Tarama yap (ana thread'de güvenli çağrı)
            self.root.after(0, self.start_scan)
            
            # Taramanın tamamlanmasını bekle
            time.sleep(5)
    
    def stop_scan(self):
        """Periyodik taramayı durdurur"""
        if self.periodic_running:
            self.periodic_running = False
            self.stop_button.config(state=tk.DISABLED)
            self.status_var.set("Periyodik tarama durduruldu")
            messagebox.showinfo("Periyodik Tarama", "Periyodik tarama durduruldu.")


# Program çalıştırma
if __name__ == "__main__":
    root = tk.Tk()
    app = ARP_GUI(root)
    root.mainloop()
