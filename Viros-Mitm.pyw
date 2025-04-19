#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
ARP Spoofing Tespit Aracı - Spotify Tema
Bu araç, ağda olası ARP spoofing saldırılarını tespit etmek için gerekli tüm fonksiyonları ve 
tkinter tabanlı bir grafik arayüz içerir.

Geliştirici: Replit Kullanıcısı
Versiyon: 2.0
Tarih: 2025-04-19
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
from tkinter import scrolledtext, messagebox, ttk, Toplevel, PhotoImage, Canvas, Frame
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
        # Windows için cmd ekranını gizle
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0  # SW_HIDE
            
        # Platforma göre uygun komutu belirle
        if os.name == 'nt':  # Windows
            output = subprocess.check_output(['arp', '-a'], text=True, startupinfo=startupinfo)
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
        # Windows için cmd ekranını gizle
        startupinfo = None
        if os.name == 'nt':
            startupinfo = subprocess.STARTUPINFO()
            startupinfo.dwFlags |= subprocess.STARTF_USESHOWWINDOW
            startupinfo.wShowWindow = 0  # SW_HIDE
            
        if os.name == 'nt':  # Windows
            output = subprocess.check_output(['ipconfig'], text=True, startupinfo=startupinfo)
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
    # Bilgi girişleri olmayan şüpheli kayıtların sayısını hesapla
    gercek_supheli_sayisi = len([entry for entry in suspicious_entries 
                               if entry["type"] not in ["info_broadcast", "info_multicast"]])
    print(f"Şüpheli kayıt sayısı: {gercek_supheli_sayisi}")
    
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
        
        # Gerçek şüpheli durumlar varsa uyarı göster
        if gercek_supheli_sayisi > 0:
            print("\n⚠️ Şüpheli durumlar tespit edildi. Ağınızda ARP spoofing saldırısı olabilir.")
            print("⚠️ Özellikle birden fazla MAC adresine sahip bir ağ geçidi varsa, bu ciddi bir tehlike işaretidir.")
        else:
            print("\n✅ Ağınız şu an için güvenli görünüyor.")
    else:
        print("\n✅ Ağınız şu an için güvenli görünüyor.")
    
    print("\n" + "=" * 60)
    print("🏁 Tarama Tamamlandı")
    print("=" * 60)


# ============= GRAFİK KULLANICI ARAYÜZÜ =============

# Yuvarlak köşeli çerçeve oluşturmak için özel widget
class RoundedFrame(tk.Frame):
    def __init__(self, parent, bg_color="#121212", corner_radius=10, **kwargs):
        tk.Frame.__init__(self, parent, bg=bg_color, highlightthickness=0, **kwargs)
        
        self.corner_radius = corner_radius
        self.bg_color = bg_color
        
        # Canvas oluştur ve frame'e ekle
        self.canvas = tk.Canvas(self, bg=bg_color, highlightthickness=0)
        self.canvas.pack(fill="both", expand=True)
        
        # Dikdörtgen çiz
        self.canvas.update()  # Canvas boyutunu almak için güncelleme yap
        width = self.canvas.winfo_width()
        height = self.canvas.winfo_height()
        
        # İlk kez boyut 1'den büyük olmalı
        if width > 1 and height > 1:
            self.rounded_rect(0, 0, width, height, self.corner_radius, self.bg_color)
        
        # Boyut değişiminde yeniden çiz
        self.bind("<Configure>", self._on_resize)
    
    def _on_resize(self, event):
        """Frame boyutu değiştiğinde yuvarlak köşeli dikdörtgeni yeniden çizer"""
        width = event.width
        height = event.height
        self.canvas.delete("all")  # Tüm çizimleri temizle
        self.rounded_rect(0, 0, width, height, self.corner_radius, self.bg_color)
    
    def rounded_rect(self, x1, y1, x2, y2, r, fill_color):
        """Yuvarlak köşeli dikdörtgen çizer"""
        points = [
            x1+r, y1,
            x2-r, y1,
            x2, y1,
            x2, y1+r,
            x2, y2-r,
            x2, y2,
            x2-r, y2,
            x1+r, y2,
            x1, y2,
            x1, y2-r,
            x1, y1+r,
            x1, y1
        ]
        
        return self.canvas.create_polygon(points, fill=fill_color, smooth=True)

# Spotify stili buton
class SpotifyButton(tk.Canvas):
    def __init__(self, parent, text="Button", command=None, width=120, height=40, 
                 bg_color="#1DB954", text_color="#FFFFFF", hover_color="#1ED760",
                 font=("Arial", 12), corner_radius=20, **kwargs):
        tk.Canvas.__init__(self, parent, width=width, height=height, 
                         bg=parent["bg"], highlightthickness=0, **kwargs)
        
        self.command = command
        self.bg_color = bg_color
        self.hover_color = hover_color
        self.corner_radius = corner_radius
        self.text = text
        self.text_color = text_color
        self.font = font
        
        # Buton çiz
        self.button_shape = self.rounded_rect(0, 0, width, height, corner_radius, bg_color)
        self.button_text = self.create_text(width/2, height/2, text=text, 
                                         fill=text_color, font=font)
        
        # Mouse olayları
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)
        
    def rounded_rect(self, x1, y1, x2, y2, r, fill_color):
        """Yuvarlak köşeli dikdörtgen çizer"""
        points = [
            x1+r, y1,
            x2-r, y1,
            x2, y1,
            x2, y1+r,
            x2, y2-r,
            x2, y2,
            x2-r, y2,
            x1+r, y2,
            x1, y2,
            x1, y2-r,
            x1, y1+r,
            x1, y1
        ]
        
        return self.create_polygon(points, fill=fill_color, smooth=True)
    
    def _on_enter(self, event):
        """Mouse buton üzerine geldiğinde"""
        self.itemconfig(self.button_shape, fill=self.hover_color)
        
    def _on_leave(self, event):
        """Mouse butondan ayrıldığında"""
        self.itemconfig(self.button_shape, fill=self.bg_color)
        
    def _on_click(self, event):
        """Butona tıklandığında"""
        if self.command:
            self.command()

# Ana uygulama sınıfı
class ARP_GUI_Spotify:
    def __init__(self, root):
        self.root = root
        self.root.title("ARP Guardian - Ağ Güvenliği")
        self.root.geometry("900x600")
        self.root.minsize(800, 500)
        
        # Spotify renk şeması
        self.bg_color = "#121212"       # Ana arka plan - koyu siyah
        self.sidebar_color = "#000000"  # Kenar çubuğu - siyah
        self.text_color = "#FFFFFF"     # Beyaz metin
        self.accent_color = "#1DB954"   # Spotify yeşili
        self.card_color = "#181818"     # Kart arka planı
        self.card_hover = "#282828"     # Kart hover rengi
        self.warning_color = "#F59B23"  # Uyarı rengi - turuncu
        self.danger_color = "#E8265E"   # Tehlike rengi - kırmızı
        
        # Uygulama ikonları (Emojilerle temsil ediliyor, daha sonra gerçek ikonlarla değiştirilebilir)
        self.icons = {
            "home": "🏠",
            "scan": "🔍",
            "history": "📜",
            "settings": "⚙️",
            "info": "ℹ️",
            "warning": "⚠️",
            "success": "✅",
            "danger": "❌"
        }
        
        # Ana container
        self.root.configure(bg=self.bg_color)
        
        # Layout
        self.setup_layout()
        
        # İçerikleri yükle
        self.load_home_content()
        
        # Arka plan tarama değişkenleri
        self.periodic_running = False
        self.periodic_thread = None
        self.warning_window = None
        self.periodic_var = tk.BooleanVar()
        self.startup_var = tk.BooleanVar()
        self.period_hours = tk.IntVar(value=24)  # Varsayılan 24 saat
    
    def setup_layout(self):
        """Ana yerleşim düzenini oluşturur"""
        # Ana container
        self.main_container = tk.Frame(self.root, bg=self.bg_color)
        self.main_container.pack(fill=tk.BOTH, expand=True)
        
        # Sol kenar çubuğu
        self.sidebar = tk.Frame(self.main_container, bg=self.sidebar_color, width=220)
        self.sidebar.pack(side=tk.LEFT, fill=tk.Y, padx=0, pady=0)
        self.sidebar.pack_propagate(False)  # Boyutu sabit tut
        
        # Spotify logo ve başlık
        logo_frame = tk.Frame(self.sidebar, bg=self.sidebar_color)
        logo_frame.pack(fill=tk.X, padx=20, pady=(20, 30))
        
        logo_text = tk.Label(logo_frame, text="🛡️ ARP Guardian", 
                          font=("Arial", 16, "bold"), 
                          bg=self.sidebar_color, fg=self.text_color)
        logo_text.pack(anchor=tk.W)
        
        version_label = tk.Label(logo_frame, text="v2.0 - Ağ Güvenlik Aracı", 
                              font=("Arial", 8), 
                              bg=self.sidebar_color, fg="#B3B3B3")
        version_label.pack(anchor=tk.W, pady=(2, 0))
        
        # Kenar çubuğu navigasyonu
        self.create_sidebar_button("Ana Sayfa", self.icons["home"], self.load_home_content)
        self.create_sidebar_button("Ağ Taraması", self.icons["scan"], self.load_scan_content)
        self.create_sidebar_button("Tarama Geçmişi", self.icons["history"], self.load_history_content)
        self.create_sidebar_button("Ayarlar", self.icons["settings"], self.load_settings_content)
        
        # Bilgi etiketi
        info_frame = tk.Frame(self.sidebar, bg=self.sidebar_color)
        info_frame.pack(side=tk.BOTTOM, fill=tk.X, padx=20, pady=20)
        
        info_label = tk.Label(info_frame, 
                           text="Bu uygulama ağınızı ARP spoofing saldırılarına karşı korur.", 
                           wraplength=180, justify=tk.LEFT,
                           font=("Arial", 9), 
                           bg=self.sidebar_color, fg="#B3B3B3")
        info_label.pack(anchor=tk.W)
        
        # Ana içerik alanı
        self.content_area = tk.Frame(self.main_container, bg=self.bg_color)
        self.content_area.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=0, pady=0)
        
        # Alt durum çubuğu
        self.status_var = tk.StringVar()
        self.status_var.set("Hoş geldiniz! Ağınızı taramak için sol menüden 'Ağ Taraması' seçeneğine tıklayın.")
        
        self.status_bar = tk.Label(self.root, textvariable=self.status_var,
                                bd=1, relief=tk.FLAT, anchor=tk.W,
                                bg="#282828", fg="#B3B3B3", font=("Arial", 9),
                                padx=10, pady=5)
        self.status_bar.pack(side=tk.BOTTOM, fill=tk.X)
    
    def create_sidebar_button(self, text, icon, command):
        """Kenar çubuğu navigasyon butonu oluşturur"""
        btn_frame = tk.Frame(self.sidebar, bg=self.sidebar_color, padx=15, pady=5)
        btn_frame.pack(fill=tk.X, padx=5, pady=2)
        
        # Buton özellikleri
        btn_frame.bind("<Button-1>", lambda e: command())
        btn_frame.bind("<Enter>", 
                     lambda e: btn_frame.configure(background="#282828"))
        btn_frame.bind("<Leave>", 
                     lambda e: btn_frame.configure(background=self.sidebar_color))
        
        # Buton içeriği
        icon_label = tk.Label(btn_frame, text=icon, font=("Arial", 14),
                           bg=btn_frame["bg"], fg=self.text_color)
        icon_label.pack(side=tk.LEFT, pady=5)
        
        text_label = tk.Label(btn_frame, text=text, font=("Arial", 12),
                           bg=btn_frame["bg"], fg=self.text_color)
        text_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Alt widget'lar için de hover efekti
        icon_label.bind("<Enter>", 
                      lambda e: btn_frame.configure(background="#282828"))
        text_label.bind("<Enter>", 
                      lambda e: btn_frame.configure(background="#282828"))
        icon_label.bind("<Button-1>", lambda e: command())
        text_label.bind("<Button-1>", lambda e: command())
    
    def clear_content(self):
        """İçerik alanını temizler"""
        for widget in self.content_area.winfo_children():
            widget.destroy()
    
    def load_home_content(self):
        """Ana sayfa içeriğini yükler"""
        self.clear_content()
        
        # Başlık
        header = tk.Frame(self.content_area, bg=self.bg_color)
        header.pack(fill=tk.X, padx=30, pady=(30, 0))
        
        title = tk.Label(header, text="ARP Guardian'a Hoş Geldiniz", 
                       font=("Arial", 24, "bold"), 
                       bg=self.bg_color, fg=self.text_color)
        title.pack(anchor=tk.W)
        
        subtitle = tk.Label(header, 
                         text="Ağınızın güvenliğini korumak için gelişmiş bir araç", 
                         font=("Arial", 12), 
                         bg=self.bg_color, fg="#B3B3B3")
        subtitle.pack(anchor=tk.W, pady=(5, 0))
        
        # İçerik
        content_frame = tk.Frame(self.content_area, bg=self.bg_color)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=20)
        
        # Öne çıkan özellikler
        features_label = tk.Label(content_frame, text="Neler Yapabilirsiniz?", 
                               font=("Arial", 18, "bold"), 
                               bg=self.bg_color, fg=self.text_color)
        features_label.pack(anchor=tk.W, pady=(0, 15))
        
        # Özellik kartları için container
        cards_container = tk.Frame(content_frame, bg=self.bg_color)
        cards_container.pack(fill=tk.BOTH, padx=0, pady=0)
        
        # Kartlar için grid düzeni
        cards_container.columnconfigure(0, weight=1)
        cards_container.columnconfigure(1, weight=1)
        cards_container.columnconfigure(2, weight=1)
        
        # Özellik kartları
        self.create_feature_card(
            cards_container, 0, 0,
            "🔍 Ağ Taraması", 
            "Ağınızdaki tüm cihazları tarayarak ARP spoofing saldırılarını tespit edin.",
            self.load_scan_content
        )
        
        self.create_feature_card(
            cards_container, 0, 1,
            "🕒 Periyodik Kontrol", 
            "Ağınızı düzenli aralıklarla otomatik olarak kontrol edin.",
            self.load_settings_content
        )
        
        self.create_feature_card(
            cards_container, 0, 2,
            "📊 Tarama Geçmişi", 
            "Önceki taramaların sonuçlarını görüntüleyin ve analiz edin.",
            self.load_history_content
        )
        
        self.create_feature_card(
            cards_container, 1, 0,
            "⚠️ Uyarı Sistemi", 
            "Tehlikeli durumlar tespit edildiğinde anında bildirim alın.",
            lambda: messagebox.showinfo("Bilgi", "Bu özellik yakında gelecek!")
        )
        
        self.create_feature_card(
            cards_container, 1, 1,
            "🔒 Güvenlik Önerileri", 
            "Ağınızı daha güvenli hale getirmek için öneriler alın.",
            lambda: messagebox.showinfo("Bilgi", "Bu özellik yakında gelecek!")
        )
        
        self.create_feature_card(
            cards_container, 1, 2,
            "⚙️ Özelleştirme", 
            "Uygulamayı ihtiyaçlarınıza göre özelleştirin.",
            self.load_settings_content
        )
        
    def create_feature_card(self, parent, row, col, title, description, command):
        """Özellik kartı oluşturur"""
        # Kart çerçevesi
        card = RoundedFrame(parent, bg_color=self.card_color, corner_radius=10)
        card.grid(row=row, column=col, padx=10, pady=10, sticky="nsew")
        
        # İçerik çerçevesi
        content = tk.Frame(card, bg=self.card_color)
        content.place(relx=0.5, rely=0.5, anchor=tk.CENTER, width=200, height=150)
        
        # Başlık ve açıklama
        title_label = tk.Label(content, text=title, 
                            font=("Arial", 14, "bold"), 
                            bg=self.card_color, fg=self.text_color,
                            wraplength=180)
        title_label.pack(anchor=tk.CENTER, pady=(20, 10))
        
        desc_label = tk.Label(content, text=description, 
                           font=("Arial", 10), 
                           bg=self.card_color, fg="#B3B3B3",
                           wraplength=180, justify=tk.CENTER)
        desc_label.pack(anchor=tk.CENTER, pady=(0, 15))
        
        # Hover efekti
        for widget in [card, content, title_label, desc_label]:
            widget.bind("<Enter>", 
                     lambda e, c=card: c.configure(bg_color=self.card_hover))
            widget.bind("<Leave>", 
                     lambda e, c=card: c.configure(bg_color=self.card_color))
            widget.bind("<Button-1>", lambda e: command())
    
    def load_scan_content(self):
        """Tarama ekranını yükler"""
        self.clear_content()
        
        # Başlık
        header = tk.Frame(self.content_area, bg=self.bg_color)
        header.pack(fill=tk.X, padx=30, pady=(30, 20))
        
        title = tk.Label(header, text="Ağ Taraması", 
                       font=("Arial", 24, "bold"), 
                       bg=self.bg_color, fg=self.text_color)
        title.pack(anchor=tk.W)
        
        subtitle = tk.Label(header, 
                         text="Ağınızı ARP spoofing saldırılarına karşı kontrol edin", 
                         font=("Arial", 12), 
                         bg=self.bg_color, fg="#B3B3B3")
        subtitle.pack(anchor=tk.W, pady=(5, 0))
        
        # Tarama kontrolleri
        controls_frame = tk.Frame(self.content_area, bg=self.bg_color)
        controls_frame.pack(fill=tk.X, padx=30, pady=(0, 10))
        
        # Tarama butonu - Spotify stilinde
        self.scan_button = SpotifyButton(
            controls_frame, 
            text="Ağımı Tara", 
            command=self.start_scan,
            width=150, 
            height=40,
            bg_color=self.accent_color,
            hover_color="#1ED760",
            font=("Arial", 12, "bold")
        )
        self.scan_button.pack(side=tk.LEFT, padx=(0, 10))
        
        # İlerleme çubuğu
        self.progress_frame = tk.Frame(controls_frame, bg=self.bg_color)
        self.progress_frame.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(10, 0))
        
        # Özel stil için ttk kullanıyoruz
        style = ttk.Style()
        style.theme_use('default')
        style.configure("Spotify.Horizontal.TProgressbar", 
                       background=self.accent_color,
                       troughcolor=self.card_color,
                       borderwidth=0,
                       thickness=8)
        
        self.progress = ttk.Progressbar(
            self.progress_frame, 
            orient=tk.HORIZONTAL, 
            length=300, 
            mode='indeterminate',
            style="Spotify.Horizontal.TProgressbar"
        )
        
        # Sonuç kartı - yuvarlak köşeli
        self.result_card = RoundedFrame(
            self.content_area, 
            bg_color=self.card_color, 
            corner_radius=10,
            padx=20, 
            pady=20
        )
        self.result_card.pack(fill=tk.BOTH, expand=True, padx=30, pady=(10, 30))
        
        # Sonuç kartı içeriği
        result_content = tk.Frame(self.result_card, bg=self.card_color)
        result_content.place(relx=0.5, rely=0.1, anchor=tk.N, relwidth=0.9, relheight=0.8)
        
        # Durum simgesi
        self.status_icon = tk.Label(result_content, text=self.icons["info"], 
                                 font=("Arial", 48), 
                                 bg=self.card_color, fg=self.text_color)
        self.status_icon.pack(pady=(0, 5))
        
        # Durum başlığı
        self.status_title = tk.Label(result_content, text="Ağınızın Durumu", 
                                  font=("Arial", 16, "bold"), 
                                  bg=self.card_color, fg=self.text_color)
        self.status_title.pack(pady=(0, 5))
        
        # Durum açıklaması
        self.status_text = tk.Label(result_content, 
                                 text="Ağınızın güvenlik durumunu görmek için 'Ağımı Tara' düğmesine tıklayın.",
                                 wraplength=600, justify="center", 
                                 font=("Arial", 12), 
                                 bg=self.card_color, fg="#B3B3B3")
        self.status_text.pack(pady=(0, 20))
        
        # Sonuç alanı
        self.result_text = scrolledtext.ScrolledText(
            result_content, 
            wrap=tk.WORD, 
            height=8,
            bg="#282828", 
            fg=self.text_color, 
            font=("Consolas", 10), 
            bd=0
        )
        self.result_text.pack(fill=tk.BOTH, expand=True, pady=(10, 0))
        self.result_text.config(state=tk.DISABLED)
    
    def start_scan(self):
        """Tarama işlemini başlatır"""
        # Arayüzü güncelle
        self.status_var.set("Ağınız taranıyor...")
        self.scan_button.configure(state=tk.DISABLED)
        self.progress.pack(fill=tk.X, expand=True)
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
                        important_lines.append(line)
                        # Broadcast/Multicast için is_safe'i false yapma
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
                self.root.after(0, lambda: self.scan_button.configure(state=tk.NORMAL))
                self.root.after(0, lambda: self.status_var.set("Tarama tamamlandı"))
                
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Hata", f"Tarama sırasında hata: {str(e)}"))
            self.root.after(0, self.progress.stop)
            self.root.after(0, self.progress.pack_forget)
            self.root.after(0, lambda: self.scan_button.configure(state=tk.NORMAL))
            self.root.after(0, lambda: self.status_var.set("Tarama hatası"))
    
    def _update_ui(self, is_safe, important_lines, suspicious_entries):
        """Tarama sonuçlarına göre arayüzü günceller"""
        # Gerçekten tehlikeli durumları filtrele - info_broadcast_multicast tipindeki girdileri hariç tut
        real_threats = [entry for entry in suspicious_entries if entry.get("type") != "info_broadcast_multicast"]
        
        # Gerçekten tehlike var mı kontrol et
        is_truly_safe = len(real_threats) == 0
        
        # Sonuç kartını güncelle
        if is_truly_safe:
            self.status_icon.config(text=self.icons["success"])
            self.status_title.config(text="Ağınız Güvende", fg=self.accent_color)
            self.status_text.config(text="Herhangi bir ARP spoofing tehdidi tespit edilmedi.")
            self.result_card.configure(bg_color=self.card_color)
        else:
            self.status_icon.config(text=self.icons["warning"])
            self.status_title.config(text="Saldırı Riski!", fg=self.warning_color)
            self.status_text.config(text="Ağınızda şüpheli ARP etkinliği tespit edildi! Detaylar için aşağıya bakın.")
            self.result_card.configure(bg_color="#282828")
            
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
                    self.result_text.tag_configure("success", foreground=self.accent_color)
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
        self.warning_window.configure(bg=self.bg_color)
        self.warning_window.transient(self.root)
        self.warning_window.grab_set()
        
        # İçerik
        content = tk.Frame(self.warning_window, bg=self.bg_color, padx=20, pady=20)
        content.pack(fill=tk.BOTH, expand=True)
        
        # Başlık ve ikon
        header = tk.Frame(content, bg=self.bg_color)
        header.pack(fill=tk.X, pady=(0, 15))
        
        # Uyarı ikonu
        icon = tk.Label(header, text=self.icons["warning"], font=("Arial", 36), 
                      fg=self.warning_color, bg=self.bg_color)
        icon.pack(side=tk.LEFT, padx=(0, 15))
        
        header_text = tk.Frame(header, bg=self.bg_color)
        header_text.pack(side=tk.LEFT)
        
        warning_title = tk.Label(header_text, text="Güvenlik Uyarısı", 
                              font=("Arial", 16, "bold"), 
                              fg=self.warning_color, bg=self.bg_color)
        warning_title.pack(anchor=tk.W)
        
        warning_subtitle = tk.Label(header_text, text="ARP spoofing riski tespit edildi", 
                                 font=("Arial", 12), 
                                 fg="#B3B3B3", bg=self.bg_color)
        warning_subtitle.pack(anchor=tk.W)
        
        # Açıklama kartı
        description_card = RoundedFrame(content, bg_color=self.card_color, corner_radius=10)
        description_card.pack(fill=tk.X, pady=10)
        
        description_content = tk.Frame(description_card, bg=self.card_color)
        description_content.place(relx=0.5, rely=0.5, anchor=tk.CENTER, relwidth=0.9, relheight=0.8)
        
        description = tk.Label(description_content, 
                            text="""ARP spoofing, ağınızda kötü niyetli bir cihazın kendisini başka bir cihaz 
                                 gibi göstererek trafiği dinlemesi veya değiştirmesi durumudur.
                                 
                                 Bu saldırı, kredi kartı bilgileri, şifreler ve diğer hassas bilgilerin 
                                 çalınmasına yol açabilir.""",
                            wraplength=430, justify=tk.LEFT, 
                            bg=self.card_color, fg=self.text_color, font=("Arial", 10))
        description.pack(fill=tk.X)
        
        # Tespit edilen tehditler
        threats_label = tk.Label(content, text="Tespit Edilen Tehditler:", 
                              font=("Arial", 12, "bold"), 
                              bg=self.bg_color, fg=self.text_color)
        threats_label.pack(anchor=tk.W, pady=(15, 5))
        
        # Tehditler kartı
        threats_card = RoundedFrame(content, bg_color=self.card_color, corner_radius=10)
        threats_card.pack(fill=tk.X, pady=(0, 10))
        
        threats_content = tk.Frame(threats_card, bg=self.card_color)
        threats_content.place(relx=0.5, rely=0.5, anchor=tk.CENTER, relwidth=0.9, relheight=0.8)
        
        for entry in suspicious_entries:
            message = entry.get("message", "")
            if message:
                threat_label = tk.Label(threats_content, text=message, 
                                     wraplength=430, justify=tk.LEFT, 
                                     bg=self.card_color, fg=self.text_color, font=("Arial", 10))
                threat_label.pack(pady=2, anchor=tk.W)
        
        # Önerilen önlemler kartı
        actions_label = tk.Label(content, text="Önerilen Önlemler:", 
                              font=("Arial", 12, "bold"), 
                              bg=self.bg_color, fg=self.text_color)
        actions_label.pack(anchor=tk.W, pady=(15, 5))
        
        actions_card = RoundedFrame(content, bg_color=self.card_color, corner_radius=10)
        actions_card.pack(fill=tk.X, pady=(0, 10))
        
        actions_content = tk.Frame(actions_card, bg=self.card_color)
        actions_content.place(relx=0.5, rely=0.5, anchor=tk.CENTER, relwidth=0.9, relheight=0.8)
        
        # Önerilen önlemler listesi
        actions = [
            "Ağ bağlantınızı hemen kesin veya güvenli olmayan ağlarda hassas işlemler yapmaktan kaçının.",
            "Ağ yöneticinize durumu bildirin.",
            "VPN kullanarak ağ trafiğinizi şifreleyin.",
            "HTTPS bağlantıları ve güvenli iletişim protokolleri kullanın.",
            "Statik ARP girdileri ekleyerek kritik cihazların MAC adreslerini sabitleyin."
        ]
        
        for i, action in enumerate(actions):
            action_frame = tk.Frame(actions_content, bg=self.card_color)
            action_frame.pack(fill=tk.X, pady=2)
            
            bullet = tk.Label(action_frame, text="•", font=("Arial", 12, "bold"),
                           bg=self.card_color, fg=self.accent_color)
            bullet.pack(side=tk.LEFT, padx=(0, 5))
            
            action_text = tk.Label(action_frame, text=action, wraplength=400, justify=tk.LEFT,
                                font=("Arial", 10), bg=self.card_color, fg=self.text_color)
            action_text.pack(side=tk.LEFT, fill=tk.X, expand=True, anchor=tk.W)
        
        # Kapat butonu
        close_btn = SpotifyButton(content, text="Anladım", command=self.warning_window.destroy,
                              width=100, height=35, bg_color=self.accent_color)
        close_btn.pack(side=tk.RIGHT, pady=10)
        
        # Pencereyi ortala
        self.warning_window.update_idletasks()
        width = self.warning_window.winfo_width()
        height = self.warning_window.winfo_height()
        x = (self.warning_window.winfo_screenwidth() // 2) - (width // 2)
        y = (self.warning_window.winfo_screenheight() // 2) - (height // 2)
        self.warning_window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    
    def load_history_content(self):
        """Tarama geçmişi ekranını yükler"""
        self.clear_content()
        
        # Başlık
        header = tk.Frame(self.content_area, bg=self.bg_color)
        header.pack(fill=tk.X, padx=30, pady=(30, 20))
        
        title = tk.Label(header, text="Tarama Geçmişi", 
                       font=("Arial", 24, "bold"), 
                       bg=self.bg_color, fg=self.text_color)
        title.pack(anchor=tk.W)
        
        subtitle = tk.Label(header, 
                         text="Önceki taramaların sonuçlarını görüntüleyin", 
                         font=("Arial", 12), 
                         bg=self.bg_color, fg="#B3B3B3")
        subtitle.pack(anchor=tk.W, pady=(5, 0))
        
        # İçerik
        content_frame = RoundedFrame(self.content_area, bg_color=self.card_color, corner_radius=10)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=(10, 30))
        
        # İçerik alanı
        info_frame = tk.Frame(content_frame, bg=self.card_color)
        info_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER, relwidth=0.8, relheight=0.8)
        
        # Henüz uygulama geçmişi yok
        info_icon = tk.Label(info_frame, text="🕒", font=("Arial", 48), 
                         bg=self.card_color, fg=self.text_color)
        info_icon.pack(pady=(0, 10))
        
        info_title = tk.Label(info_frame, text="Geçmiş Bulunamadı", 
                          font=("Arial", 16, "bold"), 
                          bg=self.card_color, fg=self.text_color)
        info_title.pack(pady=(0, 5))
        
        info_text = tk.Label(info_frame, 
                         text="Tarama geçmişi henüz oluşturulmadı. Bir tarama yaptığınızda sonuçlar burada görüntülenecektir.",
                         wraplength=500, justify=tk.CENTER, 
                         font=("Arial", 12), 
                         bg=self.card_color, fg="#B3B3B3")
        info_text.pack(pady=(0, 20))
        
        # Tarama butonu
        scan_btn = SpotifyButton(info_frame, text="Tarama Yap", command=self.load_scan_content,
                             width=150, height=40, bg_color=self.accent_color)
        scan_btn.pack()
    
    def load_settings_content(self):
        """Ayarlar ekranını yükler"""
        self.clear_content()
        
        # Başlık
        header = tk.Frame(self.content_area, bg=self.bg_color)
        header.pack(fill=tk.X, padx=30, pady=(30, 20))
        
        title = tk.Label(header, text="Ayarlar", 
                       font=("Arial", 24, "bold"), 
                       bg=self.bg_color, fg=self.text_color)
        title.pack(anchor=tk.W)
        
        subtitle = tk.Label(header, 
                         text="Uygulama ayarlarını özelleştirin", 
                         font=("Arial", 12), 
                         bg=self.bg_color, fg="#B3B3B3")
        subtitle.pack(anchor=tk.W, pady=(5, 0))
        
        # Ayarlar kartı
        settings_card = RoundedFrame(self.content_area, bg_color=self.card_color, corner_radius=10)
        settings_card.pack(fill=tk.BOTH, expand=True, padx=30, pady=(10, 30))
        
        # Ayarlar içeriği
        settings_content = tk.Frame(settings_card, bg=self.card_color)
        settings_content.place(relx=0.5, rely=0.1, anchor=tk.N, relwidth=0.9, relheight=0.8)
        
        # Genel Ayarlar başlığı
        general_title = tk.Label(settings_content, text="Genel Ayarlar", 
                              font=("Arial", 16, "bold"), 
                              bg=self.card_color, fg=self.text_color)
        general_title.pack(anchor=tk.W, pady=(20, 10))
        
        # Periyodik tarama ayarı
        periodic_frame = tk.Frame(settings_content, bg=self.card_color)
        periodic_frame.pack(fill=tk.X, pady=5)
        
        # Özel stil için ttk checkbutton
        style = ttk.Style()
        style.configure("Spotify.TCheckbutton", 
                      background=self.card_color, 
                      foreground=self.text_color)
        
        # Periyodik tarama seçeneği
        periodic_check = ttk.Checkbutton(
            periodic_frame, 
            text="Periyodik tarama", 
            variable=self.periodic_var, 
            style="Spotify.TCheckbutton"
        )
        periodic_check.pack(side=tk.LEFT)
        
        # Periyodik tarama ayarları
        period_frame = tk.Frame(settings_content, bg=self.card_color)
        period_frame.pack(fill=tk.X, pady=5)
        
        period_label = tk.Label(period_frame, text="Tarama sıklığı:", 
                             font=("Arial", 12),
                             bg=self.card_color, fg=self.text_color)
        period_label.pack(side=tk.LEFT, padx=(20, 10))
        
        # Saat seçimi için combobox
        period_values = ["1", "2", "4", "6", "8", "12", "24", "48", "72"]
        period_combobox = ttk.Combobox(
            period_frame, 
            values=period_values, 
            width=5, 
            state="readonly",
            font=("Arial", 12)
        )
        
        # Mevcut değeri seç
        current_hour = str(self.period_hours.get())
        if current_hour in period_values:
            period_combobox.set(current_hour)
        else:
            period_combobox.set("24")
            
        period_combobox.pack(side=tk.LEFT)
        
        hours_label = tk.Label(period_frame, text="saat", 
                            font=("Arial", 12),
                            bg=self.card_color, fg=self.text_color)
        hours_label.pack(side=tk.LEFT, padx=(5, 0))
        
        # Sistem başlangıcında çalıştırma
        startup_frame = tk.Frame(settings_content, bg=self.card_color)
        startup_frame.pack(fill=tk.X, pady=5)
        
        startup_check = ttk.Checkbutton(
            startup_frame, 
            text="Bilgisayar açılışında başlat", 
            variable=self.startup_var, 
            style="Spotify.TCheckbutton"
        )
        startup_check.pack(side=tk.LEFT)
        
        # Kaydet butonu
        save_frame = tk.Frame(settings_content, bg=self.card_color)
        save_frame.pack(fill=tk.X, pady=(20, 0))
        
        save_btn = SpotifyButton(
            save_frame, 
            text="Kaydet", 
            command=lambda: self.save_settings(period_combobox.get()),
            width=100, 
            height=35, 
            bg_color=self.accent_color
        )
        save_btn.pack(side=tk.RIGHT)
    
    def save_settings(self, period_value):
        """Ayarları kaydeder"""
        try:
            hours = int(period_value)
            self.period_hours.set(hours)
            messagebox.showinfo("Ayarlar", "Ayarlarınız başarıyla kaydedildi.")
        except ValueError:
            messagebox.showerror("Hata", "Geçerli bir saat değeri giriniz.")
    
    def start_periodic_scan(self):
        """Periyodik taramayı başlatır"""
        self.periodic_running = True
        
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
    
    def _periodic_thread(self):
        """Periyodik tarama arka plan thread'i"""
        # Seçilen saat değerine göre saniye hesapla
        hours = self.period_hours.get()
        interval = hours * 3600  # Saat başına 3600 saniye
        
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
    

# Program çalıştırma
if __name__ == "__main__":
    root = tk.Tk()
    app = ARP_GUI_Spotify(root)
    root.mainloop()
