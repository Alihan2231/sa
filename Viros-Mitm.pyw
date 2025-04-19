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
import json
import datetime
import math
import random

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

# Geçmiş verilerini saklama ve yükleme
def save_scan_history(scan_result, is_safe):
    """Tarama sonucunu geçmişe kaydeder"""
    history_file = os.path.join(tempfile.gettempdir(), "arp_scanner_history.json")
    
    # Mevcut geçmişi yükle
    if os.path.exists(history_file):
        try:
            with open(history_file, 'r', encoding='utf-8') as f:
                history = json.load(f)
        except:
            history = []
    else:
        history = []
    
    # Yeni sonucu ekle
    new_entry = {
        "date": datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "result": scan_result,
        "is_safe": is_safe
    }
    
    history.append(new_entry)
    
    # Maksimum 100 kayıt tut
    if len(history) > 100:
        history = history[-100:]
    
    # Geçmişi kaydet
    try:
        with open(history_file, 'w', encoding='utf-8') as f:
            json.dump(history, f, ensure_ascii=False, indent=2)
    except Exception as e:
        print(f"Geçmiş kaydedilirken hata oluştu: {e}")

def load_scan_history():
    """Tarama geçmişini yükler"""
    history_file = os.path.join(tempfile.gettempdir(), "arp_scanner_history.json")
    
    if os.path.exists(history_file):
        try:
            with open(history_file, 'r', encoding='utf-8') as f:
                history = json.load(f)
            return history
        except Exception as e:
            print(f"Geçmiş yüklenirken hata oluştu: {e}")
    
    return []


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
        self.animation_id = None
        self.state = tk.NORMAL
        
        # Buton çiz
        self.button_shape = self.rounded_rect(0, 0, width, height, corner_radius, bg_color)
        self.button_text = self.create_text(width/2, height/2, text=text, 
                                         fill=text_color, font=font)
        
        # Mouse olayları
        self.bind("<Enter>", self._on_enter)
        self.bind("<Leave>", self._on_leave)
        self.bind("<Button-1>", self._on_click)
    
    def configure(self, **kwargs):
        """Buton özelliklerini yapılandırır"""
        if "state" in kwargs:
            self.state = kwargs["state"]
            if self.state == tk.DISABLED:
                self.itemconfig(self.button_shape, fill="#666666")
            else:
                self.itemconfig(self.button_shape, fill=self.bg_color)
        
        if "text" in kwargs:
            self.text = kwargs["text"]
            self.itemconfig(self.button_text, text=self.text)
    
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
        if self.state == tk.NORMAL:
            self._animate_hover(0)
    
    def _on_leave(self, event):
        """Mouse butondan ayrıldığında"""
        if self.state == tk.NORMAL:
            self._animate_hover(1)
    
    def _animate_hover(self, direction):
        """Hover animasyonunu yapar"""
        if self.animation_id:
            self.after_cancel(self.animation_id)
            self.animation_id = None
        
        if direction == 0:  # Mouse üzerine geldiğinde
            steps = 10
            current_color = self.bg_color
            target_color = self.hover_color
        else:  # Mouse ayrıldığında
            steps = 7
            current_color = self.hover_color
            target_color = self.bg_color
        
        def interpolate_color(start_rgb, end_rgb, steps, step):
            """İki renk arasında geçiş yapar"""
            r1, g1, b1 = int(start_rgb[1:3], 16), int(start_rgb[3:5], 16), int(start_rgb[5:7], 16)
            r2, g2, b2 = int(end_rgb[1:3], 16), int(end_rgb[3:5], 16), int(end_rgb[5:7], 16)
            
            r = r1 + (r2 - r1) * step / steps
            g = g1 + (g2 - g1) * step / steps
            b = b1 + (b2 - b1) * step / steps
            
            return f'#{int(r):02x}{int(g):02x}{int(b):02x}'
        
        def animate(step=0):
            """Animasyon kareleri"""
            if step <= steps:
                color = interpolate_color(current_color, target_color, steps, step)
                self.itemconfig(self.button_shape, fill=color)
                self.animation_id = self.after(20, lambda: animate(step + 1))
            else:
                self.animation_id = None
        
        animate()
    
    def _on_click(self, event):
        """Butona tıklandığında"""
        if self.state == tk.NORMAL and self.command:
            # Tıklama animasyonunu başlat
            self._animate_click()
            self.after(200, self.command)
    
    def _animate_click(self):
        """Tıklama animasyonu - butonun boyutunu küçültüp büyütür"""
        original_width = self.winfo_width()
        original_height = self.winfo_height()
        
        # Küçültme adımları
        steps = 5
        for i in range(1, steps + 1):
            scale = 1 - 0.03 * i
            new_width = int(original_width * scale)
            new_height = int(original_height * scale)
            
            # Merkezde tut
            padding_x = (original_width - new_width) // 2
            padding_y = (original_height - new_height) // 2
            
            self.coords(self.button_shape, 
                     padding_x, padding_y, 
                     original_width - padding_x, original_height - padding_y)
            
            # Metni ortala
            self.coords(self.button_text, original_width // 2, original_height // 2)
            
            self.update()
            self.after(20)
        
        # Geri büyütme adımları
        for i in range(steps, 0, -1):
            scale = 1 - 0.03 * i
            new_width = int(original_width * scale)
            new_height = int(original_height * scale)
            
            # Merkezde tut
            padding_x = (original_width - new_width) // 2
            padding_y = (original_height - new_height) // 2
            
            self.coords(self.button_shape, 
                     padding_x, padding_y, 
                     original_width - padding_x, original_height - padding_y)
            
            # Metni ortala
            self.coords(self.button_text, original_width // 2, original_height // 2)
            
            self.update()
            self.after(20)
        
        # Orijinal boyutu geri yükle
        self.coords(self.button_shape, 0, 0, original_width, original_height)
        self.coords(self.button_text, original_width // 2, original_height // 2)

# Animasyonlu daire ilerleme çubuğu
class CircularProgressbar(tk.Canvas):
    def __init__(self, parent, width=100, height=100, max_value=100, 
                 bg_color="#121212", fg_color="#1DB954", text_color="#FFFFFF",
                 outline_width=8, font=("Arial", 20), **kwargs):
        super().__init__(parent, width=width, height=height, 
                       bg=bg_color, highlightthickness=0, **kwargs)
        
        self.max_value = max_value
        self.current_value = 0
        self.bg_color = bg_color
        self.fg_color = fg_color
        self.text_color = text_color
        self.outline_width = outline_width
        self.font = font
        
        # Daire merkezi ve yarıçapı
        self.center_x = width // 2
        self.center_y = height // 2
        self.radius = min(width, height) // 2 - outline_width
        
        # Arka plan dairesi
        self.bg_circle = self.create_oval(
            self.center_x - self.radius,
            self.center_y - self.radius,
            self.center_x + self.radius,
            self.center_y + self.radius,
            outline="#333333",
            width=outline_width,
            fill=bg_color
        )
        
        # İlerleme yayı
        self.progress_arc = None
        
        # Yüzde metni
        self.text_item = self.create_text(
            self.center_x,
            self.center_y,
            text="0%",
            font=font,
            fill=text_color
        )
        
        # İlk çizim
        self.update_progress(0)
    
    def update_progress(self, value):
        """İlerleme çubuğunu günceller"""
        # Değeri sınırla
        value = max(0, min(value, self.max_value))
        self.current_value = value
        
        # Yüzde hesapla
        percentage = int((value / self.max_value) * 100)
        
        # Metni güncelle
        self.itemconfig(self.text_item, text=f"{percentage}%")
        
        # Açıyı hesapla (360 derece tam daire)
        angle = (value / self.max_value) * 360
        
        # Önceki yayı sil
        if self.progress_arc:
            self.delete(self.progress_arc)
        
        # Boş yay çizme için 0.1 değeri
        if angle <= 0.1:
            angle = 0.1
        
        # İlerleme yayını çiz
        start_angle = 90  # Başlangıç açısı (saat 12 pozisyonu)
        self.progress_arc = self.create_arc(
            self.center_x - self.radius,
            self.center_y - self.radius,
            self.center_x + self.radius,
            self.center_y + self.radius,
            start=start_angle,
            extent=-angle,  # Saat yönünün tersine
            outline=self.fg_color,
            width=self.outline_width,
            style="arc"
        )
    
    def animate_to(self, target_value, duration=1000, steps=30):
        """Hedef değere animasyonlu geçiş yapar"""
        start_value = self.current_value
        value_change = target_value - start_value
        step_time = duration / steps
        
        def update_step(step):
            if step <= steps:
                # Easing fonksiyonu - yavaşlayan hareket
                t = step / steps
                ease = 1 - (1 - t) * (1 - t)  # Ease-out quad
                
                # Yeni değer
                new_value = start_value + (value_change * ease)
                self.update_progress(new_value)
                
                # Sonraki adım
                self.after(int(step_time), lambda: update_step(step + 1))
        
        update_step(0)

# Animasyonlu grafik
class AnimatedChart(tk.Canvas):
    def __init__(self, parent, width=400, height=200, data=None, 
                 bg_color="#121212", line_color="#1DB954", **kwargs):
        super().__init__(parent, width=width, height=height, 
                       bg=bg_color, highlightthickness=0, **kwargs)
        
        self.width = width
        self.height = height
        self.bg_color = bg_color
        self.line_color = line_color
        self.data = data or []
        self.max_points = 20  # Maksimum gösterilecek veri noktası
        self.line_id = None
        self.point_ids = []
        self.animation_step = 0
        
        # Eksenleri çiz
        self._draw_axes()
        
        # Veri varsa çiz
        if self.data:
            self.animate_draw()
    
    def _draw_axes(self):
        """X ve Y eksenlerini çizer"""
        # X ekseni
        self.create_line(
            30, self.height - 30,  # Başlangıç noktası
            self.width - 20, self.height - 30,  # Bitiş noktası
            fill="#666666",
            width=1
        )
        
        # Y ekseni
        self.create_line(
            30, self.height - 30,  # Başlangıç noktası
            30, 20,  # Bitiş noktası
            fill="#666666",
            width=1
        )
    
    def set_data(self, data):
        """Grafik verilerini ayarlar"""
        self.data = data[-self.max_points:] if len(data) > self.max_points else data
        self.delete("chart")  # Önceki grafiği temizle
        self.animation_step = 0
        self.point_ids = []
        self.line_id = None
        self.animate_draw()
    
    def animate_draw(self):
        """Grafiği animasyonlu olarak çizer"""
        if not self.data:
            return
            
        # Verilerin maks ve min değerlerini bul
        values = [point["value"] for point in self.data]
        max_value = max(values) if values else 0
        min_value = min(values) if values else 0
        
        # Sıfırdan küçükse, sıfır min_value olsun
        min_value = min(0, min_value)
        
        # Değer aralığı çok küçükse, görselleştirme için aralığı genişlet
        if max_value - min_value < 10:
            max_value += 5
            min_value -= 5
        
        # Koordinat hesaplama fonksiyonu
        def get_point_coords(idx, value):
            # X koordinatı, noktalar arasında eşit aralık
            x_step = (self.width - 50) / (len(self.data) - 1) if len(self.data) > 1 else 0
            x = 30 + idx * x_step
            
            # Y koordinatı, değeri eksen üzerine ölçekle
            value_range = max_value - min_value
            if value_range == 0:  # Sıfıra bölmeyi önle
                y_ratio = 0
            else:
                y_ratio = (value - min_value) / value_range
            
            y = self.height - 30 - (y_ratio * (self.height - 50))
            return x, y
        
        # Animasyonun bu adımında çizilecek nokta sayısı
        points_to_draw = min(len(self.data), self.animation_step + 1)
        
        # Mevcut çizgileri ve noktaları temizle
        if self.line_id:
            self.delete(self.line_id)
        for point_id in self.point_ids:
            self.delete(point_id)
        
        # Noktaları ve çizgileri çiz
        coords = []
        self.point_ids = []
        
        for i in range(points_to_draw):
            point = self.data[i]
            x, y = get_point_coords(i, point["value"])
            coords.extend([x, y])
            
            # Nokta çiz
            color = "#34A853" if point.get("is_safe", True) else "#EA4335"
            point_id = self.create_oval(x-4, y-4, x+4, y+4, fill=color, outline="", tags="chart")
            self.point_ids.append(point_id)
            
            # Nokta etiketi
            date_label = point.get("date", "").split()[0]  # Sadece tarihi al
            if i % 3 == 0 or i == len(self.data) - 1:  # Her 3 noktada bir ve son noktada etiket
                self.create_text(x, self.height - 15, text=date_label, 
                              fill="#999999", font=("Arial", 8), tags="chart")
        
        # Çizgiyi çiz
        if len(coords) >= 4:  # En az 2 nokta olmalı
            self.line_id = self.create_line(coords, fill=self.line_color, width=2, smooth=True, tags="chart")
        
        # Animasyonu devam ettir
        if self.animation_step < len(self.data) - 1:
            self.animation_step += 1
            self.after(100, self.animate_draw)
        else:
            # Son noktanın detaylarını göster
            if self.data:
                last_point = self.data[-1]
                last_x, last_y = get_point_coords(len(self.data) - 1, last_point["value"])
                self.create_text(
                    last_x, last_y - 15, 
                    text=f"{last_point['value']}",
                    fill="#FFFFFF", 
                    font=("Arial", 9, "bold"),
                    tags="chart"
                )

# Animasyonlu kayan panel
class SlidePanel(tk.Frame):
    def __init__(self, parent, start_pos, end_pos, width, height, bg_color="#121212", **kwargs):
        super().__init__(parent, width=width, height=height, bg=bg_color, **kwargs)
        
        self.parent = parent
        self.start_pos = start_pos
        self.end_pos = end_pos
        self.width = width
        self.height = height
        self.current_pos = start_pos
        self.animation_id = None
        
        # Paneli başlangıç pozisyonuna yerleştir
        self.place(x=start_pos[0], y=start_pos[1], width=width, height=height)
    
    def slide_in(self, duration=500):
        """Paneli içeri kaydır"""
        self._animate_slide(self.start_pos, self.end_pos, duration)
    
    def slide_out(self, duration=500):
        """Paneli dışarı kaydır"""
        self._animate_slide(self.end_pos, self.start_pos, duration)
    
    def _animate_slide(self, start, end, duration):
        """Kayma animasyonunu gerçekleştirir"""
        if self.animation_id:
            self.after_cancel(self.animation_id)
        
        steps = 20
        step_time = duration / steps
        start_x, start_y = start
        end_x, end_y = end
        dx, dy = end_x - start_x, end_y - start_y
        
        def update_step(step):
            if step <= steps:
                # Easing fonksiyonu - yavaşlayan hareket
                t = step / steps
                ease = 1 - (1 - t) * (1 - t)  # Ease-out quad
                
                # Yeni konum
                new_x = start_x + (dx * ease)
                new_y = start_y + (dy * ease)
                
                # Paneli yerleştir
                self.place(x=new_x, y=new_y, width=self.width, height=self.height)
                self.current_pos = (new_x, new_y)
                
                # Sonraki adım
                self.animation_id = self.after(int(step_time), lambda: update_step(step + 1))
            else:
                self.animation_id = None
        
        update_step(0)

# Parçacık animasyonu canvas'ı
class ParticleAnimationCanvas(tk.Canvas):
    def __init__(self, parent, width, height, bg_color="#121212", **kwargs):
        super().__init__(parent, width=width, height=height, 
                       bg=bg_color, highlightthickness=0, **kwargs)
        
        self.width = width
        self.height = height
        self.bg_color = bg_color
        self.particles = []
        self.running = False
        self.animation_speed = 30  # ms
        
        # Transparan bir poligon oluştur (arka planı ayarlamak için)
        self.create_polygon(0, 0, width, 0, width, height, 0, height, 
                         fill=bg_color, outline="")
    
    def start_animation(self, particle_count=30):
        """Parçacık animasyonunu başlatır"""
        if self.running:
            return
        
        self.running = True
        
        # Parçacıkları oluştur
        for _ in range(particle_count):
            self._create_random_particle()
        
        # Animasyonu başlat
        self._animate()
    
    def stop_animation(self):
        """Animasyonu durdurur"""
        self.running = False
    
    def _create_random_particle(self):
        """Rastgele bir parçacık oluşturur"""
        x = random.randint(0, self.width)
        y = random.randint(0, self.height)
        size = random.randint(2, 5)
        speed = random.uniform(0.5, 2.0)
        angle = random.uniform(0, 2 * math.pi)
        velocity = (speed * math.cos(angle), speed * math.sin(angle))
        alpha = random.uniform(0.3, 0.7)
        
        # Spotify yeşilinin tonlarını kullan
        color_base = "#1DB954"
        r, g, b = int(color_base[1:3], 16), int(color_base[3:5], 16), int(color_base[5:7], 16)
        variation = random.randint(-20, 20)
        r = max(0, min(255, r + variation))
        g = max(0, min(255, g + variation))
        b = max(0, min(255, b + variation))
        color = f"#{r:02x}{g:02x}{b:02x}"
        
        # Oval parçacık çiz
        particle_id = self.create_oval(x-size, y-size, x+size, y+size, 
                                     fill=color, outline="", 
                                     stipple="gray50")  # Yarı saydam için stipple
        
        # Parçacık bilgilerini sakla
        self.particles.append({
            "id": particle_id,
            "x": x,
            "y": y,
            "size": size,
            "velocity": velocity,
            "color": color,
            "alpha": alpha,
            "age": 0,
            "max_age": random.randint(100, 200)
        })
    
    def _animate(self):
        """Parçacıkları hareket ettirir"""
        if not self.running:
            return
        
        # Parçacıkları güncelle
        for particle in self.particles[:]:
            # Pozisyonu güncelle
            particle["x"] += particle["velocity"][0]
            particle["y"] += particle["velocity"][1]
            
            # Yaşı artır
            particle["age"] += 1
            
            # Yaşlandıkça saydamlığı azalt
            remaining_life = 1 - (particle["age"] / particle["max_age"])
            
            # Parçacığı hareket ettir
            self.coords(
                particle["id"],
                particle["x"] - particle["size"],
                particle["y"] - particle["size"],
                particle["x"] + particle["size"],
                particle["y"] + particle["size"]
            )
            
            # Ekrandan çıkarsa veya yaşam süresi dolduysa yenisiyle değiştir
            if (particle["x"] < -10 or particle["x"] > self.width + 10 or
                particle["y"] < -10 or particle["y"] > self.height + 10 or
                particle["age"] >= particle["max_age"]):
                
                # Eski parçacığı sil
                self.delete(particle["id"])
                self.particles.remove(particle)
                
                # Yeni parçacık ekle
                self._create_random_particle()
        
        # Sonraki kareyi çiz
        self.after(self.animation_speed, self._animate)

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
        
        # Uygulama ikonları (SVG yerine Unicode emojiler kullanılıyor)
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
        
        # Parçacık animasyonunu başlat
        self.particles = ParticleAnimationCanvas(self.content_area, 600, 400, bg_color=self.bg_color)
        
        # İçerikleri yükle
        self.load_home_content()
        
        # Arka plan tarama değişkenleri
        self.periodic_running = False
        self.periodic_thread = None
        self.warning_window = None
        self.periodic_var = tk.BooleanVar()
        self.startup_var = tk.BooleanVar()
        self.period_hours = tk.IntVar(value=24)  # Varsayılan 24 saat
        
        # Aktivite göstergeleri
        self.scan_count = 0
        self.threat_count = 0
        self.last_scan_time = None
        
        # Tema animasyonu
        self.root.after(100, lambda: self._animate_startup())
    
    def _animate_startup(self):
        """Başlangıç animasyonunu oynatır"""
        # Sidebar itemlerini sırayla göster
        for i, child in enumerate(self.sidebar.winfo_children()):
            if isinstance(child, tk.Frame):
                child.configure(bg="#000000")  # Başlangıçta görünmez
                
                # Gecikme hesapla
                delay = 100 + (i * 100)
                
                # Animasyonu başlat
                self.root.after(delay, lambda c=child: self._fade_in(c))
        
        # Parçacık animasyonu
        particles = ParticleAnimationCanvas(self.content_area, 800, 400, bg_color=self.bg_color)
        particles.place(x=0, y=0, relwidth=1, relheight=1)
        particles.start_animation(50)
        
        # 3 saniye sonra animasyonu durdur
        self.root.after(3000, particles.stop_animation)
        self.root.after(3500, particles.destroy)
    
    def _fade_in(self, widget, step=0, steps=10):
        """Widget'ı kademeli olarak gösterir"""
        if step <= steps:
            # Renk interpolasyonu
            r, g, b = 0, 0, 0  # Başlangıç rengi (siyah)
            target_r, target_g, target_b = 0, 0, 0  # Hedef renk (sidebar_color - siyah)
            
            # Geçiş oranı
            ratio = step / steps
            
            # Yeni renk
            new_r = int(r + (target_r - r) * ratio)
            new_g = int(g + (target_g - g) * ratio)
            new_b = int(b + (target_b - b) * ratio)
            
            # Opacity için stipple pattern kullan (daha çok görünür yap)
            if step < steps / 2:
                stipple = "gray75"
            elif step < steps * 0.8:
                stipple = "gray50"
            else:
                stipple = "gray25"
            
            # Rengi uygula
            widget.configure(bg=f'#{new_r:02x}{new_g:02x}{new_b:02x}')
            
            # Çocuk widgetlar
            for child in widget.winfo_children():
                if isinstance(child, tk.Label):
                    # Opaklığı ayarla
                    opacity = ratio
                    intensity = int(255 * opacity)
                    fg_color = f'#{intensity:02x}{intensity:02x}{intensity:02x}'
                    child.configure(fg=fg_color)
            
            # Sonraki adım
            self.root.after(30, lambda: self._fade_in(widget, step + 1, steps))
        else:
            # Son adım - normal renklere döndür
            widget.configure(bg=self.sidebar_color)
            
            # Çocuk widgetlar
            for child in widget.winfo_children():
                if isinstance(child, tk.Label):
                    child.configure(fg=self.text_color)
    
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
        btn_frame.bind("<Button-1>", lambda e: self._animate_sidebar_click(btn_frame, command))
        btn_frame.bind("<Enter>", 
                     lambda e: self._animate_sidebar_hover(btn_frame, True))
        btn_frame.bind("<Leave>", 
                     lambda e: self._animate_sidebar_hover(btn_frame, False))
        
        # Buton içeriği
        icon_label = tk.Label(btn_frame, text=icon, font=("Arial", 14),
                           bg=btn_frame["bg"], fg=self.text_color)
        icon_label.pack(side=tk.LEFT, pady=5)
        
        text_label = tk.Label(btn_frame, text=text, font=("Arial", 12),
                           bg=btn_frame["bg"], fg=self.text_color)
        text_label.pack(side=tk.LEFT, padx=10, pady=5)
        
        # Alt widget'lar için de hover efekti
        icon_label.bind("<Enter>", 
                      lambda e: self._animate_sidebar_hover(btn_frame, True))
        text_label.bind("<Enter>", 
                      lambda e: self._animate_sidebar_hover(btn_frame, True))
        icon_label.bind("<Button-1>", 
                      lambda e: self._animate_sidebar_click(btn_frame, command))
        text_label.bind("<Button-1>", 
                      lambda e: self._animate_sidebar_click(btn_frame, command))
    
    def _animate_sidebar_hover(self, frame, enter):
        """Sidebar butonuna hover animasyonu ekler"""
        target_color = "#282828" if enter else self.sidebar_color
        current_color = frame["bg"]
        
        steps = 8
        
        def interpolate_color(start_color, end_color, step, steps):
            r1, g1, b1 = int(start_color[1:3], 16), int(start_color[3:5], 16), int(start_color[5:7], 16)
            r2, g2, b2 = int(end_color[1:3], 16), int(end_color[3:5], 16), int(end_color[5:7], 16)
            
            r = r1 + (r2 - r1) * step / steps
            g = g1 + (g2 - g1) * step / steps
            b = b1 + (b2 - b1) * step / steps
            
            return f'#{int(r):02x}{int(g):02x}{int(b):02x}'
        
        def animate_step(step):
            if step <= steps:
                color = interpolate_color(current_color, target_color, step, steps)
                frame.configure(background=color)
                
                # Alt widget'ların rengini de güncelle
                for child in frame.winfo_children():
                    child.configure(background=color)
                
                frame.after(20, lambda: animate_step(step + 1))
        
        animate_step(1)
    
    def _animate_sidebar_click(self, frame, command):
        """Sidebar butona tıklama animasyonu ekler"""
        original_bg = frame["bg"]
        target_bg = self.accent_color
        
        # Kısa bir parlaklık efekti
        frame.configure(background=target_bg)
        for child in frame.winfo_children():
            child.configure(background=target_bg)
        
        # Orijinal renge geri dön
        self.root.after(150, lambda: frame.configure(background=original_bg))
        self.root.after(150, lambda: [child.configure(background=original_bg) for child in frame.winfo_children()])
        
        # Komutu çalıştır
        self.root.after(150, command)
    
    def clear_content(self):
        """İçerik alanını temizler"""
        for widget in self.content_area.winfo_children():
            widget.destroy()
    
    def load_home_content(self):
        """Ana sayfa içeriğini yükler"""
        self.clear_content()
        
        # Parçacık animasyonu başlat
        particles = ParticleAnimationCanvas(self.content_area, 800, 400, bg_color=self.bg_color)
        particles.place(x=0, y=0, relwidth=1, relheight=1)
        particles.start_animation(30)
        
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
        
        # Aktivite özeti
        if self.scan_count > 0:
            activity_frame = tk.Frame(self.content_area, bg=self.bg_color)
            activity_frame.pack(fill=tk.X, padx=30, pady=(20, 0))
            
            # Tarama sayısı
            scan_card = RoundedFrame(activity_frame, bg_color=self.card_color, corner_radius=15)
            scan_card.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
            
            scan_content = tk.Frame(scan_card, bg=self.card_color)
            scan_content.place(relx=0.5, rely=0.5, anchor=tk.CENTER, width=150, height=100)
            
            scan_icon = tk.Label(scan_content, text="🔍", font=("Arial", 24), 
                              bg=self.card_color, fg=self.text_color)
            scan_icon.pack(pady=(10, 5))
            
            scan_count = tk.Label(scan_content, text=str(self.scan_count), 
                               font=("Arial", 18, "bold"), 
                               bg=self.card_color, fg=self.accent_color)
            scan_count.pack()
            
            scan_label = tk.Label(scan_content, text="Tarama", 
                               font=("Arial", 10), 
                               bg=self.card_color, fg="#B3B3B3")
            scan_label.pack()
            
            # Tespit edilen tehditler
            threat_card = RoundedFrame(activity_frame, bg_color=self.card_color, corner_radius=15)
            threat_card.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
            
            threat_content = tk.Frame(threat_card, bg=self.card_color)
            threat_content.place(relx=0.5, rely=0.5, anchor=tk.CENTER, width=150, height=100)
            
            threat_icon = tk.Label(threat_content, text="⚠️", font=("Arial", 24), 
                                bg=self.card_color, fg=self.text_color)
            threat_icon.pack(pady=(10, 5))
            
            threat_count = tk.Label(threat_content, text=str(self.threat_count), 
                                 font=("Arial", 18, "bold"), 
                                 bg=self.card_color, fg=self.warning_color)
            threat_count.pack()
            
            threat_label = tk.Label(threat_content, text="Tehdit", 
                                 font=("Arial", 10), 
                                 bg=self.card_color, fg="#B3B3B3")
            threat_label.pack()
            
            # Son tarama
            last_scan_card = RoundedFrame(activity_frame, bg_color=self.card_color, corner_radius=15)
            last_scan_card.grid(row=0, column=2, padx=10, pady=10, sticky="nsew")
            
            last_scan_content = tk.Frame(last_scan_card, bg=self.card_color)
            last_scan_content.place(relx=0.5, rely=0.5, anchor=tk.CENTER, width=150, height=100)
            
            last_scan_icon = tk.Label(last_scan_content, text="🕒", font=("Arial", 24), 
                                   bg=self.card_color, fg=self.text_color)
            last_scan_icon.pack(pady=(10, 5))
            
            if self.last_scan_time:
                time_str = self.last_scan_time.strftime("%H:%M:%S")
                date_str = self.last_scan_time.strftime("%d/%m/%Y")
            else:
                time_str = "--:--:--"
                date_str = "--/--/----"
            
            last_scan_time = tk.Label(last_scan_content, text=time_str, 
                                   font=("Arial", 16, "bold"), 
                                   bg=self.card_color, fg=self.accent_color)
            last_scan_time.pack()
            
            last_scan_date = tk.Label(last_scan_content, text=date_str, 
                                   font=("Arial", 10), 
                                   bg=self.card_color, fg="#B3B3B3")
            last_scan_date.pack()
            
            # Grid ayarları
            activity_frame.columnconfigure(0, weight=1)
            activity_frame.columnconfigure(1, weight=1)
            activity_frame.columnconfigure(2, weight=1)
        
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
        
        # 10 saniye sonra parçacık animasyonunu durdur
        self.root.after(10000, particles.stop_animation)
        self.root.after(10500, particles.destroy)
    
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
                     lambda e, c=card, tc=content: self._animate_card_hover(c, tc, True))
            widget.bind("<Leave>", 
                     lambda e, c=card, tc=content: self._animate_card_hover(c, tc, False))
            widget.bind("<Button-1>", lambda e: self._animate_card_click(card, command))
    
    def _animate_card_hover(self, card, content, enter):
        """Kart hover animasyonu"""
        target_color = self.card_hover if enter else self.card_color
        current_color = card.bg_color
        
        steps = 8
        
        def interpolate_color(start_color, end_color, step, steps):
            r1, g1, b1 = int(start_color[1:3], 16), int(start_color[3:5], 16), int(start_color[5:7], 16)
            r2, g2, b2 = int(end_color[1:3], 16), int(end_color[3:5], 16), int(end_color[5:7], 16)
            
            r = r1 + (r2 - r1) * step / steps
            g = g1 + (g2 - g1) * step / steps
            b = b1 + (b2 - b1) * step / steps
            
            return f'#{int(r):02x}{int(g):02x}{int(b):02x}'
        
        def animate_step(step):
            if step <= steps:
                color = interpolate_color(current_color, target_color, step, steps)
                card.bg_color = color
                card.canvas.configure(background=color)
                content.configure(background=color)
                
                # Alt widget'ların rengini de güncelle
                for child in content.winfo_children():
                    child.configure(background=color)
                
                card.after(20, lambda: animate_step(step + 1))
        
        animate_step(1)
    
    def _animate_card_click(self, card, command):
        """Kart tıklama animasyonu"""
        original_scale = 1.0
        min_scale = 0.95
        
        def animate_scale(scale, direction):
            if direction == "down":  # Küçültme
                if scale > min_scale:
                    new_scale = scale - 0.01
                    card._on_resize(None)  # Yeniden boyutlandırma efekti
                    card.after(10, lambda: animate_scale(new_scale, "down"))
                else:
                    card.after(50, lambda: animate_scale(min_scale, "up"))
            else:  # Büyütme
                if scale < original_scale:
                    new_scale = scale + 0.01
                    card._on_resize(None)  # Yeniden boyutlandırma efekti
                    card.after(10, lambda: animate_scale(new_scale, "up"))
                else:
                    command()  # İşlemi tamamla
        
        animate_scale(original_scale, "down")
    
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
        
        # Dairesel ilerleme çubuğu
        self.circular_progress = CircularProgressbar(
            controls_frame, 
            width=60, 
            height=60, 
            bg_color=self.bg_color, 
            fg_color=self.accent_color
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
        
        # İlerleme çubuğu yerine dairesel ilerleme çubuğunu göster
        self.circular_progress.pack(side=tk.LEFT, padx=(10, 0))
        
        # Sonuç alanını temizle
        self.result_text.config(state=tk.NORMAL)
        self.result_text.delete(1.0, tk.END)
        self.result_text.config(state=tk.DISABLED)
        
        # Animasyonlu ilerleme
        self._animate_scan_progress()
        
        # Arka planda tarama yap
        threading.Thread(target=self._scan_thread, daemon=True).start()
    
    def _animate_scan_progress(self):
        """Tarama ilerleme çubuğunu animasyonlu gösterir"""
        steps = 50
        
        def update_step(step):
            if step <= steps:
                progress = step / steps * 100
                self.circular_progress.update_progress(progress)
                
                # Eğer tarama tamamlanmadıysa, döngüyü devam ettir
                if step == steps and self.scan_button.cget("state") == "disabled":
                    # Başa dön
                    self.root.after(50, lambda: update_step(0))
                else:
                    self.root.after(50, lambda: update_step(step + 1))
        
        update_step(0)
    
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
            
            # Gerçekten tehlikeli durumları filtrele
            real_threats = [entry for entry in suspicious_entries if entry.get("type") not in ["info_broadcast_multicast", "info_other"]]
            is_truly_safe = len(real_threats) == 0
            
            # İstatistikleri güncelle
            self.scan_count += 1
            if not is_truly_safe:
                self.threat_count += len(real_threats)
            self.last_scan_time = datetime.datetime.now()
            
            # Geçmişe kaydet
            save_scan_history(scan_output, is_truly_safe)
            
            # Arayüzü güncelle
            self.root.after(0, lambda: self._update_ui(is_safe, important_lines, suspicious_entries))
            
            # Periyodik tarama başlatılacak mı?
            if self.periodic_var.get() and not self.periodic_running:
                self.root.after(0, self.start_periodic_scan)
            else:
                # İlerleme çubuğunu kapat ve düğmeyi etkinleştir
                self.root.after(0, lambda: self.circular_progress.update_progress(100))
                self.root.after(1000, lambda: self.circular_progress.pack_forget())
                self.root.after(1000, lambda: self.scan_button.configure(state=tk.NORMAL))
                self.root.after(1000, lambda: self.status_var.set("Tarama tamamlandı"))
                
        except Exception as e:
            self.root.after(0, lambda: messagebox.showerror("Hata", f"Tarama sırasında hata: {str(e)}"))
            self.root.after(0, lambda: self.circular_progress.pack_forget())
            self.root.after(0, lambda: self.scan_button.configure(state=tk.NORMAL))
            self.root.after(0, lambda: self.status_var.set("Tarama hatası"))
    
    def _update_ui(self, is_safe, important_lines, suspicious_entries):
        """Tarama sonuçlarına göre arayüzü günceller"""
        # Gerçekten tehlikeli durumları filtrele - info_broadcast_multicast tipindeki girdileri hariç tut
        real_threats = [entry for entry in suspicious_entries if entry.get("type") not in ["info_broadcast_multicast", "info_other"]]
        
        # Gerçekten tehlike var mı kontrol et
        is_truly_safe = len(real_threats) == 0
        
        # Sonuç kartını güncelle
        if is_truly_safe:
            self._animate_result_update(
                icon=self.icons["success"],
                title="Ağınız Güvende",
                title_color=self.accent_color,
                message="Herhangi bir ARP spoofing tehdidi tespit edilmedi.",
                card_color=self.card_color
            )
        else:
            self._animate_result_update(
                icon=self.icons["warning"],
                title="Saldırı Riski!",
                title_color=self.warning_color,
                message="Ağınızda şüpheli ARP etkinliği tespit edildi! Detaylar için aşağıya bakın.",
                card_color="#282828"
            )
            
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
    
    def _animate_result_update(self, icon, title, title_color, message, card_color):
        """Sonuç panelini animasyonlu günceller"""
        # Önceki içerik
        current_icon = self.status_icon.cget("text")
        current_title = self.status_title.cget("text")
        current_message = self.status_text.cget("text")
        current_card_color = self.result_card.bg_color
        
        # İçeriği soluklaştır
        def fade_out(alpha=1.0, step=0, steps=5):
            if step < steps:
                self.status_icon.configure(fg=f"#{int(255*alpha):02x}{int(255*alpha):02x}{int(255*alpha):02x}")
                self.status_title.configure(fg=f"#{int(255*alpha):02x}{int(255*alpha):02x}{int(255*alpha):02x}")
                self.status_text.configure(fg=f"#{int(200*alpha):02x}{int(200*alpha):02x}{int(200*alpha):02x}")
                
                # Bir sonraki adım
                new_alpha = alpha - (1.0 / steps)
                self.root.after(50, lambda: fade_out(new_alpha, step + 1, steps))
            else:
                # İçeriği değiştir
                self.status_icon.configure(text=icon)
                self.status_title.configure(text=title)
                self.status_text.configure(text=message)
                
                # Card rengini değiştir
                self._animate_card_color_change(current_card_color, card_color)
                
                # Yeni içeriği kademeli göster
                fade_in()
        
        # İçeriği kademeli göster
        def fade_in(alpha=0.0, step=0, steps=10):
            if step < steps:
                # Icon rengi
                icon_color = f"#{int(255*alpha):02x}{int(255*alpha):02x}{int(255*alpha):02x}"
                self.status_icon.configure(fg=icon_color)
                
                # Başlık rengi - hedef renge doğru kademeli
                r, g, b = int(title_color[1:3], 16), int(title_color[3:5], 16), int(title_color[5:7], 16)
                title_r = int(r * alpha)
                title_g = int(g * alpha)
                title_b = int(b * alpha)
                title_color_faded = f"#{title_r:02x}{title_g:02x}{title_b:02x}"
                self.status_title.configure(fg=title_color_faded)
                
                # Mesaj rengi
                message_color = f"#{int(180*alpha):02x}{int(180*alpha):02x}{int(180*alpha):02x}"
                self.status_text.configure(fg=message_color)
                
                # Bir sonraki adım
                new_alpha = alpha + (1.0 / steps)
                self.root.after(50, lambda: fade_in(new_alpha, step + 1, steps))
        
        # Animasyonu başlat
        fade_out()
    
    def _animate_card_color_change(self, start_color, end_color, steps=10):
        """Kart arka plan rengini kademeli değiştirir"""
        r1, g1, b1 = int(start_color[1:3], 16), int(start_color[3:5], 16), int(start_color[5:7], 16)
        r2, g2, b2 = int(end_color[1:3], 16), int(end_color[3:5], 16), int(end_color[5:7], 16)
        
        def animate_step(step):
            if step <= steps:
                # Easing fonksiyonu - yavaşlayan hareket
                t = step / steps
                ease = 1 - (1 - t) * (1 - t)  # Ease-out quad
                
                # Ara renk
                r = r1 + (r2 - r1) * ease
                g = g1 + (g2 - g1) * ease
                b = b1 + (b2 - b1) * ease
                color = f'#{int(r):02x}{int(g):02x}{int(b):02x}'
                
                # Rengi uygula
                self.result_card.bg_color = color
                self.result_card.canvas.configure(background=color)
                
                # Çocuk widget'ları güncelle
                for child in self.result_card.winfo_children():
                    child.configure(background=color)
                    for grandchild in child.winfo_children():
                        if isinstance(grandchild, tk.Label) or isinstance(grandchild, tk.Frame):
                            grandchild.configure(background=color)
                
                # Bir sonraki adım
                self.root.after(50, lambda: animate_step(step + 1))
        
        # Animasyonu başlat
        animate_step(0)
    
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
        
        # Animasyon için başlangıç durumu
        self.warning_window.attributes('-alpha', 0.0)
        
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
        
        # Yavaşça göster
        def fade_in(alpha=0.0):
            alpha += 0.1
            self.warning_window.attributes('-alpha', alpha)
            
            if alpha < 1.0:
                self.warning_window.after(20, lambda: fade_in(alpha))
        
        # Animasyonu başlat
        fade_in()
    
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
        
        # Geçmiş verilerini yükle
        history = load_scan_history()
        
        if history:
            # Geçmiş istatistikleri 
            stats_frame = tk.Frame(self.content_area, bg=self.bg_color)
            stats_frame.pack(fill=tk.X, padx=30, pady=(0, 15))
            
            # Güvenlik grafiği için veri oluştur
            chart_data = []
            safe_count = 0
            threat_count = 0
            
            for i, entry in enumerate(history):
                is_safe = entry.get("is_safe", True)
                chart_data.append({
                    "date": entry.get("date", f"Tarama {i+1}"),
                    "value": 100 if is_safe else 0,  # Güvenli: 100, Tehlikeli: 0
                    "is_safe": is_safe
                })
                
                if is_safe:
                    safe_count += 1
                else:
                    threat_count += 1
            
            # Güvenlik durumu grafiği
            chart_frame = RoundedFrame(stats_frame, bg_color=self.card_color, corner_radius=10)
            chart_frame.pack(fill=tk.X, pady=10)
            
            chart_title = tk.Label(chart_frame, text="Güvenlik Durumu Geçmişi", 
                                font=("Arial", 14, "bold"), 
                                bg=self.card_color, fg=self.text_color)
            chart_title.pack(anchor=tk.W, padx=20, pady=(15, 5))
            
            chart_subtitle = tk.Label(chart_frame, 
                                   text=f"Son {len(history)} tarama sonucu", 
                                   font=("Arial", 10), 
                                   bg=self.card_color, fg="#B3B3B3")
            chart_subtitle.pack(anchor=tk.W, padx=20, pady=(0, 10))
            
            # Animasyonlu grafik
            chart = AnimatedChart(chart_frame, width=600, height=200, 
                               data=chart_data, 
                               bg_color=self.card_color, 
                               line_color=self.accent_color)
            chart.pack(padx=20, pady=(0, 20), fill=tk.X)
            
            # Özet istatistikler
            summary_frame = tk.Frame(self.content_area, bg=self.bg_color)
            summary_frame.pack(fill=tk.X, padx=30, pady=(0, 15))
            
            # Grid yapısı
            for i in range(3):
                summary_frame.columnconfigure(i, weight=1)
            
            # Son taramalar
            last_scans_card = RoundedFrame(summary_frame, bg_color=self.card_color, corner_radius=10)
            last_scans_card.grid(row=0, column=0, padx=10, pady=10, sticky="nsew")
            
            # Güvenli / tehlikeli oranları
            ratio_card = RoundedFrame(summary_frame, bg_color=self.card_color, corner_radius=10)
            ratio_card.grid(row=0, column=1, padx=10, pady=10, sticky="nsew")
            
            # Son 3 güvenli tarama
            ratio_frame = tk.Frame(ratio_card, bg=self.card_color)
            ratio_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
            
            ratio_title = tk.Label(ratio_frame, text="Güvenlik Oranı", 
                                font=("Arial", 14, "bold"), 
                                bg=self.card_color, fg=self.text_color)
            ratio_title.pack(anchor=tk.W, pady=(0, 15))
            
            # Dairesel ilerleme
            total_scans = safe_count + threat_count
            if total_scans > 0:
                safe_ratio = (safe_count / total_scans) * 100
            else:
                safe_ratio = 0
            
            ratio_progress = CircularProgressbar(
                ratio_frame, 
                width=100, 
                height=100, 
                bg_color=self.card_color, 
                fg_color=self.accent_color
            )
            ratio_progress.pack(pady=10)
            ratio_progress.update_progress(safe_ratio)
            
            ratio_text = tk.Label(ratio_frame, 
                               text=f"Güvenli: {safe_count} / Tehlikeli: {threat_count}", 
                               font=("Arial", 10), 
                               bg=self.card_color, fg="#B3B3B3")
            ratio_text.pack(pady=(5, 0))
            
            # Son taramalar listesi
            scans_frame = tk.Frame(last_scans_card, bg=self.card_color)
            scans_frame.pack(fill=tk.BOTH, expand=True, padx=20, pady=20)
            
            scans_title = tk.Label(scans_frame, text="Son Taramalar", 
                                font=("Arial", 14, "bold"), 
                                bg=self.card_color, fg=self.text_color)
            scans_title.pack(anchor=tk.W, pady=(0, 15))
            
            # Son 5 taramayı göster
            recent_history = history[-5:] if len(history) > 5 else history
            recent_history.reverse()  # En son yapılan tarama en üstte
            
            for entry in recent_history:
                is_safe = entry.get("is_safe", True)
                date = entry.get("date", "Bilinmeyen tarih")
                
                scan_row = tk.Frame(scans_frame, bg=self.card_color)
                scan_row.pack(fill=tk.X, pady=5)
                
                icon = "✅" if is_safe else "⚠️"
                color = self.accent_color if is_safe else self.warning_color
                
                scan_icon = tk.Label(scan_row, text=icon, font=("Arial", 14), 
                                   bg=self.card_color, fg=color)
                scan_icon.pack(side=tk.LEFT, padx=(0, 10))
                
                scan_info = tk.Label(scan_row, text=f"Tarama: {date}", 
                                  font=("Arial", 10), 
                                  bg=self.card_color, fg=self.text_color)
                scan_info.pack(side=tk.LEFT)
                
                scan_status = tk.Label(scan_row, 
                                    text="Güvenli" if is_safe else "Tehlikeli", 
                                    font=("Arial", 10), 
                                    bg=self.card_color, fg=color)
                scan_status.pack(side=tk.RIGHT)
                
                # Satırın hover efekti
                scan_row.bind("<Enter>", 
                           lambda e, f=scan_row: f.configure(background=self.card_hover))
                scan_row.bind("<Leave>", 
                           lambda e, f=scan_row: f.configure(background=self.card_color))
                
                for child in scan_row.winfo_children():
                    child.bind("<Enter>", 
                            lambda e, f=scan_row: f.configure(background=self.card_hover))
                    child.bind("<Leave>", 
                            lambda e, f=scan_row: f.configure(background=self.card_color))
        else:
            # Henüz uygulama geçmişi yok
            info_frame = RoundedFrame(self.content_area, bg_color=self.card_color, corner_radius=10)
            info_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=(10, 30))
            
            no_data_frame = tk.Frame(info_frame, bg=self.card_color)
            no_data_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER, relwidth=0.8, relheight=0.8)
            
            info_icon = tk.Label(no_data_frame, text="🕒", font=("Arial", 48), 
                              bg=self.card_color, fg=self.text_color)
            info_icon.pack(pady=(0, 10))
            
            info_title = tk.Label(no_data_frame, text="Geçmiş Bulunamadı", 
                               font=("Arial", 16, "bold"), 
                               bg=self.card_color, fg=self.text_color)
            info_title.pack(pady=(0, 5))
            
            info_text = tk.Label(no_data_frame, 
                              text="Tarama geçmişi henüz oluşturulmadı. Bir tarama yaptığınızda sonuçlar burada görüntülenecektir.",
                              wraplength=500, justify=tk.CENTER, 
                              font=("Arial", 12), 
                              bg=self.card_color, fg="#B3B3B3")
            info_text.pack(pady=(0, 20))
            
            # Tarama butonu
            scan_btn = SpotifyButton(no_data_frame, text="Tarama Yap", command=self.load_scan_content,
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
        
        # Periyodik tarama ayarı için frame
        periodic_setting_frame = RoundedFrame(settings_content, bg_color=self.card_hover, corner_radius=8)
        periodic_setting_frame.pack(fill=tk.X, pady=10)
        
        periodic_frame = tk.Frame(periodic_setting_frame, bg=self.card_hover)
        periodic_frame.pack(fill=tk.X, padx=15, pady=15)
        
        # Periyodik tarama seçeneği
        class AnimatedCheckbox(tk.Canvas):
            def __init__(self, parent, variable, **kwargs):
                super().__init__(parent, width=24, height=24, bg=parent["bg"], 
                               highlightthickness=0, **kwargs)
                
                self.variable = variable
                self.animation_id = None
                
                # Çember ve işaret çiz
                self.outer_circle = self.create_oval(2, 2, 22, 22, outline="#555555", width=2, fill="")
                self.inner_circle = self.create_oval(6, 6, 18, 18, outline="", fill="")
                
                # İşaretli durumu yansıt
                self._update_state()
                
                # Değişken değişimini izle
                self.variable.trace_add("write", lambda *args: self._update_state())
                
                # Tıklama işleyici
                self.bind("<Button-1>", self._toggle)
            
            def _toggle(self, event):
                """Checkbox durumunu tersine çevir"""
                self.variable.set(not self.variable.get())
            
            def _update_state(self):
                """Checkbox durumunu güncelle"""
                if self.animation_id:
                    self.after_cancel(self.animation_id)
                
                is_checked = self.variable.get()
                start_radius = 0 if is_checked else 6
                end_radius = 6 if is_checked else 0
                start_color = "#121212" if not is_checked else "#1DB954"
                end_color = "#1DB954" if is_checked else "#121212"
                
                self._animate_check(start_radius, end_radius, start_color, end_color)
            
            def _animate_check(self, start_radius, end_radius, start_color, end_color, step=0, steps=10):
                """İşaretleme animasyonu"""
                if step <= steps:
                    # Lineer interpolasyon
                    t = step / steps
                    
                    # Kademeli animasyon efekti 
                    t_eased = t * t * (3 - 2 * t)  # Smooth step interpolation
                    
                    # Renk ayarla
                    r1, g1, b1 = int(start_color[1:3], 16), int(start_color[3:5], 16), int(start_color[5:7], 16)
                    r2, g2, b2 = int(end_color[1:3], 16), int(end_color[3:5], 16), int(end_color[5:7], 16)
                    
                    r = r1 + (r2 - r1) * t_eased
                    g = g1 + (g2 - g1) * t_eased
                    b = b1 + (b2 - b1) * t_eased
                    
                    color = f'#{int(r):02x}{int(g):02x}{int(b):02x}'
                    
                    # İç daire boyutunu güncelle
                    radius = start_radius + (end_radius - start_radius) * t_eased
                    
                    self.itemconfig(self.inner_circle, fill=color)
                    self.coords(self.inner_circle, 
                            12-radius, 12-radius, 
                            12+radius, 12+radius)
                    
                    # Bir sonraki adım
                    self.animation_id = self.after(20, lambda: self._animate_check(
                        start_radius, end_radius, start_color, end_color, step+1, steps))
                else:
                    self.animation_id = None
        
        # Özel checkbox ve etiket
        checkbox_frame = tk.Frame(periodic_frame, bg=self.card_hover)
        checkbox_frame.pack(anchor=tk.W)
        
        checkbox = AnimatedCheckbox(checkbox_frame, self.periodic_var)
        checkbox.pack(side=tk.LEFT, padx=(0, 10))
        
        checkbox_label = tk.Label(checkbox_frame, text="Periyodik tarama", 
                               font=("Arial", 12), 
                               bg=self.card_hover, fg=self.text_color)
        checkbox_label.pack(side=tk.LEFT)
        
        # Etiket de tıklanabilir olsun
        checkbox_label.bind("<Button-1>", lambda e: self.periodic_var.set(not self.periodic_var.get()))
        
        # Periyodik tarama ayarları
        period_frame = tk.Frame(periodic_frame, bg=self.card_hover)
        period_frame.pack(fill=tk.X, pady=(15, 0))
        
        period_label = tk.Label(period_frame, text="Tarama sıklığı:", 
                             font=("Arial", 12),
                             bg=self.card_hover, fg=self.text_color)
        period_label.pack(side=tk.LEFT, padx=(20, 10))
        
        # Özel stil için ttk kullanıyoruz
        style = ttk.Style()
        style.theme_use('default')
        style.configure("Spotify.TCombobox", 
                      padding=5,
                      background=self.accent_color)
        
        # Saat değerleri için slider
        period_values = ["1", "2", "4", "6", "8", "12", "24", "48", "72"]
        
        # Spotify stili combobox
        class SpotifyCombobox(tk.Frame):
            def __init__(self, parent, values, current_value, bg_color="#282828", **kwargs):
                super().__init__(parent, bg=bg_color, **kwargs)
                
                self.values = values
                self.current_value = tk.StringVar(value=current_value)
                self.dropdown_visible = False
                
                # Ana buton
                self.button = tk.Frame(self, bg=bg_color, padx=10, pady=5)
                self.button.pack(fill=tk.X)
                
                # Buton metni
                self.button_text = tk.Label(self.button, textvariable=self.current_value, 
                                         font=("Arial", 12), 
                                         bg=bg_color, fg="#FFFFFF")
                self.button_text.pack(side=tk.LEFT)
                
                # Ok işareti
                self.arrow = tk.Label(self.button, text="▼", font=("Arial", 8), 
                                   bg=bg_color, fg="#AAAAAA")
                self.arrow.pack(side=tk.RIGHT, padx=(5, 0))
                
                # Açılır menü
                self.dropdown = tk.Frame(self, bg="#333333", padx=2, pady=2)
                
                # Değerler listesi
                for value in values:
                    item = tk.Label(self.dropdown, text=value, font=("Arial", 12), 
                                 bg="#333333", fg="#FFFFFF", 
                                 padx=10, pady=5)
                    item.pack(fill=tk.X)
                    
                    # Hover efekti
                    item.bind("<Enter>", lambda e, i=item: i.config(bg=self.master["bg"]))
                    item.bind("<Leave>", lambda e, i=item: i.config(bg="#333333"))
                    
                    # Tıklama
                    item.bind("<Button-1>", lambda e, v=value: self._select_value(v))
                
                # Açılır menüyü gösterip gizle
                self.button.bind("<Button-1>", self._toggle_dropdown)
                
                # Buton hover efekti
                self.button.bind("<Enter>", lambda e: self.button.config(bg="#383838"))
                self.button.bind("<Leave>", lambda e: self.button.config(bg=bg_color))
                for child in self.button.winfo_children():
                    child.bind("<Enter>", lambda e: self.button.config(bg="#383838"))
                    child.bind("<Leave>", lambda e: self.button.config(bg=bg_color))
            
            def _toggle_dropdown(self, event=None):
                """Açılır menüyü göster/gizle"""
                if self.dropdown_visible:
                    self.dropdown.pack_forget()
                    self.arrow.config(text="▼")
                else:
                    self.dropdown.pack(fill=tk.X)
                    self.arrow.config(text="▲")
                
                self.dropdown_visible = not self.dropdown_visible
            
            def _select_value(self, value):
                """Değer seçildiğinde"""
                self.current_value.set(value)
                self._toggle_dropdown()
            
            def get(self):
                """Seçilen değeri döndürür"""
                return self.current_value.get()
        
        # Saat seçimi için combobox
        combo = SpotifyCombobox(
            period_frame, 
            values=period_values, 
            current_value=str(self.period_hours.get()),
            bg_color=self.card_hover
        )
        combo.pack(side=tk.LEFT, padx=(0, 10))
        
        hours_label = tk.Label(period_frame, text="saat", 
                            font=("Arial", 12),
                            bg=self.card_hover, fg=self.text_color)
        hours_label.pack(side=tk.LEFT, padx=(5, 0))
        
        # Sistem başlangıcında çalıştırma
        startup_frame = RoundedFrame(settings_content, bg_color=self.card_hover, corner_radius=8)
        startup_frame.pack(fill=tk.X, pady=10)                # İçeriği soluklaştır
                def fade_out(alpha=1.0, step=0, steps=5):
                    if step < steps:
                        new_alpha = alpha - (alpha / steps)
                        self.status_icon.configure(fg=f"#{int(255*new_alpha):02x}{int(255*new_alpha):02x}{int(255*new_alpha):02x}")
                        self.status_title.configure(fg=f"#{int(255*new_alpha):02x}{int(255*new_alpha):02x}{int(255*new_alpha):02x}")
                        self.status_text.configure(fg=f"#{int(255*new_alpha):02x}{int(255*new_alpha):02x}{int(255*new_alpha):02x}")
                        self.root.after(50, lambda: fade_out(new_alpha, step+1, steps))
                    else:
                        # İçeriği güncelle
                        self.status_icon.configure(text=icon, fg=self.text_color)
                        self.status_title.configure(text=title, fg=title_color)
                        self.status_text.configure(text=message, fg="#B3B3B3")
                        
                        # Kartın rengini değiştir
                        self.result_card.bg_color = card_color
                        self.result_card.canvas.configure(background=card_color)
                        
                        # Yeni içeriği kademeli göster
                        fade_in()
                
                # İçeriği kademeli göster
                def fade_in(alpha=0.0, step=0, steps=10):
                    if step < steps:
                        new_alpha = alpha + ((1.0 - alpha) / steps)
                        if step < steps / 2:  # İkonu önce göster
                            self.status_icon.configure(fg=f"#{int(255*new_alpha):02x}{int(255*new_alpha):02x}{int(255*new_alpha):02x}")
                        
                        if step > steps / 4:  # Sonra başlık
                            self.status_title.configure(fg=title_color)
                        
                        if step > steps / 2:  # En son mesaj
                            self.status_text.configure(fg=f"#{int(179*new_alpha):02x}{int(179*new_alpha):02x}{int(179*new_alpha):02x}")
                        
                        self.root.after(50, lambda: fade_in(new_alpha, step+1, steps))
                
                # Animasyonu başlat
                fade_out()
    
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
        
        # Uyarı ikonu - animasyonlu
        icon_label = tk.Label(header, text=self.icons["warning"], font=("Arial", 36), 
                           fg=self.warning_color, bg=self.bg_color)
        icon_label.pack(side=tk.LEFT, padx=(0, 15))
        
        # Uyarı ikonunu anime et - yanıp sönme
        def blink_icon(state=True):
            if state:
                icon_label.configure(fg=self.warning_color)
            else:
                icon_label.configure(fg="#555555")
            
            # Animasyona devam et
            if self.warning_window.winfo_exists():
                self.warning_window.after(500, lambda: blink_icon(not state))
        
        # Animasyonu başlat
        blink_icon()
        
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
        
        # Animasyonlu tehdit görünümü
        for i, entry in enumerate(suspicious_entries):
            message = entry.get("message", "")
            if message:
                # Tehdit içeriğini oluştur
                threat_frame = tk.Frame(threats_content, bg=self.card_color)
                threat_frame.pack(pady=2, fill=tk.X)
                
                threat_label = tk.Label(threat_frame, text=message, 
                                     wraplength=430, justify=tk.LEFT, 
                                     bg=self.card_color, fg=self.text_color, font=("Arial", 10))
                threat_label.pack(side=tk.LEFT, anchor=tk.W)
                
                # İlk görünümde gizle
                threat_frame.pack_forget()
                
                # Kademeli gösterme
                def show_threat(frame, index):
                    delay = index * 300  # Her tehdit arasında 300ms bekle
                    self.warning_window.after(delay, frame.pack, {'pady': 2, 'fill': tk.X})
                
                # Gösterme çağrısı
                show_threat(threat_frame, i)
        
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
            
            # İlk görünümde gizle
            action_frame.pack_forget()
            
            # Kademeli gösterme
            def show_action(frame, index):
                delay = 1000 + (index * 300)  # Tehditlerden sonra göster
                self.warning_window.after(delay, frame.pack, {'fill': tk.X, 'pady': 2})
            
            # Gösterme çağrısı
            show_action(action_frame, i)
        
        # Kapat butonu
        close_btn = SpotifyButton(content, text="Anladım", command=self.warning_window.destroy,
                              width=100, height=35, bg_color=self.accent_color)
        
        # Butonu başlangıçta gizle, animasyonla göster
        close_btn.pack_forget()
        self.warning_window.after(2500, lambda: close_btn.pack(side=tk.RIGHT, pady=10))
        
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
        
        # Geçmiş verilerini yükle
        history_data = load_scan_history()
        
        # İçerik
        content_frame = RoundedFrame(self.content_area, bg_color=self.card_color, corner_radius=10)
        content_frame.pack(fill=tk.BOTH, expand=True, padx=30, pady=(10, 30))
        
        if not history_data:
            # Henüz uygulama geçmişi yoksa
            info_frame = tk.Frame(content_frame, bg=self.card_color)
            info_frame.place(relx=0.5, rely=0.5, anchor=tk.CENTER, relwidth=0.8, relheight=0.8)
            
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
        else:
            # Geçmiş var, düzenli şekilde göster
            history_container = tk.Frame(content_frame, bg=self.card_color, padx=20, pady=20)
            history_container.pack(fill=tk.BOTH, expand=True)
            
            # Özet bilgiler
            summary_frame = tk.Frame(history_container, bg=self.card_color)
            summary_frame.pack(fill=tk.X, pady=(0, 20))
            
            # Toplam tarama sayısı
            total_scan_label = tk.Label(summary_frame, 
                                     text=f"Toplam Tarama: {len(history_data)}", 
                                     font=("Arial", 12, "bold"), 
                                     bg=self.card_color, fg=self.text_color)
            total_scan_label.pack(side=tk.LEFT, padx=(0, 20))
            
            # Toplam tehdit sayısı
            threat_count = sum(1 for item in history_data if not item.get("is_safe", True))
            threat_label = tk.Label(summary_frame, 
                                 text=f"Tehdit Tespit Edilen: {threat_count}", 
                                 font=("Arial", 12, "bold"), 
                                 bg=self.card_color, fg=self.warning_color if threat_count > 0 else self.text_color)
            threat_label.pack(side=tk.LEFT)
            
            # Grafik kartı
            chart_frame = tk.Frame(history_container, bg=self.card_color)
            chart_frame.pack(fill=tk.X, pady=(0, 20))
            
            chart_label = tk.Label(chart_frame, text="Tarama Geçmişi Grafiği", 
                                font=("Arial", 14, "bold"), 
                                bg=self.card_color, fg=self.text_color)
            chart_label.pack(anchor=tk.W, pady=(0, 10))
            
            # Grafik için verileri hazırla
            chart_data = []
            for item in history_data:
                # Tarih ve güvenlik durumu
                date_str = item.get("date", "")
                is_safe = item.get("is_safe", True)
                
                # Tehdit değeri (güvenliyse 0, değilse 1)
                value = 0 if is_safe else 1
                
                # Grafik verisine ekle
                chart_data.append({
                    "date": date_str,
                    "value": value,
                    "is_safe": is_safe
                })
            
            # Animasyonlu grafik
            chart = AnimatedChart(chart_frame, width=700, height=200, 
                               bg_color=self.card_color, 
                               line_color=self.accent_color)
            chart.pack(fill=tk.X, expand=True, pady=(0, 20))
            chart.set_data(chart_data)
            
            # Geçmiş kayıtları için scrollable liste
            history_label = tk.Label(history_container, text="Detaylı Tarama Geçmişi", 
                                  font=("Arial", 14, "bold"), 
                                  bg=self.card_color, fg=self.text_color)
            history_label.pack(anchor=tk.W, pady=(0, 10))
            
            # Scrollable çerçeve
            history_list_frame = tk.Frame(history_container, bg=self.card_color)
            history_list_frame.pack(fill=tk.BOTH, expand=True)
            
            # Canvas ve scrollbar
            canvas = tk.Canvas(history_list_frame, bg=self.card_color, 
                            bd=0, highlightthickness=0)
            scrollbar = ttk.Scrollbar(history_list_frame, orient=tk.VERTICAL, 
                                    command=canvas.yview)
            
            # Canvas içeriği için çerçeve
            list_frame = tk.Frame(canvas, bg=self.card_color)
            
            # Canvas yapılandırması
            canvas.configure(yscrollcommand=scrollbar.set)
            canvas.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
            scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
            
            # Çerçeveyi canvas'a bağla
            canvas_frame = canvas.create_window((0, 0), window=list_frame, anchor=tk.NW)
            
            # Canvas boyutunu güncelleme
            def on_frame_configure(event):
                canvas.configure(scrollregion=canvas.bbox("all"))
            
            list_frame.bind("<Configure>", on_frame_configure)
            
            # Canvas genişliğini ayarlama
            def on_canvas_configure(event):
                canvas.itemconfig(canvas_frame, width=event.width)
            
            canvas.bind("<Configure>", on_canvas_configure)
            
            # Fare tekerleği bağlama
            def on_mousewheel(event):
                canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")
            
            canvas.bind_all("<MouseWheel>", on_mousewheel)
            
            # Geçmiş kartlarını oluştur
            for i, item in enumerate(reversed(history_data)):  # En yeniden en eskiye sırala
                date_str = item.get("date", "")
                is_safe = item.get("is_safe", True)
                
                # Her kayıt için kart
                scan_frame = tk.Frame(list_frame, bg=self.card_color, padx=5, pady=5)
                scan_frame.pack(fill=tk.X, pady=5)
                
                # Tarih ve güvenlik durumu kartı
                scan_card = RoundedFrame(scan_frame, 
                                      bg_color=self.accent_color if is_safe else self.warning_color, 
                                      corner_radius=10)
                scan_card.pack(fill=tk.X)
                
                # Kart içeriği
                card_content = tk.Frame(scan_card, 
                                     bg=self.accent_color if is_safe else self.warning_color)
                card_content.place(relx=0.5, rely=0.5, anchor=tk.CENTER, relwidth=0.95, relheight=0.9)
                
                # Üst satır: tarih ve durum
                header_frame = tk.Frame(card_content, 
                                     bg=self.accent_color if is_safe else self.warning_color)
                header_frame.pack(fill=tk.X, pady=(10, 5))
                
                # Tarih
                date_label = tk.Label(header_frame, text=date_str, 
                                   font=("Arial", 12, "bold"), 
                                   bg=header_frame["bg"], fg=self.text_color)
                date_label.pack(side=tk.LEFT)
                
                # Durum
                status_text = "✅ Güvenli" if is_safe else "⚠️ Tehdit"
                status_label = tk.Label(header_frame, text=status_text, 
                                     font=("Arial", 12, "bold"), 
                                     bg=header_frame["bg"], fg=self.text_color)
                status_label.pack(side=tk.RIGHT)
                
                # Kart altına detay butonu
                details_frame = tk.Frame(card_content, 
                                      bg=self.accent_color if is_safe else self.warning_color)
                details_frame.pack(fill=tk.X, pady=(5, 10))
                
                details_btn = tk.Label(details_frame, text="Detayları Göster", 
                                    font=("Arial", 10, "underline"), 
                                    bg=details_frame["bg"], fg=self.text_color)
                details_btn.pack(side=tk.RIGHT)
                
                # Detay gösterme işlevi
                details_btn.bind("<Button-1>", lambda e, result=item["result"]: 
                              self._show_scan_details(result, date_str, is_safe))
                details_btn.bind("<Enter>", 
                              lambda e, btn=details_btn: btn.configure(fg="#DDDDDD"))
                details_btn.bind("<Leave>", 
                              lambda e, btn=details_btn: btn.configure(fg=self.text_color))
                
                # Animasyonlu görünüm
                scan_frame.pack_forget()  # İlk başta gizle
                self.root.after(i * 100, scan_frame.pack, {'fill': tk.X, 'pady': 5})
    
    def _show_scan_details(self, result_text, date_str, is_safe):
        """Tarama detaylarını gösterir"""
        details_window = Toplevel(self.root)
        details_window.title(f"Tarama Detayları - {date_str}")
        details_window.geometry("700x500")
        details_window.configure(bg=self.bg_color)
        details_window.transient(self.root)
        
        # Ana çerçeve
        main_frame = tk.Frame(details_window, bg=self.bg_color, padx=20, pady=20)
        main_frame.pack(fill=tk.BOTH, expand=True)
        
        # Başlık
        header = tk.Frame(main_frame, bg=self.bg_color)
        header.pack(fill=tk.X, pady=(0, 15))
        
        title = tk.Label(header, text=f"Tarama Detayları: {date_str}", 
                       font=("Arial", 16, "bold"), 
                       bg=self.bg_color, fg=self.text_color)
        title.pack(side=tk.LEFT)
        
        status_text = "✅ Güvenli" if is_safe else "⚠️ Tehdit"
        status_label = tk.Label(header, text=status_text, 
                             font=("Arial", 14, "bold"), 
                             bg=self.bg_color, 
                             fg=self.accent_color if is_safe else self.warning_color)
        status_label.pack(side=tk.RIGHT)
        
        # Detay kartı
        details_card = RoundedFrame(main_frame, bg_color=self.card_color, corner_radius=10)
        details_card.pack(fill=tk.BOTH, expand=True, pady=10)
        
        # Detay içeriği
        details_text = scrolledtext.ScrolledText(details_card, 
                                             wrap=tk.WORD, 
                                             bg="#282828", 
                                             fg=self.text_color, 
                                             font=("Consolas", 10), 
                                             bd=0)
        details_text.place(relx=0.5, rely=0.5, anchor=tk.CENTER, relwidth=0.95, relheight=0.9)
        
        # Sonuçları göster
        details_text.insert(tk.END, result_text)
        
        # Kapat butonu
        close_frame = tk.Frame(main_frame, bg=self.bg_color)
        close_frame.pack(fill=tk.X, pady=(10, 0))
        
        close_btn = SpotifyButton(close_frame, text="Kapat", 
                              command=details_window.destroy,
                              width=100, height=35, 
                              bg_color=self.accent_color)
        close_btn.pack(side=tk.RIGHT)
        
        # Pencereyi ortala
        details_window.update_idletasks()
        width = details_window.winfo_width()
        height = details_window.winfo_height()
        x = (details_window.winfo_screenwidth() // 2) - (width // 2)
        y = (details_window.winfo_screenheight() // 2) - (height // 2)
        details_window.geometry('{}x{}+{}+{}'.format(width, height, x, y))
    
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
        style.configure("Spotify.TCombobox", 
                      fieldbackground="#282828", 
                      background=self.card_color, 
                      foreground=self.text_color,
                      selectbackground=self.accent_color,
                      selectforeground=self.text_color)
        
        period_values = ["1", "2", "4", "6", "8", "12", "24", "48", "72"]
        period_combobox = ttk.Combobox(
            period_frame, 
            values=period_values, 
            width=5, 
            state="readonly",
            font=("Arial", 12),
            style="Spotify.TCombobox"
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
        
        # Tema ayarları
        theme_title = tk.Label(settings_content, text="Tema Ayarları", 
                            font=("Arial", 16, "bold"), 
                            bg=self.card_color, fg=self.text_color)
        theme_title.pack(anchor=tk.W, pady=(20, 10))
        
        # Tema renkleri
        theme_frame = tk.Frame(settings_content, bg=self.card_color)
        theme_frame.pack(fill=tk.X, pady=5)
        
        theme_label = tk.Label(theme_frame, text="Vurgu rengi:", 
                            font=("Arial", 12),
                            bg=self.card_color, fg=self.text_color)
        theme_label.pack(side=tk.LEFT, padx=(20, 10))
        
        # Renk seçimi için butonlar
        colors = {
            "Spotify Yeşili": "#1DB954",
            "Mor": "#9C27B0",
            "Mavi": "#2196F3",
            "Turuncu": "#FF9800",
            "Kırmızı": "#F44336"
        }
        
        for name, color in colors.items():
            color_frame = tk.Frame(theme_frame, bg=self.card_color)
            color_frame.pack(side=tk.LEFT, padx=5)
            
            # Renk örneği
            color_sample = tk.Canvas(color_frame, width=20, height=20, 
                                  bg=color, highlightthickness=0)
            color_sample.pack()
            
            # Renk adı
            color_name = tk.Label(color_frame, text=name, 
                              font=("Arial", 8),
                              bg=self.card_color, fg="#B3B3B3")
            color_name.pack()
            
            # Tıklama olayı
            color_sample.bind("<Button-1>", 
                           lambda e, c=color: self._preview_accent_color(c))
        
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
        
        # İptal butonu
        cancel_btn = SpotifyButton(
            save_frame, 
            text="İptal", 
            command=self.load_home_content,
            width=80, 
            height=35, 
            bg_color="#555555",
            hover_color="#666666"
        )
        cancel_btn.pack(side=tk.RIGHT, padx=(0, 10))
    
    def _preview_accent_color(self, color):
        """Vurgu rengini önizleme yapar"""
        # Orijinal rengi geçici olarak değiştir
        original_color = self.accent_color
        self.accent_color = color
        
        # Uyarı mesajı
        messagebox.showinfo(
            "Renk Önizleme", 
            "Bu renk ayarlar kaydedildiğinde uygulanacaktır."
        )
        
        # Orijinal renge geri dön
        self.accent_color = original_color
    
    def save_settings(self, period_value):
        """Ayarları kaydeder"""
        try:
            hours = int(period_value)
            self.period_hours.set(hours)
            
            # Animasyonlu bildirim
            self._show_notification("Ayarlarınız kaydedildi!")
            
            # Ana sayfaya dön
            self.root.after(1000, self.load_home_content)
        except ValueError:
            messagebox.showerror("Hata", "Geçerli bir saat değeri giriniz.")
    
    def _show_notification(self, message, duration=2000, bg_color=None):
        """Animasyonlu bildirim gösterir"""
        if bg_color is None:
            bg_color = self.accent_color
        
        # Bildirim penceresi
        notification = Toplevel(self.root)
        notification.overrideredirect(True)  # Pencere çerçevesini gizle
        notification.attributes("-topmost", True)  # En üstte göster
        notification.configure(bg=bg_color)
        
        # Bildirim içeriği
        padding = 10
        message_label = tk.Label(notification, text=message, 
                              bg=bg_color, fg=self.text_color,
                              font=("Arial", 12), padx=20, pady=padding)
        message_label.pack()
        
        # Boyutu ve konumu hesapla
        notification.update_idletasks()
        width = notification.winfo_width()
        height = notification.winfo_height()
        
        # Ana pencereye göre konumlandır
        x = self.root.winfo_x() + (self.root.winfo_width() // 2) - (width // 2)
        # Başlangıçta ekranın altında
        y_start = self.root.winfo_y() + self.root.winfo_height()
        # Hedef konum: Ana pencere altında
        y_end = self.root.winfo_y() + self.root.winfo_height() - height - 20
        
        notification.geometry(f"{width}x{height}+{x}+{y_start}")
        
        # Animasyon
        steps = 10
        step_y = (y_start - y_end) / steps
        
        def animate_in(step=0):
            if step <= steps:
                y = y_start - (step * step_y)
                notification.geometry(f"{width}x{height}+{x}+{int(y)}")
                notification.after(20, lambda: animate_in(step + 1))
            else:
                # Belirli süre sonra kapat
                notification.after(duration, lambda: animate_out())
        
        def animate_out(step=0):
            if step <= steps:
                y = y_end + (step * step_y)
                notification.geometry(f"{width}x{height}+{x}+{int(y)}")
                notification.after(20, lambda: animate_out(step + 1))
            else:
                notification.destroy()
        
        # Animasyonu başlat
        animate_in()
    
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
