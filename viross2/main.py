#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
Viros Mitm - Gelişmiş ARP Spoofing Tespit Aracı
Bu uygulama, ağ arayüzlerini potansiyel ARP spoofing saldırıları için izler,
arka planda zamanlanmış taramalar yapar ve sistemle otomatik olarak başlayacak
şekilde yapılandırılabilir.

Sürüm: 1.0
"""

import os
import sys
import tkinter as tk
import traceback
from tkinter import messagebox

def main():
    """
    Ana uygulama giriş noktası.
    all_in_one.py dosyasını çalıştırır.
    """
    try:
        # all_in_one.py'ı içe aktar ve main() fonksiyonunu çalıştır
        # Bu dosya, uygulamanın tüm işlevselliğini içerir
        import all_in_one
        all_in_one.main()
    except ImportError:
        # all_in_one.py bulunamadı veya içe aktarılamadı
        messagebox.showerror(
            "Hata", 
            "all_in_one.py dosyası bulunamadı veya içe aktarılamadı.\n"
            "Lütfen dosyanın mevcut olduğunu kontrol edin."
        )
    except Exception as e:
        # Diğer hatalar
        error_msg = f"Hata: {str(e)}\n\n{traceback.format_exc()}"
        print(error_msg)
        messagebox.showerror("Viros Mitm - Hata", error_msg)

if __name__ == "__main__":
    # --minimized parametresiyle çalıştırıldıysa
    if len(sys.argv) > 1 and sys.argv[1] == "--minimized":
        # Küçültülmüş olarak başlatmak için
        os.environ["START_MINIMIZED"] = "1"
        
    main()
