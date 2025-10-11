# Kriptoloji Sunucu-Client Uygulaması

Bu proje Flask ve Socket.IO kullanılarak geliştirilmiş bir şifreleme tabanlı mesajlaşma sistemidir.  
Sunucu (Server) ve istemci (Client) arayüzleri arasında gerçek zamanlı iletişim sağlanır.  
Mesajlar gönderilmeden önce seçilen algoritmayla şifrelenir ve karşı tarafta çözülmüş olarak görüntülenir.

Desteklenen algoritmalar: Caesar, Vigenere, Substitution, Affine

---

## Özellikler

- Gerçek zamanlı iki yönlü mesajlaşma (Socket.IO)
- Arayüzden algoritma ve anahtar seçimi
- Otomatik şifreleme ve çözme işlemleri
- IP ve port yapılandırması
- Basit web arayüzü

---

## Çalışma Mantığı

1. Sunucu başlatılır.  
   server.py dosyası seçilen IP ve port üzerinden dinlemeye başlar.

2. Client dinlemeyi başlatır.  
   client.py belirtilen IP ve port üzerinden sunucuyla bağlantı kurar.

3. Mesaj gönderilir.  
   İki taraf arasında şifrelenmiş mesaj alışverişi yapılır.  
   Her iki tarafın arayüzünde de mesajın şifreli ve çözülmüş hali görüntülenir.

---

## Gereksinimler

- Python 3.10 veya üzeri  
- Gerekli kütüphaneler:
## Çalıştırma
python server.py
python client.py