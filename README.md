# PhishHook Detector

System wykrywania potencjalnych domen phishingowych na podstawie Certificate Transparency Logs (CT Logs).

## Opis projektu

Projekt realizuje analizę logów certyfikatów SSL/TLS w czasie rzeczywistym z wykorzystaniem API `certstream.calidog.io`. Wyszukiwane są nowe certyfikaty zawierające znane marki (np. paypal, bankofamerica), a następnie oceniane są cechy domen wskazujące na potencjalny phishing. Program wspiera także analizę historyczną z `crt.sh` oraz generowanie wariantów typosquattingu za pomocą `dnstwister.report`.

Projekt oparty jest na podejściu heurystycznym opisanym w pracy naukowej:  
**"Phish-Hook: Detecting Phishing Certificates Using Certificate Transparency Logs"**

## Funkcjonalności

- Monitorowanie CT Logs w czasie rzeczywistym
- Wykrywanie podejrzanych domen zawierających nazwy znanych marek
- Generowanie typosquattingu (wariantów literówek) za pomocą DNSTwister
- Heurystyczna analiza phishingowa oparta na 8 cechach:
  - F1: Mała odległość Levenshteina do nazwy marki
  - F2: Głębokie subdomeny
  - F3: Certyfikat wystawiony przez darmowe CA
  - F4: Podejrzane rozszerzenie domeny (TLD)
  - F5: Obecność TLD w subdomenie
  - F6: Obecność podejrzanych słów kluczowych
  - F7: Wysoka entropia domeny (generowana automatycznie)
  - F8: Duża liczba myślników w nazwie domeny

## Wymagania

- Python 3.7 lub nowszy
- Zainstalowane biblioteki:
  - `requests`
  - `websocket-client`

Można je zainstalować komendą:
```bash
pip install -r requirements.txt
```

## Uruchomienie

```bash
python detector.py
```

Po uruchomieniu wyświetli się menu wyboru:
1. Monitorowanie logów w czasie rzeczywistym  
2. Analiza historyczna na podstawie danych z `crt.sh`  
3. Analiza jednej domeny  
4. Generowanie wariantów typosquattingu  
5. Statystyki  
6. Wyjście  

## Pliki

- `detector.py` – główny plik programu
- `requirements.txt` – wymagane biblioteki
- `README.md` – dokumentacja
- `phishing_detections_YYYYMMDD.json` – zapis wykrytych domen

Autorzy:
**Adam Waśko (115986)**  
**Szymon Świercz (119274)**  
**Karolina Woch (119293)**  
**Aleksandra Szymańska (120851)**
Rok: 2025
