#!/usr/bin/env python3
#!/usr/bin/env python3

import json
import re
import time
import requests
import threading
import websocket
import math
import base64
from datetime import datetime, timedelta
from typing import List, Dict
from urllib.parse import urlparse

class PhishingDetectorCTLogs:
    def __init__(self):
        self.target_brands = [
            'paypal', 'societegenerale', 'bankofamerica', 'chase', 'amazon',
            'microsoft', 'apple', 'google', 'facebook', 'instagram', 'twitter',
            'github', 'visa', 'mastercard', 'americanexpress', 'wells-fargo',
            'citibank', 'hsbc', 'santander', 'barclays', 'lloyds'
        ]
        self.suspicious_keywords = [
            'activity', 'alert', 'purchase', 'authentication', 'authorize', 'bill',
            'client', 'support', 'unlock', 'wallet', 'form', 'log-in', 'live',
            'manage', 'verification', 'webscr', 'authenticate', 'credential',
            'secure', 'login', 'update', 'verify', 'account', 'service', 'official',
            'auth', 'security', 'validation', 'confirmation', 'activation', 'recovery',
            'protect', 'safe', 'signin', 'password', 'customer', 'confirm'
        ]
        self.suspicious_tlds = [
            'bank', 'online', 'business', 'party', 'cc', 'pw', 'center', 'racing',
            'cf', 'ren', 'click', 'review', 'club', 'science', 'country', 'stream',
            'download', 'study', 'ga', 'support', 'gb', 'tech', 'gdn', 'tk', 'gq',
            'top', 'info', 'vip', 'kim', 'win', 'loan', 'work', 'men', 'xin',
            'ml', 'xyz', 'mom'
        ]
        self.free_cas = [
            "let's encrypt", 'letsencrypt', 'cloudflare', 'ssl.com', 'zerossl'
        ]
        self.detected_domains = []
        self.processed_domains = set()
        self.stats = {
            'total_processed': 0,
            'suspicious_found': 0,
            'certstream_active': False,
            'start_time': None
        }
        self.ws = None
        self.monitoring_thread = None

    def calculate_levenshtein_distance(self, s1: str, s2: str) -> int:
        if len(s1) < len(s2):
            return self.calculate_levenshtein_distance(s2, s1)
        if len(s2) == 0:
            return len(s1)
        previous_row = list(range(len(s2) + 1))
        for i, c1 in enumerate(s1):
            current_row = [i + 1]
            for j, c2 in enumerate(s2):
                insertions = previous_row[j + 1] + 1
                deletions = current_row[j] + 1
                substitutions = previous_row[j] + (c1 != c2)
                current_row.append(min(insertions, deletions, substitutions))
            previous_row = current_row
        return previous_row[-1]

    def calculate_shannon_entropy(self, text: str) -> float:
        if not text:
            return 0
        entropy = 0
        for char in set(text):
            prob = text.count(char) / len(text)
            if prob > 0:
                entropy -= prob * math.log2(prob)
        return entropy

    def has_small_levenshtein_distance(self, domain: str) -> bool:
        domain_parts = domain.lower().replace('-', '').replace('.', ' ').split()
        for part in domain_parts:
            for brand in self.target_brands:
                distance = self.calculate_levenshtein_distance(part, brand)
                if distance <= 2 and len(part) >= 4:
                    return True
        return False

    def has_deeply_nested_subdomains(self, domain: str) -> bool:
        subdomain_count = domain.count('.')
        return subdomain_count >= 4

    def is_issued_from_free_ca(self, issuer: str) -> bool:
        issuer_lower = issuer.lower()
        return any(ca in issuer_lower for ca in self.free_cas)

    def has_suspicious_tld(self, domain: str) -> bool:
        tld = domain.split('.')[-1].lower()
        return tld in self.suspicious_tlds

    def has_inner_tld_in_subdomain(self, domain: str) -> bool:
        parts = domain.split('.')
        if len(parts) <= 2:
            return False
        common_tlds = ['com', 'org', 'net', 'edu', 'gov']
        for part in parts[:-1]:
            if part.lower() in common_tlds:
                return True
        return False

    def contains_suspicious_keywords(self, domain: str) -> int:
        domain_lower = domain.lower()
        count = 0
        for keyword in self.suspicious_keywords:
            if keyword in domain_lower:
                count += 1
        return count

    def has_high_shannon_entropy(self, domain: str) -> bool:
        main_domain = domain.split('.')[0]
        entropy = self.calculate_shannon_entropy(main_domain)
        return entropy > 3.5

    def has_hyphens_in_subdomain(self, domain: str) -> bool:
        hyphen_count = domain.count('-')
        return hyphen_count >= 2

    def is_potential_phishing_domain(self, domain: str) -> bool:
        domain_lower = domain.lower().strip()
        if domain_lower.startswith('*.'):
            domain_lower = domain_lower[2:]
        for brand in self.target_brands:
            if brand in domain_lower:
                legitimate_domains = [
                    brand, f"www.{brand}", f"{brand}.com", f"www.{brand}.com",
                    f"{brand}.org", f"{brand}.net", f"m.{brand}.com"
                ]
                if domain_lower not in legitimate_domains:
                    return True
        return False

    def analyze_domain_features(self, domain: str, issuer: str = "") -> Dict:
        features = {}
        score = 0
        reasons = []

        f1 = self.has_small_levenshtein_distance(domain)
        features['small_levenshtein_distance'] = f1
        if f1:
            score += 20
            reasons.append("Podobieństwo do nazw znanych marek")

        f2 = self.has_deeply_nested_subdomains(domain)
        features['deeply_nested_subdomains'] = f2
        if f2:
            score += 15
            reasons.append("Głębokie zagnieżdżenie subdomen")

        f3 = self.is_issued_from_free_ca(issuer)
        features['issued_from_free_ca'] = f3
        if f3:
            score += 10
            reasons.append("Wystawiono przez darmowe CA")

        f4 = self.has_suspicious_tld(domain)
        features['suspicious_tld'] = f4
        if f4:
            score += 15
            reasons.append("Podejrzane TLD")

        f5 = self.has_inner_tld_in_subdomain(domain)
        features['inner_tld_in_subdomain'] = f5
        if f5:
            score += 10
            reasons.append("Obecność TLD w subdomenie")

        f6_count = self.contains_suspicious_keywords(domain)
        features['suspicious_keywords_count'] = f6_count
        if f6_count > 0:
            score += f6_count * 5
            reasons.append(f"Zawiera {f6_count} podejrzanych słów kluczowych")

        f7 = self.has_high_shannon_entropy(domain)
        features['high_shannon_entropy'] = f7
        if f7:
            score += 15
            reasons.append("Wysoka entropia (prawdopodobnie generowana automatycznie)")

        f8 = self.has_hyphens_in_subdomain(domain)
        features['hyphens_in_subdomain'] = f8
        if f8:
            score += 10
            reasons.append("Wiele myślników w domenie")

        if score >= 70:
            category = "wysokie podejrzenie"
        elif score >= 50:
            category = "podejrzana"
        elif score >= 30:
            category = "prawdopodobna"
        elif score >= 15:
            category = "potencjalna"
        else:
            category = "legitna"

        return {
            'domain': domain,
            'issuer': issuer,
            'phishing_score': min(score, 100),
            'phishing_likelihood_category': category,
            'is_likely_phishing': score >= 30,
            'features': features,
            'reasons': reasons,
            'analysis_timestamp': datetime.now().isoformat()
        }

    def get_dnstwister_variants(self, domain: str, limit: int = 15) -> List[str]:
        try:
            print(f"Pobieranie wariantów z DNSTwister dla: {domain}")
            hex_url = f"https://dnstwister.report/api/to_hex/{domain}"
            response = requests.get(hex_url, timeout=10)
            if response.status_code != 200:
                print(f"DNSTwister API niedostępny (status: {response.status_code})")
                return []
            try:
                data = response.json()
                hex_domain = data.get('domain_as_hexadecimal', response.text.strip('"'))
            except:
                hex_domain = response.text.strip('"')
            fuzzy_url = f"https://dnstwister.report/api/fuzz/{hex_domain}"
            fuzzy_response = requests.get(fuzzy_url, timeout=15)
            if fuzzy_response.status_code != 200:
                print(f"DNSTwister API błąd (status: {fuzzy_response.status_code})")
                return []
            fuzzy_data = fuzzy_response.json()
            variants = []
            for item in fuzzy_data.get('fuzzy_domains', []):
                variant = item.get('domain', '').strip()
                if variant and variant != domain and variant not in variants:
                    variants.append(variant)
            print(f"Znaleziono {len(variants)} wariantów DNSTwister")
            return variants[:limit]
        except Exception as e:
            print(f"DNSTwister API niedostępny: {str(e)[:100]}")
            return []

    def save_detection(self, analysis: Dict):
        filename = f"phishing_detections_{datetime.now().strftime('%Y%m%d')}.json"
        try:
            try:
                with open(filename, 'r', encoding='utf-8') as f:
                    data = json.load(f)
            except FileNotFoundError:
                data = []
            data.append(analysis)
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(data, f, indent=2, ensure_ascii=False)
            print(f"Zapisano do {filename}")
        except Exception as e:
            print(f"Błąd zapisu: {e}")

    def on_certstream_message(self, ws, message):
        try:
            data = json.loads(message)
            if data.get('message_type') == 'certificate_update':
                cert_data = data.get('data', {})
                leaf_cert = cert_data.get('leaf_cert', {})
                all_domains = leaf_cert.get('all_domains', [])
                chain = cert_data.get('chain', [])
                issuer = ""
                if chain:
                    issuer_info = chain[0].get('subject', {})
                    issuer = issuer_info.get('aggregated', '') or issuer_info.get('CN', '')
                self.stats['total_processed'] += len(all_domains)
                for domain in all_domains:
                    domain = domain.strip().lstrip('*.')
                    if domain in self.processed_domains:
                        continue
                    self.processed_domains.add(domain)
                    if self.is_potential_phishing_domain(domain):
                        analysis = self.analyze_domain_features(domain, issuer)
                        if analysis['is_likely_phishing']:
                            self.stats['suspicious_found'] += 1
                            print(f"WYKRYTO PHISHING!")
                            print(f"Domena: {domain}")
                            print(f"Kategoria: {analysis['phishing_likelihood_category'].upper()}")
                            print(f"Wynik: {analysis['phishing_score']}/100")
                            print(f"Wystawca: {issuer}")
                            print(f"Powody: {', '.join(analysis['reasons'])}")
                            self.detected_domains.append(analysis)
                            self.save_detection(analysis)
        except:
            pass

    def on_certstream_error(self, ws, error):
        print(f"Błąd certstream: {error}")

    def on_certstream_close(self, ws, close_status_code, close_msg):
        print(f"Połączenie certstream zamknięte")
        self.stats['certstream_active'] = False

    def on_certstream_open(self, ws):
        print("Połączono z certstream.calidog.io")
        self.stats['certstream_active'] = True

    def start_realtime_monitoring(self):
        def run_certstream():
            try:
                self.ws = websocket.WebSocketApp(
                    "wss://certstream.calidog.io/",
                    on_message=self.on_certstream_message,
                    on_error=self.on_certstream_error,
                    on_close=self.on_certstream_close,
                    on_open=self.on_certstream_open
                )
                self.ws.run_forever(reconnect=5)
            except Exception as e:
                print(f"Błąd połączenia certstream: {e}")
                self.stats['certstream_active'] = False

        self.monitoring_thread = threading.Thread(target=run_certstream, daemon=True)
        self.monitoring_thread.start()
        return True

    def monitor_ct_logs_realtime(self):
        print("SYSTEM WYKRYWANIA PHISHINGU W CT LOGS")
        print("="*60)
        print("Monitorowanie w czasie rzeczywistym logów Certificate Transparency")
        print("Wyszukiwanie domen phishingowych za pomocą 8 cech")
        print("Aby zatrzymać, wciśnij Ctrl+C")
        print("-"*60)
        self.stats['start_time'] = datetime.now()
        self.start_realtime_monitoring()
        timeout = 15
        while not self.stats['certstream_active'] and timeout > 0:
            print(f"Łączenie z certstream.calidog.io... ({timeout}s)")
            time.sleep(1)
            timeout -= 1
        if not self.stats['certstream_active']:
            print("Nie udało się połączyć z certstream")
            return
        try:
            print("Monitorowanie aktywne! Analiza certyfikatów na żywo...")
            while self.stats['certstream_active']:
                time.sleep(30)
                elapsed = datetime.now() - self.stats['start_time']
                print(f"\nSTATYSTYKI ({elapsed.seconds//60}m {elapsed.seconds%60}s)")
                print(f"Przetworzonych domen: {self.stats['total_processed']}")
                print(f"Podejrzanych domen: {self.stats['suspicious_found']}")
                if self.stats['total_processed'] > 0:
                    detection_rate = (self.stats['suspicious_found']/self.stats['total_processed']*100)
                    print(f"Skuteczność wykrywania: {detection_rate:.4f}%")
        except KeyboardInterrupt:
            print("\nZatrzymano monitorowanie...")
            self.stop_monitoring()
            print("Wyniki końcowe:")
            print(f"Wykryto {len(self.detected_domains)} podejrzanych domen")

    def stop_monitoring(self):
        self.stats['certstream_active'] = False
        if self.ws:
            self.ws.close()

    def analyze_historical_data(self, hours_back: int = 24, max_per_brand: int = 50):
        print(f"ANALIZA HISTORYCZNYCH LOGÓW CT (ostatnie {hours_back}h)")
        print("Używanie API crt.sh (do demonstracji)")
        print("-"*60)
        total_suspicious = 0
        for brand in self.target_brands[:5]:
            print(f"Wyszukiwanie certyfikatów dla: {brand}")
            try:
                url = f"https://crt.sh/?q=%25{brand}%25&output=json"
                response = requests.get(url, timeout=15)
                if response.status_code != 200:
                    print(f"Błąd dla {brand}: HTTP {response.status_code}")
                    continue
                certificates = response.json()
                cutoff_time = datetime.now() - timedelta(hours=hours_back)
                recent_certs = []
                for cert in certificates[:200]:
                    try:
                        entry_time = datetime.fromisoformat(
                            cert.get('entry_timestamp', '').replace('Z', '+00:00')
                        )
                        if entry_time >= cutoff_time:
                            recent_certs.append(cert)
                    except:
                        continue
                print(f"Znaleziono {len(recent_certs)} nowych certyfikatów")
                brand_suspicious = 0
                processed_for_brand = 0
                for cert in recent_certs[:max_per_brand]:
                    domain_names = cert.get('name_value', '').split('\n')
                    for domain in domain_names:
                        domain = domain.strip().lstrip('*.')
                        if not domain or domain in self.processed_domains:
                            continue
                        self.processed_domains.add(domain)
                        processed_for_brand += 1
                        if self.is_potential_phishing_domain(domain):
                            issuer_name = cert.get('issuer_name', '')
                            analysis = self.analyze_domain_features(domain, issuer_name)
                            if analysis['is_likely_phishing']:
                                brand_suspicious += 1
                                total_suspicious += 1
                                print(f"PODEJRZANE: {domain}")
                                print(f"Kategoria: {analysis['phishing_likelihood_category']}")
                                print(f"Wynik: {analysis['phishing_score']}")
                                print(f"Wystawca: {issuer_name}")
                                self.detected_domains.append(analysis)
                                self.save_detection(analysis)
                        if processed_for_brand >= max_per_brand:
                            break
                    if processed_for_brand >= max_per_brand:
                        break
                print(f"Przetworzono: {processed_for_brand} domen")
                print(f"Podejrzanych domen dla {brand}: {brand_suspicious}")
                time.sleep(2)
            except Exception as e:
                print(f"Błąd przetwarzania {brand}: {e}")
        print("\nANALIZA HISTORYCZNA ZAKOŃCZONA")
        print(f"Liczba podejrzanych domen: {total_suspicious}")
        return total_suspicious

    def analyze_single_domain(self, domain: str, check_variants: bool = True):
        print(f"\nANALIZA DOMENY: {domain}")
        print("-"*50)
        if self.is_potential_phishing_domain(domain):
            analysis = self.analyze_domain_features(domain)
            print(f"Wynik: {analysis['phishing_likelihood_category'].upper()}")
            print(f"Ocena phishingowa: {analysis['phishing_score']}/100")
            if analysis['reasons']:
                print("Powody wykrycia:")
                for reason in analysis['reasons']:
                    print(f"  - {reason}")
            print("\nAnaliza cech (Phish-Hook):")
            features = analysis['features']
            print(f"  F1 - Mała odległość Levenshteina: {features['small_levenshtein_distance']}")
            print(f"  F2 - Głębokie subdomeny: {features['deeply_nested_subdomains']}")
            print(f"  F3 - Darmowe CA: {features['issued_from_free_ca']}")
            print(f"  F4 - Podejrzane TLD: {features['suspicious_tld']}")
            print(f"  F5 - TLD w subdomenie: {features['inner_tld_in_subdomain']}")
            print(f"  F6 - Liczba podejrzanych słów kluczowych: {features['suspicious_keywords_count']}")
            print(f"  F7 - Wysoka entropia: {features['high_shannon_entropy']}")
            print(f"  F8 - Myślniki w subdomenie: {features['hyphens_in_subdomain']}")
            if check_variants:
                print("\nSprawdzanie wariantów DNSTwister...")
                variants = self.get_dnstwister_variants(domain)
                if variants:
                    suspicious_variants = []
                    for variant in variants:
                        if self.is_potential_phishing_domain(variant):
                            var_analysis = self.analyze_domain_features(variant)
                            if var_analysis['is_likely_phishing']:
                                suspicious_variants.append((variant, var_analysis['phishing_likelihood_category']))
                    if suspicious_variants:
                        print(f"Wykryto {len(suspicious_variants)} podejrzanych wariantów:")
                        for variant, category in suspicious_variants:
                            print(f"  {variant} ({category})")
                    else:
                        print("Brak podejrzanych wariantów")
            return analysis
        else:
            print("Domena nie zawiera obserwowanych marek")
            return None

def main():
    detector = PhishingDetectorCTLogs()
    print("SYSTEM WYKRYWANIA PHISHINGU NA PODSTAWIE CT LOGS")
    print("Analiza Certificate Transparency Logs pod kątem wykrywania phishingu")
    print("="*70)
    while True:
        print(f"\nMonitorowane marki: {len(detector.target_brands)}")
        print("Przykładowe marki: paypal, societegenerale, bankofamerica, chase, amazon itd.")
        print("\nMenu:")
        print("1. Monitorowanie CT Logs na żywo (certstream.calidog.io)")
        print("2. Analiza historyczna (crt.sh API - demonstracja)")
        print("3. Analiza pojedynczej domeny")
        print("4. Generuj warianty typosquattingu (DNSTwister)")
        print("5. Statystyki wykrywania")
        print("6. Wyjście")
        choice = input("\nWybierz opcję (1-6): ").strip()
        if choice == '1':
            detector.monitor_ct_logs_realtime()
        elif choice == '2':
            try:
                hours = int(input("Podaj liczbę godzin wstecz do analizy: ").strip())
            except ValueError:
                hours = 24
            try:
                max_per_brand = int(input("Maksymalnie domen na markę (np. 50): ").strip())
            except ValueError:
                max_per_brand = 50
            detector.analyze_historical_data(hours_back=hours, max_per_brand=max_per_brand)
        elif choice == '3':
            domain = input("Podaj domenę do analizy: ").strip()
            if domain:
                detector.analyze_single_domain(domain)
            else:
                print("Nie podano domeny.")
        elif choice == '4':
            domain = input("Podaj domenę do wygenerowania wariantów: ").strip()
            if domain:
                print(f"\nGenerowanie wariantów typosquattingu dla: {domain}")
                variants = detector.get_dnstwister_variants(domain)
                if variants:
                    print(f"\nZnaleziono {len(variants)} wariantów:")
                    for i, v in enumerate(variants, 1):
                        print(f"{i}. {v}")
                else:
                    print("Nie udało się pobrać wariantów z DNSTwister API.")
            else:
                print("Nie podano domeny.")
        elif choice == '5':
            print(f"\nSTATYSTYKI WYKRYWANIA:")
            print(f"Znalezione podejrzane domeny: {len(detector.detected_domains)}")
            print(f"Przetworzone domeny: {len(detector.processed_domains)}")
            print(f"Monitorowane marki: {len(detector.target_brands)}")
            if detector.detected_domains:
                print(f"\nOstatnie 5 wykryć:")
                for detection in detector.detected_domains[-5:]:
                    domain = detection['domain']
                    category = detection['phishing_likelihood_category']
                    score = detection['phishing_score']
                    print(f"  - {domain} ({category}, wynik: {score})")
            else:
                print("Brak wykryć.")
        elif choice == '6':
            if detector.stats.get('certstream_active'):
                detector.stop_monitoring()
            print("Do zobaczenia!")
            break
        else:
            print("Niepoprawna opcja. Wybierz 1-6.")

if __name__ == "__main__":
    main()
