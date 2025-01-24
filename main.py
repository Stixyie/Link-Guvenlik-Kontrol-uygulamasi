import sys
import os
import json
import time
import re
import socket
import ssl
import logging
import urllib.parse
import requests
from bs4 import BeautifulSoup
import cloudscraper
from PyQt6.QtWidgets import *
from PyQt6.QtCore import *
from PyQt6.QtGui import QFont, QIcon, QColor, QTextCharFormat, QBrush, QPalette, QAction
from selenium import webdriver
from selenium.webdriver.chrome.service import Service
from selenium.webdriver.chrome.options import Options
from webdriver_manager.chrome import ChromeDriverManager
import numpy as np
from sklearn.ensemble import RandomForestClassifier
import joblib
import tld
import whois
from datetime import datetime
import hashlib
import validators
from dotenv import load_dotenv
import base64
load_dotenv()
from PyQt6.QtCore import QPropertyAnimation, QEasingCurve, QPoint, QTimer, Qt, QRect
import urllib3
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

class SecurityMLAnalyzer:
    def __init__(self):
        self.feature_names = [
            'has_ssl', 'domain_age_days', 'url_length', 'num_subdomains',
            'num_special_chars', 'has_suspicious_words', 'has_ip_address',
            'redirect_count', 'external_resources_count', 'form_count',
            'js_obfuscation_score', 'domain_expiry_days', 'uses_https',
            'ssl_issuer_trusted', 'blacklist_score'
        ]
        self.model = self._initialize_model()
        
        # JavaScript risk patterns with weights
        self.js_risk_patterns = {
            'eval(': 0.4,
            'document.write(': 0.3,
            'unescape(': 0.4,
            'escape(': 0.2,
            'fromCharCode': 0.3,
            'atob(': 0.3,
            'btoa(': 0.2,
            'decodeURIComponent(': 0.2,
            'encodeURIComponent(': 0.1,
            '.replace(': 0.1,
            'window.location': 0.3,
            'document.cookie': 0.4,
            'document.referrer': 0.2,
            'document.domain': 0.2,
            'prompt(': 0.3,
            'alert(': 0.1,
            'confirm(': 0.1,
            'debugger': 0.2,
            'new Function(': 0.4,
            'setTimeout(': 0.2,
            'setInterval(': 0.2,
            'XMLHttpRequest': 0.2,
            'fetch(': 0.2,
            'WebSocket': 0.2,
            'localStorage': 0.1,
            'sessionStorage': 0.1,
            'indexedDB': 0.1,
            'document.createElement': 0.2,
            'document.getElementById': 0.1,
            'innerHTML': 0.3,
            'onclick': 0.1,
            'onload': 0.1,
            'onerror': 0.2
        }
        
    def _initialize_model(self):
        try:
            # Try to load existing model
            return joblib.load('security_model.joblib')
        except:
            # Create a simple default model if no saved model exists
            from sklearn.ensemble import RandomForestClassifier
            from sklearn.model_selection import train_test_split
            
            # Generate synthetic training data
            safe_features = []
            unsafe_features = []
            
            # Generate 100 safe and 100 unsafe feature sets
            for _ in range(100):
                # Safe website features
                safe_feature = [
                    1,                              # has_ssl
                    np.random.randint(100, 1000),   # domain_age_days
                    np.random.uniform(0.1, 0.5),    # url_length (normalized)
                    np.random.uniform(0, 0.2),      # num_subdomains (normalized)
                    np.random.uniform(0, 0.3),      # num_special_chars (normalized)
                    0,                              # has_suspicious_words
                    0,                              # has_ip_address
                    np.random.uniform(0, 0.2),      # redirect_count (normalized)
                    np.random.uniform(0.1, 0.5),    # external_resources_count (normalized)
                    np.random.uniform(0, 0.3),      # form_count (normalized)
                    np.random.uniform(0, 0.2),      # js_obfuscation_score
                    np.random.randint(100, 1000),   # domain_expiry_days
                    1,                              # uses_https
                    1,                              # ssl_issuer_trusted
                    0                               # blacklist_score
                ]
                safe_features.append(safe_feature)
                
                # Unsafe website features
                unsafe_feature = [
                    np.random.choice([0, 1]),       # has_ssl
                    np.random.randint(0, 30),       # domain_age_days
                    np.random.uniform(0.5, 1.0),    # url_length (normalized)
                    np.random.uniform(0.5, 1.0),    # num_subdomains (normalized)
                    np.random.uniform(0.5, 1.0),    # num_special_chars (normalized)
                    np.random.choice([0, 1]),       # has_suspicious_words
                    np.random.choice([0, 1]),       # has_ip_address
                    np.random.uniform(0.5, 1.0),    # redirect_count (normalized)
                    np.random.uniform(0.5, 1.0),    # external_resources_count (normalized)
                    np.random.uniform(0.5, 1.0),    # form_count (normalized)
                    np.random.uniform(0.5, 1.0),    # js_obfuscation_score
                    np.random.randint(0, 30),       # domain_expiry_days
                    np.random.choice([0, 1]),       # uses_https
                    0,                              # ssl_issuer_trusted
                    np.random.uniform(0.3, 1.0)     # blacklist_score
                ]
                unsafe_features.append(unsafe_feature)
            
            # Combine features and labels
            X = np.vstack([safe_features, unsafe_features])
            y = np.hstack([np.ones(100), np.zeros(100)])  # 1 for safe, 0 for unsafe
            
            # Create and train a simple RandomForestClassifier
            model = RandomForestClassifier(
                n_estimators=100,
                max_depth=10,
                min_samples_split=5,
                class_weight='balanced',
                random_state=42
            )
            
            # Train the model
            model.fit(X, y)
            
            # Try to save the model
            try:
                joblib.dump(model, 'security_model.joblib')
            except Exception as e:
                logging.error(f"Model kaydetme hatası: {str(e)}")
            
            return model
        
    def calculate_js_risk(self, js_code):
        """JavaScript risk skorunu hesapla"""
        if not js_code:
            return 0.0
            
        total_risk = 0.0
        code_lower = js_code.lower()
        
        # Risk pattern kontrolü
        for pattern, weight in self.js_risk_patterns.items():
            if pattern.lower() in code_lower:
                total_risk += weight
                
        # Obfuscation kontrolü
        obfuscation_indicators = [
            len(re.findall(r'\\x[0-9a-fA-F]{2}', js_code)),  # hex encoding
            len(re.findall(r'\\u[0-9a-fA-F]{4}', js_code)),  # unicode encoding
            len(re.findall(r'\\[0-7]{3}', js_code)),         # octal encoding
            js_code.count('^'),                               # XOR operations
            js_code.count('~'),                               # bitwise operations
            len(re.findall(r'String\.fromCharCode', js_code, re.I))
        ]
        
        obfuscation_score = sum(1 for x in obfuscation_indicators if x > 0) / len(obfuscation_indicators)
        total_risk += obfuscation_score * 0.5  # Obfuscation'a %50 ağırlık ver
        
        # Risk skorunu 0-1 aralığına normalize et
        return min(1.0, total_risk)
        
    def analyze_security(self, url, soup, ssl_info):
        try:
            # Extract features
            features = np.zeros((1, len(self.feature_names)))
            
            # Basic URL features
            parsed_url = urllib.parse.urlparse(url)
            
            # SSL and Protocol Analysis
            is_https = url.startswith('https://')
            features[0, 0] = 1 if is_https else 0  # has_ssl
            features[0, 12] = 1 if is_https else 0  # uses_https
            features[0, 13] = 1 if ssl_info.get('issuer_trusted', False) else 0  # ssl_issuer_trusted
            
            # URL Structure Analysis
            url_length = len(url)
            features[0, 2] = min(url_length / 200.0, 1.0)  # Normalize URL length
            
            # Subdomain Analysis
            subdomains = parsed_url.netloc.split('.')
            num_subdomains = len(subdomains) - 2 if len(subdomains) > 2 else 0
            features[0, 3] = min(num_subdomains / 3.0, 1.0)  # Normalize subdomain count
            
            # Special Characters Analysis
            special_chars = len(re.findall(r'[^a-zA-Z0-9.-]', parsed_url.netloc))
            features[0, 4] = min(special_chars / 5.0, 1.0)  # Normalize special chars
            
            # IP Address Detection
            has_ip = bool(re.search(r'\d+\.\d+\.\d+\.\d+', parsed_url.netloc))
            features[0, 6] = 1 if has_ip else 0
            
            # Content Analysis
            js_risk_score = 0.0
            if soup:
                # Form Analysis
                forms = soup.find_all('form')
                form_count = len(forms)
                features[0, 9] = min(form_count / 5.0, 1.0)  # Normalize form count
                
                # External Resources Analysis
                external_resources = len(soup.find_all(['script', 'link', 'img']))
                features[0, 8] = min(external_resources / 30.0, 1.0)  # Normalize external resources
                
                # JavaScript Analysis
                scripts = soup.find_all('script')
                js_code = ' '.join([str(s.string) for s in scripts if s.string])
                js_risk_score = self.calculate_js_risk(js_code)
                features[0, 10] = js_risk_score
            
            # Model Prediction
            if self.model is not None:
                try:
                    # Get probability of being safe
                    proba = self.model.predict_proba(features)
                    if proba.shape[1] > 1:
                        ml_score = proba[0, 1] * 100  # Probability of being safe
                    else:
                        ml_score = proba[0, 0] * 100
                except Exception as e:
                    logging.error(f"Model tahmin hatası: {str(e)}")
                    # Calculate fallback score based on weighted features
                    weights = {
                        'ssl': 0.3,
                        'url_length': 0.1,
                        'subdomains': 0.15,
                        'special_chars': 0.15,
                        'ip_address': 0.2,
                        'js_risk': 0.1
                    }
                    
                    safe_indicators = {
                        'ssl': features[0, 0],  # has_ssl
                        'url_length': 1 - features[0, 2],  # inverse of url_length
                        'subdomains': 1 - features[0, 3],  # inverse of num_subdomains
                        'special_chars': 1 - features[0, 4],  # inverse of special_chars
                        'ip_address': 1 - features[0, 6],  # inverse of has_ip
                        'js_risk': 1 - features[0, 10]  # inverse of js_risk
                    }
                    
                    ml_score = sum(safe_indicators[k] * weights[k] for k in weights.keys()) * 100
            else:
                # Fallback scoring if model is not available
                weights = {
                    'https': 0.3,
                    'ip': 0.2,
                    'subdomains': 0.2,
                    'special_chars': 0.15,
                    'js_risk': 0.15
                }
                
                safe_indicators = {
                    'https': 1 if is_https else 0,
                    'ip': 1 if not has_ip else 0,
                    'subdomains': 1 if num_subdomains <= 2 else max(0, 1 - (num_subdomains - 2) * 0.2),
                    'special_chars': 1 if special_chars <= 3 else max(0, 1 - (special_chars - 3) * 0.2),
                    'js_risk': 1 if js_risk_score < 0.3 else max(0, 1 - js_risk_score)
                }
                
                ml_score = sum(safe_indicators[k] * weights[k] for k in weights.keys()) * 100
            
            # Generate warnings based on risk factors
            warnings = []
            if not is_https:
                warnings.append("SSL güvenliği eksik")
            if has_ip:
                warnings.append("URL'de IP adresi kullanılmış")
            if num_subdomains > 2:
                warnings.append(f"Çok sayıda alt domain ({num_subdomains} adet)")
            if special_chars > 3:
                warnings.append(f"URL'de çok sayıda özel karakter ({special_chars} adet)")
            if js_risk_score >= 0.3:
                warnings.append("Şüpheli JavaScript kodları tespit edildi")
            
            # Calculate final security score
            security_score = ml_score
            
            # Determine risk level based on security score
            if security_score >= 80:
                risk_level = "Düşük Risk"
            elif security_score >= 60:
                risk_level = "Orta Risk"
            else:
                risk_level = "Yüksek Risk"
            
            return {
                'final_score': round(security_score, 2),
                'ml_score': round(ml_score, 2),
                'js_risk_score': round(js_risk_score, 3),
                'risk_level': risk_level,
                'warnings': warnings,
                'details': {
                    'SSL Güvenliği': 'Güvenli' if is_https else 'Güvensiz',
                    'URL Analizi': {
                        'Alt Domain Sayısı': num_subdomains,
                        'Özel Karakter Sayısı': special_chars,
                        'IP Adresi Var Mı': 'Evet' if has_ip else 'Hayır'
                    },
                    'İçerik Analizi': {
                        'JavaScript Risk Skoru': f"{js_risk_score:.2f}/1.00",
                        'Harici Kaynak Sayısı': external_resources if 'external_resources' in locals() else 0
                    }
                }
            }
            
        except Exception as e:
            logging.error(f"Güvenlik analizi hatası: {str(e)}")
            return {
                'final_score': 0,
                'ml_score': 0,
                'js_risk_score': 0,
                'risk_level': 'Hata',
                'warnings': [f"Analiz sırasında hata: {str(e)}"],
                'details': {}
            }

class URLScanner(QObject):
    # Sinyaller
    scan_completed = pyqtSignal(dict)  # Tarama sonuçları için sinyal
    progress_updated = pyqtSignal(int)  # İlerleme durumu için sinyal
    error_occurred = pyqtSignal(str)    # Hata durumları için sinyal
    
    def __init__(self):
        super().__init__()
        self.scraper = cloudscraper.create_scraper(
            browser={
                'browser': 'chrome',
                'platform': 'windows',
                'mobile': False
            }
        )
        self.session = requests.Session()
        self.session.verify = False  # SSL doğrulamasını devre dışı bırak
        self.setup_selenium()
        self.ml_analyzer = SecurityMLAnalyzer()
        # Bilinen güvenli domainler - genişletilmiş liste
        self.safe_domains = {
            'google.com', 'www.google.com', 'drive.google.com', 'docs.google.com',
            'youtube.com', 'www.youtube.com',
            'facebook.com', 'www.facebook.com',
            'twitter.com', 'www.twitter.com', 'x.com',
            'instagram.com', 'www.instagram.com',
            'linkedin.com', 'www.linkedin.com',
            'github.com', 'www.github.com',
            'microsoft.com', 'www.microsoft.com', 'office.com', 'live.com',
            'apple.com', 'www.apple.com', 'icloud.com',
            'amazon.com', 'www.amazon.com',
            'netflix.com', 'www.netflix.com',
            'spotify.com', 'www.spotify.com',
            'yahoo.com', 'www.yahoo.com',
            'wikipedia.org', 'www.wikipedia.org',
            'cloudflare.com', 'www.cloudflare.com',
            'dropbox.com', 'www.dropbox.com',
            'wordpress.com', 'www.wordpress.com',
            'mozilla.org', 'www.mozilla.org',
            'whatsapp.com', 'web.whatsapp.com',
            'reddit.com', 'www.reddit.com',
            'medium.com', 'www.medium.com',
            'codeium.com', 'www.codeium.com'
        }
        
    @pyqtSlot(str)
    def scan_url(self, url):
        """URL'yi tara ve sonuçları döndür"""
        try:
            self.progress_updated.emit(10)
            
            if not url:
                self.error_occurred.emit("URL boş olamaz")
                return
            
            # URL doğrulama
            if not url.startswith(('http://', 'https://')):
                url = 'https://' + url
            
            if not validators.url(url):
                self.error_occurred.emit("Geçersiz URL formatı")
                return
            
            # API anahtarlarını kontrol et
            if not os.getenv('URLSCAN_API_KEY') or not os.getenv('VIRUSTOTAL_API_KEY'):
                self.error_occurred.emit("URLScan.io ve VirusTotal API anahtarları eksik")
                return
            
            results = {
                'url': url,
                'security_score': 0,
                'warnings': []
            }
            
            # SSL kontrolü
            self.progress_updated.emit(20)
            ssl_info = self.check_ssl(url)
            results['ssl_info'] = ssl_info
            
            # URLScan.io taraması
            self.progress_updated.emit(40)
            urlscan_results = self.scan_urlscan_io(url)
            results['urlscan_results'] = urlscan_results
            
            # VirusTotal taraması
            self.progress_updated.emit(60)
            virustotal_results = self.scan_virustotal(url)
            results['virustotal_results'] = virustotal_results
            
            # ML analizi
            self.progress_updated.emit(80)
            ml_results = self.scan_ml_based(url)
            if ml_results.get('warnings'):
                results['warnings'].extend(ml_results['warnings'])
            
            # Genel güvenlik skoru hesapla
            scores = []
            
            if urlscan_results.get('score') is not None:
                scores.append(urlscan_results['score'])
            
            if virustotal_results.get('score') is not None:
                scores.append(virustotal_results['score'])
            
            if ssl_info.get('ssl_status'):
                scores.append(100)
            else:
                scores.append(0)
                results['warnings'].append(ssl_info.get('error', 'SSL sertifikası bulunamadı'))
            
            if scores:
                results['security_score'] = sum(scores) / len(scores)
            
            self.progress_updated.emit(100)
            self.scan_completed.emit(results)
            
        except Exception as e:
            error_msg = f"Tarama sırasında hata oluştu: {str(e)}"
            logging.error(error_msg)
            self.error_occurred.emit(error_msg)
    
    def is_safe_domain(self, domain):
        """Güvenli domain kontrolü"""
        domain = domain.lower()
        return (
            domain in self.safe_domains or 
            any(domain.endswith('.' + d) for d in self.safe_domains) or
            any(d.endswith('.' + domain) for d in self.safe_domains)
        )
        
    def calculate_base_security_score(self, url, ssl_info):
        """Temel güvenlik skoru hesaplama"""
        score = 0
        warnings = []
        
        # HTTPS kontrolü (30 puan)
        if url.startswith('https://'):
            score += 30
        else:
            warnings.append("SSL güvenliği eksik")
            
        # SSL sertifika kontrolü (20 puan)
        if ssl_info.get('ssl_status', False):
            score += 20
        
        # Domain kontrolü (30 puan)
        domain = urllib.parse.urlparse(url).netloc.lower()
        if self.is_safe_domain(domain):
            score += 30
            
        # Şüpheli kelime kontrolü (20 puan)
        suspicious_words = ['hack', 'crack', 'warez', 'keygen', 'torrent', 'spam', 'phish']
        if not any(word in url.lower() for word in suspicious_words):
            score += 20
        else:
            warnings.append("URL'de şüpheli kelimeler tespit edildi")
            
        return score, warnings
        
    def scan_urlscan_io(self, url):
        """URLScan.io API ile URL taraması yap"""
        try:
            api_key = os.getenv('URLSCAN_API_KEY')
            if not api_key:
                return {
                    'error': 'URLScan.io API anahtarı bulunamadı',
                    'score': 0,
                    'malicious': True,
                    'message': 'API anahtarı eksik'
                }

            headers = {
                'API-Key': api_key,
                'Content-Type': 'application/json'
            }
            data = {
                'url': url,
                'visibility': 'public'
            }

            # Tarama isteği gönder
            scan_url = 'https://urlscan.io/api/v1/scan/'
            response = requests.post(scan_url, headers=headers, json=data)

            if response.status_code != 200:
                error_msg = f'URLScan.io API Hatası: {response.text}'
                return {
                    'error': error_msg,
                    'score': 0,
                    'malicious': True,
                    'message': error_msg
                }

            scan_results = response.json()
            result_url = scan_results.get('api')

            if not result_url:
                return {
                    'error': 'URLScan.io sonuç URL\'si alınamadı',
                    'score': 0,
                    'malicious': True,
                    'message': 'Sonuç URL\'si eksik'
                }

            # Sonuçların hazır olmasını bekle
            time.sleep(10)

            # Sonuçları al
            result_response = requests.get(result_url)
            if result_response.status_code != 200:
                error_msg = f'URLScan.io sonuçları alınamadı: {result_response.text}'
                return {
                    'error': error_msg,
                    'score': 0,
                    'malicious': True,
                    'message': error_msg
                }

            results = result_response.json()
            
            # Güvenlik skorunu hesapla
            score = 100
            warnings = []
            
            # Malicious göstergeleri kontrol et
            if results.get('verdicts', {}).get('overall', {}).get('malicious'):
                score -= 50
                warnings.append("URLScan.io tarafından zararlı olarak işaretlendi")
            
            # Şüpheli göstergeleri kontrol et
            if results.get('verdicts', {}).get('overall', {}).get('suspicious'):
                score -= 25
                warnings.append("URLScan.io tarafından şüpheli olarak işaretlendi")

            return {
                'score': score,
                'malicious': score < 50,
                'message': 'URLScan.io taraması tamamlandı',
                'warnings': warnings,
                'details': {
                    'screenshot': results.get('task', {}).get('screenshotURL'),
                    'report': results.get('task', {}).get('reportURL'),
                    'categories': results.get('verdicts', {}).get('overall', {}).get('categories', [])
                }
            }

        except Exception as e:
            error_msg = f'URLScan.io taraması sırasında hata: {str(e)}'
            logging.error(error_msg)
            return {
                'error': error_msg,
                'score': 0,
                'malicious': True,
                'message': error_msg
            }
    
    def scan_ml_based(self, url):
        try:
            # SSL kontrolleri
            ssl_info = self.check_ssl(url)
            
            # Sayfa içeriğini al
            try:
                response = self.scraper.get(url, timeout=10)
                soup = BeautifulSoup(response.text, 'lxml')
            except:
                try:
                    # Selenium ile dene
                    self.driver.get(url)
                    time.sleep(2)
                    soup = BeautifulSoup(self.driver.page_source, 'lxml')
                except:
                    soup = None
        
            # ML tabanlı güvenlik analizi
            security_report = self.ml_analyzer.analyze_security(url, soup, ssl_info)
        
            return {
                'status': 'success',
                'ml_security_score': security_report.get('final_score', 0),
                'risk_level': security_report.get('risk_level', 'Bilinmiyor'),
                'warnings': security_report.get('warnings', []),
                'details': security_report.get('details', {})
            }
        except Exception as e:
            logging.error(f"ML tabanlı tarama hatası: {str(e)}")
            return {
                'status': 'error',
                'ml_security_score': 0,
                'risk_level': 'Hata',
                'warnings': [f"Analiz sırasında hata: {str(e)}"],
                'details': {}
            }

    def setup_selenium(self):
        try:
            chrome_options = Options()
            chrome_options.add_argument("--headless")
            chrome_options.add_argument("--no-sandbox")
            chrome_options.add_argument("--disable-dev-shm-usage")
            chrome_options.add_argument("--disable-gpu")
            chrome_options.add_argument("--remote-debugging-port=0")
            chrome_options.add_experimental_option('excludeSwitches', ['enable-logging'])
            
            service = Service(ChromeDriverManager().install())
            self.driver = webdriver.Chrome(service=service, options=chrome_options)
        except Exception as e:
            logging.error(f"Selenium kurulumu hatası: {e}")
            self.driver = None
        
    def close(self):
        if hasattr(self, 'driver') and self.driver:
            try:
                self.driver.quit()
            except Exception as e:
                logging.error(f"Selenium kapatılırken hata: {e}")

    def check_ssl(self, url):
        """
        SSL sertifikası kontrolü
        
        :param url: Kontrol edilecek URL
        :return: SSL bilgileri sözlüğü
        """
        # Varsayılan SSL bilgileri
        ssl_info = {
            'ssl_status': False,  # Varsayılan olarak SSL güvensiz
            'protocol': 'Bilinmiyor',
            'issuer': {},
            'subject': {},
            'expiration_date': 'Bilinmiyor',
            'issuer_trusted': False,
            'valid': False,
            'error': ''
        }

        try:
            # URL'den hostname'i çıkar
            parsed_url = urllib.parse.urlparse(url)
            
            # HTTPS kontrolü
            if not url.startswith('https://'):
                ssl_info['error'] = 'HTTPS kullanılmıyor'
                return ssl_info

            hostname = parsed_url.netloc

            # SSL sertifikası bilgilerini al
            context = ssl.create_default_context()
            with socket.create_connection((hostname, 443)) as sock:
                with context.wrap_socket(sock, server_hostname=hostname) as secure_sock:
                    # Sertifika bilgilerini al
                    cert = secure_sock.getpeercert()
                    
                    # Sertifika detaylarını güncelle
                    ssl_info.update({
                        'ssl_status': True,  # SSL güvenli
                        'protocol': secure_sock.version(),
                        'issuer': dict(x[0] for x in cert['issuer']),
                        'subject': dict(x[0] for x in cert['subject']),
                        'expiration_date': cert.get('notAfter', 'Bilinmiyor'),
                        'issuer_trusted': True,
                        'valid': True,
                        'error': ''
                    })
                    
                    return ssl_info
        except ssl.SSLError as e:
            return {
                'ssl_status': False,
                'error': f'SSL hatası: {str(e)}'
            }
        except socket.gaierror:
            return {
                'ssl_status': False,
                'error': 'Domain adı çözümlenemedi'
            }
        except Exception as e:
            return {
                'ssl_status': False,
                'error': f'SSL kontrolü sırasında hata: {str(e)}'
            }

    def scan_url(self, url):
        """URL'yi tara ve sonuçları döndür"""
        try:
            self.progress_updated.emit(10)
            
            if not validators.url(url):
                self.error_occurred.emit("Geçersiz URL formatı")
                return
            
            results = {
                'url': url,
                'security_score': 0,
                'warnings': []
            }
            
            # SSL kontrolü
            self.progress_updated.emit(20)
            ssl_info = self.check_ssl(url)
            results['ssl_info'] = ssl_info
            
            # URLScan.io taraması
            self.progress_updated.emit(40)
            urlscan_results = self.scan_urlscan_io(url)
            results['urlscan_results'] = urlscan_results
            
            # VirusTotal taraması
            self.progress_updated.emit(60)
            virustotal_results = self.scan_virustotal(url)
            results['virustotal_results'] = virustotal_results
            
            # ML analizi
            self.progress_updated.emit(80)
            ml_results = self.scan_ml_based(url)
            if ml_results.get('warnings'):
                results['warnings'].extend(ml_results['warnings'])
            
            # Genel güvenlik skoru hesapla
            scores = []
            
            if urlscan_results.get('score') is not None:
                scores.append(urlscan_results['score'])
            
            if virustotal_results.get('score') is not None:
                scores.append(virustotal_results['score'])
            
            if ssl_info.get('ssl_status'):
                scores.append(100)
            else:
                scores.append(0)
                results['warnings'].append(ssl_info.get('error', 'SSL sertifikası bulunamadı'))
            
            if scores:
                results['security_score'] = sum(scores) / len(scores)
            
            self.progress_updated.emit(100)
            self.scan_completed.emit(results)
            
        except requests.exceptions.ConnectionError:
            self.error_occurred.emit("Bağlantı hatası: Site yanıt vermiyor veya internet bağlantınızı kontrol edin.")
        except requests.exceptions.Timeout:
            self.error_occurred.emit("Zaman aşımı: Site çok yavaş yanıt veriyor veya yanıt vermiyor.")
        except requests.exceptions.SSLError:
            self.error_occurred.emit("SSL/TLS Hatası: Güvenli bağlantı kurulamadı. Site sertifikası geçersiz olabilir.")
        except requests.exceptions.RequestException as e:
            self.error_occurred.emit(f"Bağlantı hatası: {str(e)}")
        except Exception as e:
            self.error_occurred.emit(f"Beklenmeyen hata: {str(e)}")
    
    def scan_virustotal(self, url):
        """
        VirusTotal API ile URL taraması yap
        """
        try:
            api_key = os.getenv('VIRUSTOTAL_API_KEY')
            if not api_key:
                return {
                    'error': 'VirusTotal API anahtarı bulunamadı',
                    'score': 0,
                    'malicious': True,
                    'message': 'API anahtarı eksik'
                }
            
            # URL'yi gönder
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            headers = {
                'x-apikey': api_key
            }
            
            # Önce URL'yi analiz için gönder
            submit_url = f'https://www.virustotal.com/vtapi/v2/url/scan'
            params = {'apikey': api_key, 'url': url}
            response = requests.post(submit_url, data=params)
            
            if response.status_code != 200:
                error_msg = f'VirusTotal API Hatası: {response.text}'
                return {
                    'error': error_msg,
                    'score': 0,
                    'malicious': True,
                    'message': error_msg
                }
            
            # Sonuçları al
            time.sleep(3)  # Analiz için bekle
            report_url = f'https://www.virustotal.com/vtapi/v2/url/report'
            params = {'apikey': api_key, 'resource': url}
            report = requests.get(report_url, params=params)
            
            if report.status_code != 200:
                error_msg = f'VirusTotal rapor alınamadı: {report.text}'
                return {
                    'error': error_msg,
                    'score': 0,
                    'malicious': True,
                    'message': error_msg
                }
            
            results = report.json()
            positives = results.get('positives', 0)
            total = results.get('total', 0)
            
            if total == 0:
                score = 0
                message = 'VirusTotal sonucu alınamadı'
            else:
                score = ((total - positives) / total) * 100
                message = f'VirusTotal Sonucu: {positives}/{total} motor tehdit tespit etti'
            
            return {
                'score': score,
                'malicious': positives > 0,
                'message': message,
                'details': {
                    'pozitif': positives,
                    'toplam': total,
                    'tarama_tarihi': results.get('scan_date', 'Bilinmiyor')
                }
            }
            
        except Exception as e:
            error_msg = f'VirusTotal taraması sırasında hata: {str(e)}'
            logging.error(error_msg)
            return {
                'error': error_msg,
                'score': 0,
                'malicious': True,
                'message': error_msg
            }

class APIKeyManager:
    def __init__(self):
        self.api_keys = {
            'URLSCAN_API_KEY': '',
            'VIRUSTOTAL_API_KEY': ''
        }
        
    def load_api_keys(self):
        """API anahtarlarını yükle"""
        try:
            # .env dosyasını oku
            env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
            
            if os.path.exists(env_path):
                with open(env_path, 'r', encoding='utf-8') as f:
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            key, value = line.split('=', 1)
                            key = key.strip()
                            value = value.strip()
                            
                            # Sadece geçerli anahtarları kaydet
                            if key in self.api_keys:
                                self.api_keys[key] = value
                                os.environ[key] = value
            
            # Eksik anahtarlar için uyarı
            missing_keys = [k for k, v in self.api_keys.items() if not v]
            if missing_keys:
                logging.warning(f"Eksik API anahtarları: {', '.join(missing_keys)}")
            
        except Exception as e:
            logging.error(f"API anahtarları yüklenirken hata oluştu: {str(e)}")
            
    def check_api_keys(self):
        """API anahtarlarının varlığını kontrol et"""
        missing_keys = [k for k, v in self.api_keys.items() if not v]
        return len(missing_keys) == 0, missing_keys

class APIKeyDialog(QDialog):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setWindowTitle("🔐 API Anahtarları Yönetimi")
        self.setMinimumWidth(500)
        
        layout = QVBoxLayout()
        
        # Açıklama etiketi
        description = QLabel("URL güvenlik taraması için gerekli API anahtarlarını buradan yönetebilirsiniz.")
        description.setWordWrap(True)
        layout.addWidget(description)
        
        # URLScan.io API Key
        urlscan_group = QGroupBox("URLScan.io API")
        urlscan_layout = QVBoxLayout()
        
        urlscan_key_layout = QHBoxLayout()
        self.urlscan_key = QLineEdit()
        self.urlscan_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.urlscan_key.setText(os.getenv('URLSCAN_API_KEY', ''))
        
        urlscan_show_btn = QPushButton("👁️")
        urlscan_show_btn.setToolTip("Anahtarı göster/gizle")
        urlscan_show_btn.clicked.connect(lambda: self.toggle_key_visibility(self.urlscan_key))
        
        urlscan_key_layout.addWidget(QLabel("API Anahtarı:"))
        urlscan_key_layout.addWidget(self.urlscan_key)
        urlscan_key_layout.addWidget(urlscan_show_btn)
        
        urlscan_info = QLabel('<a href="https://urlscan.io/docs/api/">URLScan.io API Dokümantasyonu</a>')
        urlscan_info.setOpenExternalLinks(True)
        urlscan_info.setToolTip("API anahtarı almak için tıklayın")
        
        urlscan_layout.addLayout(urlscan_key_layout)
        urlscan_layout.addWidget(urlscan_info)
        urlscan_group.setLayout(urlscan_layout)
        
        # VirusTotal API Key
        virustotal_group = QGroupBox("VirusTotal API")
        virustotal_layout = QVBoxLayout()
        
        virustotal_key_layout = QHBoxLayout()
        self.virustotal_key = QLineEdit()
        self.virustotal_key.setEchoMode(QLineEdit.EchoMode.Password)
        self.virustotal_key.setText(os.getenv('VIRUSTOTAL_API_KEY', ''))
        
        virustotal_show_btn = QPushButton("👁️")
        virustotal_show_btn.setToolTip("Anahtarı göster/gizle")
        virustotal_show_btn.clicked.connect(lambda: self.toggle_key_visibility(self.virustotal_key))
        
        virustotal_key_layout.addWidget(QLabel("API Anahtarı:"))
        virustotal_key_layout.addWidget(self.virustotal_key)
        virustotal_key_layout.addWidget(virustotal_show_btn)
        
        virustotal_info = QLabel('<a href="https://developers.virustotal.com/reference">VirusTotal API Dokümantasyonu</a>')
        virustotal_info.setOpenExternalLinks(True)
        virustotal_info.setToolTip("API anahtarı almak için tıklayın")
        
        virustotal_layout.addLayout(virustotal_key_layout)
        virustotal_layout.addWidget(virustotal_info)
        virustotal_group.setLayout(virustotal_layout)
        
        # Butonlar
        button_layout = QHBoxLayout()
        save_button = QPushButton("💾 Kaydet")
        save_button.clicked.connect(self.save_keys)
        save_button.setToolTip("API anahtarlarını kaydet")
        
        cancel_button = QPushButton("❌ İptal")
        cancel_button.clicked.connect(self.reject)
        cancel_button.setToolTip("Değişiklikleri iptal et")
        
        button_layout.addWidget(save_button)
        button_layout.addWidget(cancel_button)
        
        # Layout'ları ana layout'a ekle
        layout.addWidget(urlscan_group)
        layout.addWidget(virustotal_group)
        layout.addLayout(button_layout)
        
        self.setLayout(layout)
    
    def toggle_key_visibility(self, key_input):
        """API anahtarı görünürlüğünü değiştir"""
        if key_input.echoMode() == QLineEdit.EchoMode.Password:
            key_input.setEchoMode(QLineEdit.EchoMode.Normal)
        else:
            key_input.setEchoMode(QLineEdit.EchoMode.Password)
    
    def validate_keys(self):
        """API anahtarlarını doğrula"""
        urlscan_key = self.urlscan_key.text().strip()
        virustotal_key = self.virustotal_key.text().strip()
        
        # Her iki anahtar da boş olmamalı
        if not urlscan_key or not virustotal_key:
            QMessageBox.warning(self, "Eksik Anahtar", 
                                "Lütfen hem URLScan.io hem de VirusTotal için API anahtarı girin.")
            return False
        
        # Anahtar uzunluğu kontrolü
        if len(urlscan_key) < 10 or len(virustotal_key) < 10:
            QMessageBox.warning(self, "Geçersiz Anahtar", 
                                "API anahtarları çok kısa görünüyor. Lütfen doğru anahtarları girdiğinizden emin olun.")
            return False
        
        return True
    
    def save_keys(self):
        """API anahtarlarını kaydet"""
        if not self.validate_keys():
            return
        
        try:
            # .env dosyasını oku
            env_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '.env')
            
            if os.path.exists(env_path):
                with open(env_path, 'r', encoding='utf-8') as f:
                    env_content = {}
                    for line in f:
                        line = line.strip()
                        if line and not line.startswith('#'):
                            key, value = line.split('=', 1)
                            env_content[key.strip()] = value.strip()
            
            # Yeni API anahtarlarını ekle/güncelle
            env_content['URLSCAN_API_KEY'] = self.urlscan_key.text().strip()
            env_content['VIRUSTOTAL_API_KEY'] = self.virustotal_key.text().strip()
            
            # .env dosyasını güncelle
            with open(env_path, 'w', encoding='utf-8') as f:
                f.write("# API Anahtarları\n")
                for key, value in env_content.items():
                    f.write(f"{key}={value}\n")
            
            # Ortam değişkenlerini güncelle
            os.environ['URLSCAN_API_KEY'] = self.urlscan_key.text().strip()
            os.environ['VIRUSTOTAL_API_KEY'] = self.virustotal_key.text().strip()
            
            QMessageBox.information(self, "Başarılı", "API anahtarları başarıyla kaydedildi!")
            self.accept()
            
        except Exception as e:
            QMessageBox.critical(self, "Hata", f"API anahtarları kaydedilirken hata oluştu: {str(e)}")

class ScanWorker(QThread):
    progress = pyqtSignal(int)
    result = pyqtSignal(dict)
    
    def __init__(self, url):
        super().__init__()
        self.url = url
        self.url_scanner = URLScanner()
    
    def scan_virustotal(self, url):
        """
        VirusTotal API ile URL taraması yap
        """
        try:
            api_key = os.getenv('VIRUSTOTAL_API_KEY')
            if not api_key:
                return {
                    'error': 'VirusTotal API anahtarı bulunamadı',
                    'score': 0,
                    'malicious': True,
                    'message': 'API anahtarı eksik'
                }
            
            # URL'yi gönder
            url_id = base64.urlsafe_b64encode(url.encode()).decode().strip('=')
            headers = {
                'x-apikey': api_key
            }
            
            # Önce URL'yi analiz için gönder
            submit_url = f'https://www.virustotal.com/vtapi/v2/url/scan'
            params = {'apikey': api_key, 'url': url}
            response = requests.post(submit_url, data=params)
            
            if response.status_code != 200:
                error_msg = f'VirusTotal API Hatası: {response.text}'
                return {
                    'error': error_msg,
                    'score': 0,
                    'malicious': True,
                    'message': error_msg
                }
            
            # Sonuçları al
            time.sleep(3)  # Analiz için bekle
            report_url = f'https://www.virustotal.com/vtapi/v2/url/report'
            params = {'apikey': api_key, 'resource': url}
            report = requests.get(report_url, params=params)
            
            if report.status_code != 200:
                error_msg = f'VirusTotal rapor alınamadı: {report.text}'
                return {
                    'error': error_msg,
                    'score': 0,
                    'malicious': True,
                    'message': error_msg
                }
            
            results = report.json()
            positives = results.get('positives', 0)
            total = results.get('total', 0)
            
            if total == 0:
                score = 0
                message = 'VirusTotal sonucu alınamadı'
            else:
                score = ((total - positives) / total) * 100
                message = f'VirusTotal Sonucu: {positives}/{total} motor tehdit tespit etti'
            
            return {
                'score': score,
                'malicious': positives > 0,
                'message': message,
                'details': {
                    'pozitif': positives,
                    'toplam': total,
                    'tarama_tarihi': results.get('scan_date', 'Bilinmiyor')
                }
            }
            
        except Exception as e:
            error_msg = f'VirusTotal taraması sırasında hata: {str(e)}'
            logging.error(error_msg)
            return {
                'error': error_msg,
                'score': 0,
                'malicious': True,
                'message': error_msg
            }
    
    def run(self):
        try:
            self.progress.emit(10)
            
            # SSL kontrolü
            ssl_check = self.url_scanner.check_ssl(self.url)
            self.progress.emit(30)
            
            # URLScan.io taraması
            urlscan_results = self.url_scanner.scan_urlscan_io(self.url)
            self.progress.emit(50)
            
            # VirusTotal taraması
            virustotal_results = self.scan_virustotal(self.url)
            self.progress.emit(70)
            
            # Website başlığı ve meta bilgilerini al
            headers = {
                'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
            }
            
            try:
                response = requests.get(self.url, headers=headers, timeout=10, verify=False)
                soup = BeautifulSoup(response.text, 'html.parser')
                title = soup.title.string if soup.title else 'Başlık bulunamadı'
            except:
                title = 'Başlık alınamadı'
            
            self.progress.emit(90)
            
            # Güvenlik skoru hesapla
            warnings = []
            
            try:
                # Servis skorlarını hesapla
                service_scores = {
                    'urlscan': urlscan_results.get('score', 0) * 0.4,    # 40%
                    'virustotal': virustotal_results.get('score', 0) * 0.3,  # 30%
                    'ssl': (100 if ssl_check.get('ssl_status', False) else 0) * 0.3  # 30%
                }
                
                # Toplam skor hesaplama
                security_score = sum(service_scores.values())
                
                # Risk seviyesi belirleme
                if security_score >= 80:
                    risk_level = "Düşük Risk"
                elif security_score >= 60:
                    risk_level = "Orta Risk"
                else:
                    risk_level = "Yüksek Risk"
                
                # Uyarıları topla
                if not ssl_check.get('ssl_status', False):
                    warnings.append(ssl_check.get('error', 'SSL sertifikası bulunamadı'))
                if urlscan_results.get('malicious', False):
                    warnings.append(urlscan_results['message'])
                if virustotal_results.get('malicious', False):
                    warnings.append(virustotal_results['message'])
            
            except Exception as e:
                logging.error(f"Skor hesaplama hatası: {str(e)}")
                security_score = 0
                risk_level = "Belirlenemedi"
            
            # Sonuçları hazırla
            scan_results = {
                'url': self.url,
                'title': title,
                'security_score': round(security_score, 2),
                'risk_level': risk_level,
                'warnings': warnings,
                'ssl_info': ssl_check,
                'urlscan_results': urlscan_results,
                'virustotal_results': virustotal_results
            }
            
            self.progress.emit(100)
            self.result.emit(scan_results)
            
        except Exception as e:
            logging.error(f"Tarama hatası: {str(e)}")
            self.result.emit({'error': str(e)})
        finally:
            self.url_scanner.close()

class AnimatedProgressBar(QProgressBar):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setStyleSheet("""
            QProgressBar {
                border: 2px solid #2196F3;
                border-radius: 5px;
                text-align: center;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #2196F3;
                border-radius: 3px;
            }
        """)
        self._animation = QPropertyAnimation(self, b"value")
        self._animation.setEasingCurve(QEasingCurve.Type.OutCubic)
        self._animation.setDuration(800)

    def setValue(self, value):
        self._animation.stop()
        self._animation.setStartValue(self.value())
        self._animation.setEndValue(value)
        self._animation.start()

class ResultCard(QWidget):
    def __init__(self, parent=None):
        super().__init__(parent)
        self.setMinimumHeight(100)
        self.setMaximumHeight(300)
        
        layout = QVBoxLayout(self)
        layout.setContentsMargins(15, 15, 15, 15)
        layout.setSpacing(10)
        
        # Kart container
        self.container = QWidget(self)
        self.container.setObjectName("card_container")
        card_layout = QVBoxLayout(self.container)
        card_layout.setContentsMargins(0, 0, 0, 0)
        card_layout.setSpacing(10)
        
        # Başlık ve kopyalama butonu için yatay layout
        title_layout = QHBoxLayout()
        
        # Başlık
        self.title = QLabel()
        self.title.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | 
                                         Qt.TextInteractionFlag.TextSelectableByKeyboard)
        self.title.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.title.customContextMenuRequested.connect(lambda pos: self.show_context_menu(pos, self.title))
        self.title.setStyleSheet("""
            QLabel {
                font-size: 18px;
                font-weight: bold;
                color: #212121;
            }
        """)
        title_layout.addWidget(self.title)
        
        # Kopyalama butonu
        self.copy_button = QPushButton("📋")
        self.copy_button.setToolTip("Sonuçları kopyala")
        self.copy_button.setStyleSheet("""
            QPushButton {
                border: none;
                background-color: transparent;
                padding: 5px;
                font-size: 16px;
            }
            QPushButton:hover {
                background-color: #E0E0E0;
                border-radius: 5px;
            }
        """)
        self.copy_button.setCursor(Qt.CursorShape.PointingHandCursor)
        self.copy_button.clicked.connect(self.copy_content)
        title_layout.addWidget(self.copy_button)
        title_layout.setAlignment(Qt.AlignmentFlag.AlignRight)
        
        card_layout.addLayout(title_layout)
        
        # İçerik
        self.content = QLabel()
        self.content.setWordWrap(True)
        self.content.setTextInteractionFlags(Qt.TextInteractionFlag.TextSelectableByMouse | 
                                           Qt.TextInteractionFlag.TextSelectableByKeyboard)
        self.content.setContextMenuPolicy(Qt.ContextMenuPolicy.CustomContextMenu)
        self.content.customContextMenuRequested.connect(lambda pos: self.show_context_menu(pos, self.content))
        self.content.setStyleSheet("""
            QLabel {
                font-size: 14px;
                color: #616161;
                line-height: 1.4;
            }
        """)
        card_layout.addWidget(self.content)
        
        layout.addWidget(self.container)
        
        # Varsayılan stil
        self.setStyleSheet("""
            #card_container {
                background-color: white;
                border: 1px solid #E0E0E0;
                border-radius: 10px;
                padding: 15px;
            }
        """)
        
        # Opaklık animasyonu için
        self.setGraphicsEffect(QGraphicsOpacityEffect(opacity=0))
        
    def show_context_menu(self, pos, widget):
        """Sağ tıklama menüsünü göster"""
        menu = QMenu(self)
        
        # Seçili metin varsa kopyala seçeneğini ekle
        copy_action = QAction("Kopyala", self)
        copy_action.triggered.connect(lambda: self.copy_selected_text(widget))
        menu.addAction(copy_action)
        
        # Tümünü seç seçeneği
        select_all_action = QAction("Tümünü Seç", self)
        select_all_action.triggered.connect(lambda: widget.setText(widget.text()))  # This will select all text in QLabel
        menu.addAction(select_all_action)
        
        menu.exec(widget.mapToGlobal(pos))
    
    def copy_selected_text(self, widget):
        """Seçili metni kopyala"""
        selected_text = widget.selectedText()
        if selected_text:
            clipboard = QApplication.clipboard()
            clipboard.setText(selected_text)
            
            # Kopyalama animasyonu
            self.show_copy_animation()
    
    def show_copy_animation(self):
        """Kopyalama animasyonunu göster"""
        original_text = self.copy_button.text()
        self.copy_button.setText("✓")
        self.copy_button.setStyleSheet("""
            QPushButton {
                border: none;
                background-color: #4CAF50;
                color: white;
                padding: 5px;
                font-size: 16px;
                border-radius: 5px;
            }
        """)
        
        # 1 saniye sonra orijinal duruma dön
        QTimer.singleShot(1000, lambda: self.reset_copy_button(original_text))
        
    def copy_content(self):
        """Kart içeriğini panoya kopyala"""
        clipboard = QApplication.clipboard()
        text_content = f"{self.title.text()}\n\n{self.content.text()}"
        clipboard.setText(text_content)
        self.show_copy_animation()
        
    def reset_copy_button(self, original_text):
        """Kopyalama butonunu orijinal haline döndür"""
        self.copy_button.setText(original_text)
        self.copy_button.setStyleSheet("""
            QPushButton {
                border: none;
                background-color: transparent;
                padding: 5px;
                font-size: 16px;
            }
            QPushButton:hover {
                background-color: #E0E0E0;
                border-radius: 5px;
            }
        """)
        
    def show_with_animation(self):
        super().show()
        self.graphicsEffect().setOpacity(1)

class MainWindow(QMainWindow):
    def __init__(self):
        super().__init__()
        self.setWindowTitle("Stixyie URL Güvenlik Tarayıcı")
        self.setMinimumSize(800, 600)
        
        # Scanner ve thread'i başlat
        self.scanner = URLScanner()
        self.scanner_thread = QThread()
        self.scanner.moveToThread(self.scanner_thread)
        
        # Sinyalleri bağla
        self.scanner.scan_completed.connect(self.show_results)
        self.scanner.progress_updated.connect(self.update_progress)
        self.scanner.error_occurred.connect(self.show_error)
        
        self.scanner_thread.start()
        
        self.init_ui()
    
    def start_scan(self):
        """URL taramasını başlat"""
        url = self.url_input.text().strip()
        
        # URL doğrulama kontrolleri
        if not url:
            self.show_error("Lütfen taranacak bir URL girin.")
            return
            
        # URL formatını kontrol et
        if not url.startswith(('http://', 'https://')):
            self.show_error("Geçersiz URL formatı")
            return
            
        try:
            # URL'yi parse et ve geçerliliğini kontrol et
            parsed = urllib.parse.urlparse(url)
            if not all([parsed.scheme, parsed.netloc]):
                self.show_error("Geçersiz URL formatı")
                return
                
            # Boşluk ve özel karakter kontrolü
            if ' ' in url or not validators.url(url):
                self.show_error("Geçersiz URL formatı")
                return
        except Exception as e:
            self.show_error(f"URL doğrulama hatası: {str(e)}")
            return
        
        # UI'yi temizle ve hazırla
        self.clear_results()
        self.progress_bar.setValue(0)
        self.progress_bar.show()
        self.statusBar().showMessage('Tarama başlatılıyor...')
        
        # URL'yi scanner'a gönder
        self.scanner.scan_url(url)
    
    def update_progress(self, value):
        """İlerleme çubuğunu güncelle"""
        self.progress_bar.setValue(value)
    
    def show_error(self, error_msg):
        """Hata mesajını göster"""
        self.progress_bar.hide()
        self.statusBar().showMessage('Hata oluştu!')
        self.results_container.setVisible(True)
        
        error_card = ResultCard()
        error_card.title.setText("⚠️ Hata Oluştu")
        
        # Hata mesajını daha anlaşılır hale getir
        if "Geçersiz URL formatı" in error_msg or "Invalid URL" in error_msg:
            error_content = [
                "❌ Geçersiz URL Formatı",
                "\n🔍 Olası Nedenler:",
                "• URL'nin başında 'http://' veya 'https://' olmalıdır",
                "• URL özel karakterler içermemeli",
                "• URL boşluk içermemeli",
                "\n💡 Örnek doğru format:",
                "https://www.example.com"
            ]
        elif "connection" in error_msg.lower() or "bağlantı" in error_msg.lower():
            error_content = [
                "❌ Bağlantı Hatası",
                "\n🔍 Olası Nedenler:",
                "• İnternet bağlantınızı kontrol edin",
                "• Site erişilebilir olmayabilir",
                "• Güvenlik duvarı engellemiş olabilir",
                "\n💡 Öneriler:",
                "• İnternet bağlantınızı kontrol edin",
                "• Birkaç dakika sonra tekrar deneyin"
            ]
        elif "timeout" in error_msg.lower() or "zaman aşımı" in error_msg.lower():
            error_content = [
                "❌ Zaman Aşımı Hatası",
                "\n🔍 Olası Nedenler:",
                "• Site yanıt vermiyor",
                "• İnternet bağlantınız yavaş",
                "• Site geçici olarak erişilemez durumda",
                "\n💡 Öneriler:",
                "• İnternet hızınızı kontrol edin",
                "• Birkaç dakika sonra tekrar deneyin"
            ]
        else:
            error_content = [
                "❌ Beklenmeyen Hata",
                f"\n🔍 Hata Detayı:",
                error_msg,
                "\n💡 Öneriler:",
                "• URL'yi kontrol edip tekrar deneyin",
                "• Farklı bir tarayıcı kullanmayı deneyin",
                "• Daha sonra tekrar deneyin"
            ]
        
        error_card.content.setText("\n".join(error_content))
        error_card.setStyleSheet("""
            #card_container {
                background-color: #FFF3F3;
                border: 1px solid #FFD7D7;
            }
        """)
        error_card.show_with_animation()
        self.results_layout.addWidget(error_card)
    
    def clear_results(self):
        """Sonuçları temizle"""
        for i in reversed(range(self.results_layout.count())):
            widget = self.results_layout.itemAt(i).widget()
            if widget:
                widget.deleteLater()
        
        self.results_container.setVisible(True)
    
    def init_ui(self):
        # Ana widget
        main_widget = QWidget()
        self.setCentralWidget(main_widget)
        
        # Ana layout
        main_layout = QVBoxLayout(main_widget)
        main_layout.setContentsMargins(20, 20, 20, 20)
        main_layout.setSpacing(20)
        
        # Başlık
        title = QLabel("StixyieURL Güvenlik Tarayıcı")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title.setStyleSheet("""
            QLabel {
                font-size: 24px;
                font-weight: bold;
                color: #2196F3;
                margin: 20px 0;
            }
        """)
        main_layout.addWidget(title)
        
        # URL giriş alanı container
        input_container = QWidget()
        input_layout = QHBoxLayout(input_container)
        input_layout.setSpacing(10)
        
        # URL giriş alanı
        self.url_input = QLineEdit()
        self.url_input.setPlaceholderText("https://www.example.com/")
        self.url_input.setMinimumWidth(400)
        self.url_input.setStyleSheet("""
            QLineEdit {
                padding: 10px;
                border: 2px solid #E0E0E0;
                border-radius: 5px;
                font-size: 14px;
            }
            QLineEdit:focus {
                border-color: #2196F3;
            }
        """)
        
        # Butonlar
        scan_button = QPushButton("🔍 Tara")
        scan_button.clicked.connect(self.start_scan)
        scan_button.setMinimumWidth(120)
        
        api_button = QPushButton("🔑 API Ayarları")
        api_button.clicked.connect(self.show_api_dialog)
        api_button.setMinimumWidth(120)
        
        # Buton stilleri
        button_style = """
            QPushButton {
                padding: 10px 20px;
                border-radius: 5px;
                font-size: 14px;
                font-weight: bold;
                color: white;
            }
            QPushButton:hover {
                opacity: 0.8;
            }
            QPushButton:pressed {
                opacity: 0.6;
            }
        """
        
        scan_button.setStyleSheet(button_style + """
            QPushButton {
                background-color: #2196F3;
            }
        """)
        
        api_button.setStyleSheet(button_style + """
            QPushButton {
                background-color: #4CAF50;
            }
        """)
        
        # Input layout'a widget'ları ekle
        input_layout.addWidget(self.url_input, stretch=1)
        input_layout.addWidget(scan_button)
        input_layout.addWidget(api_button)
        
        main_layout.addWidget(input_container)
        
        # Progress bar
        self.progress_bar = QProgressBar()
        self.progress_bar.setStyleSheet("""
            QProgressBar {
                border: 2px solid #E0E0E0;
                border-radius: 5px;
                text-align: center;
                height: 25px;
            }
            QProgressBar::chunk {
                background-color: #2196F3;
                border-radius: 3px;
            }
        """)
        self.progress_bar.hide()
        main_layout.addWidget(self.progress_bar)
        
        # Sonuçlar için scroll area
        scroll_area = QScrollArea()
        scroll_area.setWidgetResizable(True)
        scroll_area.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        scroll_area.setStyleSheet("""
            QScrollArea {
                border: none;
                background-color: transparent;
            }
            QScrollBar:vertical {
                border: none;
                background-color: #F5F5F5;
                width: 10px;
                margin: 0px;
            }
            QScrollBar::handle:vertical {
                background-color: #BDBDBD;
                border-radius: 5px;
                min-height: 20px;
            }
            QScrollBar::handle:vertical:hover {
                background-color: #9E9E9E;
            }
        """)
        
        # Sonuçlar container'ı
        self.results_container = QWidget()
        self.results_layout = QVBoxLayout(self.results_container)
        self.results_layout.setSpacing(10)
        self.results_layout.setContentsMargins(0, 0, 0, 0)
        self.results_container.setVisible(False)
        
        scroll_area.setWidget(self.results_container)
        main_layout.addWidget(scroll_area, stretch=1)
        
        # Status bar
        self.statusBar().setStyleSheet("""
            QStatusBar {
                border-top: 1px solid #E0E0E0;
                padding: 5px;
                background-color: #F5F5F5;
            }
        """)
    
    def calculate_overall_score(self, results):
        """Genel güvenlik skorunu hesapla"""
        scores = []
        
        # URLScan.io skoru
        if 'urlscan_results' in results and 'score' in results['urlscan_results']:
            scores.append(results['urlscan_results']['score'])
        
        # VirusTotal skoru
        if 'virustotal_results' in results and 'score' in results['virustotal_results']:
            scores.append(results['virustotal_results']['score'])
        
        # SSL skoru
        if results.get('ssl_info', {}).get('ssl_status', False):
            scores.append(100)
        else:
            scores.append(0)
        
        # Ortalama skoru hesapla
        if scores:
            return sum(scores) / len(scores)
        return 0

    def get_risk_level(self, score):
        """Skor değerine göre risk seviyesini belirle"""
        if score >= 80:
            return "Düşük Risk", "success"
        elif score >= 60:
            return "Orta Risk", "warning"
        else:
            return "Yüksek Risk", "danger"

    def show_results(self, results):
        """Tarama sonuçlarını göster"""
        try:
            self.progress_bar.hide()
            self.clear_results()
            
            # Ana sonuç kartı
            main_card = ResultCard()
            score = results.get('security_score', 0)
            risk_level, risk_class = self.get_risk_level(score)
            
            main_title = f"🎯 Genel Güvenlik Değerlendirmesi"
            main_content = [
                f"URL: {results.get('url', 'Belirtilmemiş')}",
                f"\n📊 Güvenlik Skoru: {score:.1f}/100",
                f"⚠️ Risk Seviyesi: {risk_level}",
                "\n💡 Ne Anlama Geliyor?",
                "• 80-100: Site güvenli görünüyor",
                "• 60-79: Dikkatli olunmalı",
                "• 0-59: Riskli, ziyaret edilmemeli"
            ]
            
            main_card.title.setText(main_title)
            main_card.content.setText("\n".join(main_content))
            main_card.setProperty("risk_level", risk_class)
            main_card.show_with_animation()
            self.results_layout.addWidget(main_card)
            
            # SSL sonuçları
            if 'ssl_info' in results:
                ssl_card = ResultCard()
                ssl_info = results['ssl_info']
                
                if ssl_info.get('ssl_status'):
                    ssl_card.title.setText("🔒 SSL/TLS Güvenliği")
                    ssl_content = [
                        "✅ SSL/TLS Sertifikası Doğrulandı",
                        "\n📜 Sertifika Detayları:",
                        f"• Sertifika Sahibi: {ssl_info.get('issuer', 'Bilinmiyor')}",
                        f"• Geçerlilik Başlangıcı: {ssl_info.get('valid_from', 'Bilinmiyor')}",
                        f"• Geçerlilik Bitişi: {ssl_info.get('valid_to', 'Bilinmiyor')}",
                        "\n💡 Bu Ne Anlama Geliyor?",
                        "SSL sertifikası, sitenin güvenli olduğunu ve iletişimin şifrelendiğini gösterir.",
                        "Bu, kişisel bilgilerinizin korunduğu anlamına gelir."
                    ]
                else:
                    ssl_card.title.setText("⚠️ SSL/TLS Güvenlik Uyarısı")
                    error_msg = ssl_info.get('error', 'SSL sertifikası bulunamadı')
                    ssl_content = [
                        f"❌ {error_msg}",
                        "\n⚠️ Riskler:",
                        "• Bağlantınız şifrelenmemiş olabilir",
                        "• Verileriniz üçüncü şahıslar tarafından görülebilir",
                        "• Site kimliği doğrulanamamış olabilir",
                        "\n💡 Öneriler:",
                        "• Bu siteye hassas bilgiler göndermeyin",
                        "• Mümkünse HTTPS destekleyen başka bir site kullanın"
                    ]
                
                ssl_card.content.setText("\n".join(ssl_content))
                ssl_card.show_with_animation()
                self.results_layout.addWidget(ssl_card)
            
            # URLScan.io sonuçları
            if 'urlscan_results' in results:
                urlscan_card = ResultCard()
                urlscan_results = results['urlscan_results']
                
                if 'error' in urlscan_results:
                    urlscan_card.title.setText("⚠️ URLScan.io Tarama Hatası")
                    urlscan_card.content.setText(f"Hata Detayı: {urlscan_results['error']}\n\nBu geçici bir sorun olabilir. Lütfen daha sonra tekrar deneyin.")
                else:
                    urlscan_card.title.setText("🔍 URLScan.io Güvenlik Analizi")
                    score = urlscan_results.get('score', 0)
                    urlscan_content = [
                        f"📊 Güvenlik Puanı: {score}/100",
                        f"🚦 Durum: {'❌ Riskli' if urlscan_results.get('malicious') else '✅ Güvenli'}",
                    ]
                    
                    if urlscan_results.get('warnings'):
                        urlscan_content.extend([
                            "\n⚠️ Tespit Edilen Riskler:"
                        ] + [f"• {w}" for w in urlscan_results['warnings']])
                    
                    details = urlscan_results.get('details', {})
                    if details:
                        urlscan_content.append("\n📋 Ek Bilgiler:")
                        if details.get('categories'):
                            urlscan_content.append(f"• Site Kategorileri: {', '.join(details['categories'])}")
                        if details.get('screenshot'):
                            urlscan_content.append(f"\n🖼️ Site Görüntüsü:\n{details['screenshot']}")
                        if details.get('report'):
                            urlscan_content.append(f"\n📄 Detaylı Rapor:\n{details['report']}")
                
                urlscan_card.content.setText("\n".join(urlscan_content))
                urlscan_card.show_with_animation()
                self.results_layout.addWidget(urlscan_card)
            
            # VirusTotal sonuçları
            if 'virustotal_results' in results:
                vt_card = ResultCard()
                vt_results = results['virustotal_results']
                
                if 'error' in vt_results:
                    vt_card.title.setText("⚠️ VirusTotal Tarama Hatası")
                    vt_card.content.setText(f"Hata Detayı: {vt_results['error']}\n\nBu geçici bir sorun olabilir. Lütfen daha sonra tekrar deneyin.")
                else:
                    vt_card.title.setText("🛡️ VirusTotal Güvenlik Taraması")
                    details = vt_results.get('details', {})
                    pozitif = details.get('pozitif', 0)
                    toplam = details.get('toplam', 0)
                    
                    risk_level = "Düşük" if pozitif == 0 else "Yüksek" if pozitif > 2 else "Orta"
                    
                    vt_content = [
                        f"📊 Güvenlik Skoru: {vt_results.get('score', 0)}/100",
                        f"🎯 Risk Seviyesi: {risk_level}",
                        f"\n🔍 Tarama Sonuçları:",
                        f"• {pozitif} güvenlik motoru tehdit tespit etti",
                        f"• Toplam {toplam} motor tarafından tarandı",
                        f"• Tarama Tarihi: {details.get('tarama_tarihi', 'Bilinmiyor')}",
                        f"\n💡 Ne Anlama Geliyor?",
                        "• 0 tespit: Site büyük olasılıkla güvenli",
                        "• 1-2 tespit: Dikkatli olunmalı",
                        "• 3+ tespit: Site riskli olabilir",
                        "\n⚠️ Öneriler:",
                        "• Yüksek riskli sitelere girmekten kaçının",
                        "• Şüpheli dosya indirmeyin",
                        "• Kişisel bilgilerinizi paylaşmayın"
                    ]
                    
                    vt_card.content.setText("\n".join(vt_content))
                
                vt_card.show_with_animation()
                self.results_layout.addWidget(vt_card)
            
            # Genel uyarılar
            if results.get('warnings'):
                warning_card = ResultCard()
                warning_card.title.setText("⚠️ Önemli Güvenlik Uyarıları")
                warning_content = [
                    "Aşağıdaki güvenlik riskleri tespit edildi:",
                    ""
                ] + [f"❗ {w}" for w in results['warnings']]
                warning_content.extend([
                    "",
                    "💡 Öneriler:",
                    "• Bu siteyi ziyaret ederken dikkatli olun",
                    "• Hassas bilgilerinizi girmeyin",
                    "• Güvenlik yazılımınızın güncel olduğundan emin olun",
                    "• Şüpheli durumda siteyi hemen terk edin"
                ])
                warning_card.content.setText("\n".join(warning_content))
                warning_card.show_with_animation()
                self.results_layout.addWidget(warning_card)
            
            self.statusBar().showMessage('Tarama tamamlandı')
            
        except Exception as e:
            logging.error(f"Sonuçları gösterirken hata: {str(e)}")
            self.statusBar().showMessage('Sonuçlar gösterilirken hata oluştu')
            
            error_card = ResultCard()
            error_card.title.setText("❌ Hata Oluştu")
            error_content = [
                "Sonuçlar gösterilirken bir hata meydana geldi:",
                f"\n{str(e)}",
                "\n💡 Öneriler:",
                "• İnternet bağlantınızı kontrol edin",
                "• API anahtarlarınızın doğru olduğundan emin olun",
                "• Programı yeniden başlatmayı deneyin",
                "• Sorun devam ederse log dosyasını kontrol edin"
            ]
            error_card.content.setText("\n".join(error_content))
            error_card.show_with_animation()
            self.results_layout.addWidget(error_card)
            self.progress_bar.setValue(100)
            self.statusBar().showMessage('Tarama tamamlandı!')

    def show_api_dialog(self):
        """API anahtarları yönetim penceresini göster"""
        dialog = APIKeyDialog(self)
        dialog.exec()
        
if __name__ == '__main__':
    app = QApplication(sys.argv)
    main_window = MainWindow()
    main_window.show()
    sys.exit(app.exec())
