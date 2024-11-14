import joblib
import re
from urllib.parse import urlparse
from tld import get_tld
import pandas as pd


# Load the Random Forest model and label encoder
rf_model = joblib.load('random_forest_model.pkl')
label_encoder = joblib.load('label_encoder.pkl')

# Define all feature extraction functions

def having_ip_address(url):
    match = re.search(
        '(([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.'
        '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\.' '([01]?\\d\\d?|2[0-4]\\d|25[0-5])\\/)|'  
        '((0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\.(0x[0-9a-fA-F]{1,2})\\/)'  
        '(?:[a-fA-F0-9]{1,4}:){7}[a-fA-F0-9]{1,4}', url)
    return 1 if match else 0

def abnormal_url(url):
    hostname = urlparse(url).hostname or ''
    return 1 if re.search(hostname, url) else 0

def count_dot(url): return url.count('.')
def count_www(url): return url.count('www')
def count_atrate(url): return url.count('@')
def no_of_dir(url): return urlparse(url).path.count('/')
def no_of_embed(url): return urlparse(url).path.count('//')
def shortening_service(url): return 1 if re.search(r'bit\.ly|goo\.gl|tinyurl|...', url) else 0
def count_https(url): return url.count('https')
def count_http(url): return url.count('http')
def count_per(url): return url.count('%')
def count_ques(url): return url.count('?')
def count_hyphen(url): return url.count('-')
def count_equal(url): return url.count('=')
def url_length(url): return len(url)
def hostname_length(url): return len(urlparse(url).netloc or '')
def suspicious_words(url): return 1 if re.search(r'PayPal|login|bank|free|...', url) else 0
def digit_count(url): return sum(1 for i in url if i.isnumeric())
def letter_count(url): return sum(1 for i in url if i.isalpha())
def fd_length(url): return len(urlparse(url).path.split('/')[1]) if '/' in urlparse(url).path else 0
def tld_length(tld): return len(tld) if tld else 0

url ='https://voe.sx/r827molymt2w'
if url:
        
        features = {
            'use_of_ip': having_ip_address(url),
            'abnormal_url': abnormal_url(url),
            'count.': count_dot(url),
            'count-www': count_www(url),
            'count@': count_atrate(url),
            'count_dir': no_of_dir(url),
            'count_embed_domian': no_of_embed(url),
            'short_url': shortening_service(url),
            'count-https': count_https(url),
            'count-http': count_http(url),
            'count%': count_per(url),
            'count?': count_ques(url),
            'count-': count_hyphen(url),
            'count=': count_equal(url),
            'url_length': url_length(url),
            'hostname_length': hostname_length(url),
            'sus_url': suspicious_words(url),
            'fd_length': fd_length(url),
            'tld_length': tld_length(get_tld(url, fail_silently=True)),
            'count-digits': digit_count(url),
            'count-letters': letter_count(url)
        }

        # Convert features into DataFrame format for model input
        X_new = pd.DataFrame([features])

        # Make a prediction
        prediction = rf_model.predict(X_new)
        predicted_label = label_encoder.inverse_transform(prediction)
print(predicted_label)

       
