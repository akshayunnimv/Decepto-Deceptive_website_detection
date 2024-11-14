# Import Libraries
import pandas as pd
import re
from urllib.parse import urlparse
from tld import get_tld
import os  # Preserved as requested
from sklearn.model_selection import train_test_split
from sklearn.ensemble import RandomForestClassifier
from sklearn.preprocessing import LabelEncoder
from sklearn.metrics import classification_report, accuracy_score
import joblib

# Load Dataset
df = pd.read_csv('malicious_phish.csv')

# Feature Engineering Functions (Intact)
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

# Apply feature functions
df['use_of_ip'] = df['url'].apply(having_ip_address)
df['abnormal_url'] = df['url'].apply(abnormal_url)
df['count.'] = df['url'].apply(count_dot)
df['count-www'] = df['url'].apply(count_www)
df['count@'] = df['url'].apply(count_atrate)
df['count_dir'] = df['url'].apply(no_of_dir)
df['count_embed_domian'] = df['url'].apply(no_of_embed)
df['short_url'] = df['url'].apply(shortening_service)
df['count-https'] = df['url'].apply(count_https)
df['count-http'] = df['url'].apply(count_http)
df['count%'] = df['url'].apply(count_per)
df['count?'] = df['url'].apply(count_ques)
df['count-'] = df['url'].apply(count_hyphen)
df['count='] = df['url'].apply(count_equal)
df['url_length'] = df['url'].apply(url_length)
df['hostname_length'] = df['url'].apply(hostname_length)
df['sus_url'] = df['url'].apply(suspicious_words)
df['count-digits'] = df['url'].apply(digit_count)
df['count-letters'] = df['url'].apply(letter_count)
df['fd_length'] = df['url'].apply(fd_length)
df['tld'] = df['url'].apply(lambda i: get_tld(i, fail_silently=True))
df['tld_length'] = df['tld'].apply(tld_length)

# Encode target labels
label_encoder = LabelEncoder()
df["type_code"] = label_encoder.fit_transform(df["type"])

# Define features and target variable
X = df[['use_of_ip', 'abnormal_url', 'count.', 'count-www', 'count@', 'count_dir', 'count_embed_domian', 'short_url',
        'count-https', 'count-http', 'count%', 'count?', 'count-', 'count=', 'url_length', 'hostname_length',
        'sus_url', 'fd_length', 'tld_length', 'count-digits', 'count-letters']]
y = df['type_code']


# Split data
X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, shuffle=True, random_state=5, stratify=None)



# Random Forest Model
rf_model = RandomForestClassifier(n_estimators=100, max_features='sqrt', random_state=5)
rf_model.fit(X_train, y_train)
y_pred = rf_model.predict(X_test)

# Evaluate model
print(classification_report(y_test, y_pred, target_names=label_encoder.classes_))
print("Accuracy:", accuracy_score(y_test, y_pred))

# Save the model for Django
joblib.dump(rf_model, 'random_forest_model.pkl')
joblib.dump(label_encoder, 'label_encoder.pkl')
