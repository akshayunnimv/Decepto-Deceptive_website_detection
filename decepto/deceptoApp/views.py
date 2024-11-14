from django.http import HttpResponse,JsonResponse
from .models import User,Admin,Complaint,Review,Category
from django.shortcuts import render, redirect, get_object_or_404
from django.contrib.auth.hashers import make_password,check_password
from django.core.exceptions import ValidationError
from django.contrib import messages
from django.contrib.auth import logout,login,authenticate
from django.core.paginator import Paginator
from django.db.models import Count
import csv
import joblib
import re
from urllib.parse import urlparse
from tld import get_tld
import pandas as pd
import os
from django.conf import settings
import requests

# <=========Random Forest==========>
model_path = os.path.join(settings.BASE_DIR, 'random_forest_model.pkl')
label_encoder_path = os.path.join(settings.BASE_DIR, 'label_encoder.pkl')


rf_model = joblib.load(model_path)
label_encoder = joblib.load(label_encoder_path)

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

# <<===========home page==========>>
def index(request):
    return render(request,'index.html')

def about(request):
    return render(request,'about.html')

def contact(request):
    return render(request,'contact.html')

def register(request):
    if request.method == "POST":
        name = request.POST.get('Name')
        email = request.POST.get('email')
        password = request.POST.get('password')
        number = request.POST.get('mobile')
        
        if User.objects.filter(email=email).exists():
            messages.error(request, 'This email is already registered.')
            return redirect( 'register')

        try:
            Decepto_user=User(name=name,email=email,password=make_password(password),contact_number=number)
            Decepto_user.save()
            
            messages.success(request, 'Registration successful!')

            return redirect('register')  
        except ValidationError as e:
            return render(request, 'register.html', {'error': str(e)})

    return render(request, 'register.html')  

def userlogin(request):
    if request.method == "POST":
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            user = User.objects.get(email=email)

            if check_password(password, user.password):
                request.session['user_id'] = user.id
                request.user = user
                next_url = request.GET.get('next', 'userhome')
                return redirect(next_url)
                
            else:
                messages.error(request, 'Invalid email or password.')
                return redirect('userlogin') 
        except User.DoesNotExist:
            messages.error(request, 'Invalid email or password.')

    return render(request, 'userlogin.html') 

def adminlogin(request):
    if request.method == 'POST':
        email = request.POST.get('email')
        password = request.POST.get('password')

        try:
            
            admin = Admin.objects.get(email=email, password=password)
            request.session['admin_id'] = admin.id
            next_url = request.GET.get('next', 'admin_home')
            print(f"Redirecting to: {next_url}")  # Debug output
            return redirect(next_url)

        except Admin.DoesNotExist:
    
            messages.error(request, 'Invalid email or password')
            return redirect('adminlogin')

    return render(request, 'adminlogin.html')

#<<==========home page end=============>>

#<<=========user module============>>

def userlogout(request):
     if 'user_id' in request.session:
        del request.session['user_id']  # Remove user_id from session
     return redirect('userlogin')  

def userhome(request):
    if 'user_id' not in request.session:
        return redirect('userlogin')

    user_id = request.session.get('user_id')
    user = get_object_or_404(User, id=user_id)

    # Get counts for each category and total
    total_count = Category.objects.count()
    phishing_count = Category.objects.filter(category='phishing').count()
    malware_count = Category.objects.filter(category='malware').count()
    defacement_count = Category.objects.filter(category='defacement').count()

    context = {
        'total_count': total_count,
        'phishing_count': phishing_count,
        'malware_count': malware_count,
        'defacement_count': defacement_count,
        'user':user
        
    }

    return render(request, 'userHome.html', context)

def checkuser(request):
    user_id = request.session.get('user_id')
    user = get_object_or_404(User, id=user_id)
    
    if request.method == 'POST':
        
        url = request.POST.get('url')

        # Check if the URL exists in the Category table
        category_entry = Category.objects.filter(url=url).first()
        if category_entry:
           
            messages.error(request, "The URL is suspicious.")
            return redirect('checkuser')

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

        X_new = pd.DataFrame([features])
        prediction = rf_model.predict(X_new)
        predicted_label = label_encoder.inverse_transform(prediction)[0]

        safe_browsing_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}'
        payload = {
            "client": {"clientId": "your-client-id", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        response = requests.post(safe_browsing_url, json=payload)
        result = response.json()
        if predicted_label == "benign" and "matches" not in result:
            messages.success(request, "The URL is safe to use.")
        else:
            messages.error(request, "The URL is suspicious.")

            if predicted_label != "benign":
                Category.objects.create(url=url, category=predicted_label, login_id=user)
        
        return redirect('checkuser')
    return render(request, 'checkurluser.html')


def complaintuser(request):
    if request.method == "POST":
        try:
            user_id = request.session.get('user_id')
            if not user_id:
                messages.error(request, "User not logged in.")
                return redirect('login')

            # Get the complaint from POST data
            user = User.objects.get(id=user_id)
            complaint_text = request.POST.get('complaint')

            # Check if complaint_text is empty
            if not complaint_text:
                messages.error(request, "Complaint cannot be empty.")
                return redirect('complaintuser')
            
            new_complaint = Complaint(login_id=user, complaint=complaint_text)
            new_complaint.save()

            
            messages.success(request, "Complaint submitted successfully!")
            return redirect('complaintuser')  

        except Exception as e:
            messages.error(request, f"An error occurred: {str(e)}")
            return redirect('complaintuser')  


    return render (request,'complaintsuser.html')

def reviewuser(request):
    if request.method == "POST":
        try:
            user_id = request.session.get('user_id')
            if not user_id:
                messages.error(request, "User not logged in.")
                return redirect('login')
            
            user = User.objects.get(id=user_id)
            review_text = request.POST.get('review')
            url=request.POST.get('url')
            
            if not review_text:
                messages.error(request, "Review cannot be empty.")
                return redirect('reviewuser')
            
            if not url:
                messages.error(request,"URL cannot be empty")
                return redirect('reviewuser')
            
            new_review = Review(login_id=user, url=url, review=review_text)
            new_review.save() 
            
            messages.success(request, "review sent successfully!")
            return redirect('reviewuser')  

        except Exception as e:
            messages.error(request, f"An error occurred: {str(e)}")
            return redirect('reviewuser')  

    return render (request,'reviewuser.html')
def profile(request):
    # Fetch user details from the session ID
    user_id = request.session.get('user_id')
    user = get_object_or_404(User, id=user_id)

    if request.method == 'POST':
        # Get form data for updating the profile
        name = request.POST['name']
        contact_number = request.POST['contact_number']
        email = request.POST['email']
        password = request.POST['password']
        confirm_password = request.POST['confirm_password']

        # Validate password match
        if password and password != confirm_password:
            messages.error(request, "Passwords do not match!")
            return redirect('profile')

        # Update the user details
        user.name = name
        user.contact_number = contact_number
        user.email = email

        if password:
            user.password = make_password(password)  # Hash the password before saving

        user.save()
        messages.success(request, "Profile updated successfully!")
        return redirect('profile')

    return render(request, 'profile.html', {'user': user})


def user_viewreviews(request):
    reviews = Review.objects.all().order_by('-current_date')
    paginator = Paginator(reviews, 5)  
    page_number = request.GET.get('page', 1)
    page_reviews = paginator.get_page(page_number)
    return render(request, 'viewreviewuser.html', {'reviews': page_reviews})

def user_viewcomplaints(request):
    user_id = request.session.get('user_id')
    if user_id:
        complaints = Complaint.objects.filter(login_id=user_id).order_by('-date')
        paginator = Paginator(complaints, 5)
        page_number = request.GET.get('page', 1)
        page_complaints = paginator.get_page(page_number)
        return render(request, 'viewcomplaintuser.html', {'complaints': page_complaints})

    else:
        return redirect('login')  
#<<==========user module end==============>>

#<<==========admin module start============>>

def admin_home(request):
    if 'admin_id' not in request.session:
        return redirect('adminlogin')

    # Get counts for each category and total
    total_count = Category.objects.count()
    phishing_count = Category.objects.filter(category='phishing').count()
    malware_count = Category.objects.filter(category='malware').count()
    defacement_count = Category.objects.filter(category='defacement').count()

    context = {
        'total_count': total_count,
        'phishing_count': phishing_count,
        'malware_count': malware_count,
        'defacement_count': defacement_count,
    }
    return render(request,'admin_home.html',context)

def admin_viewreviews(request):
    if request.method == 'POST':
        review_id = request.POST.get('review_id')
        try:
            review = get_object_or_404(Review, id=review_id)
            review.delete()
            messages.success(request, 'Review deleted successfully!')
        except Exception as e:
            messages.error(request, f'Error deleting review: {e}')
        return redirect('admin_viewreviews') 
    
    reviews = Review.objects.all().order_by('-current_date')
    paginator = Paginator(reviews, 5) 
    page_number = request.GET.get('page', 1)
    page_reviews = paginator.get_page(page_number)

    return render(request, 'admin_viewreviews.html', {'reviews': page_reviews})
    
def admin_complaints(request):
    complaints = Complaint.objects.all().order_by('-date')
   
    if request.method == 'POST':
        complaint_id = request.POST.get('complaint_id')
        status = request.POST.get('status')
        reply = request.POST.get('reply')

        try:
            complaint = get_object_or_404(Complaint, id=complaint_id)
            complaint.status = status
            complaint.reply = reply
            complaint.save()
            messages.success(request, 'Reply and status updated successfully.')
            return redirect('admin_complaints')  

        except Exception as e:
            messages.error(request, f"An error occurred: {str(e)}")
            return redirect('admin_complaints')

    paginator = Paginator(complaints, 5)
    page_number = request.GET.get('page', 1)
    page_complaints = paginator.get_page(page_number)

    return render(request, 'admin_complaints.html', {'complaints': page_complaints})


GOOGLE_SAFE_BROWSING_API_KEY = settings.GOOGLE_SAFE_BROWSING_API_KEY

def admin_checkurl(request):
    if request.method == 'POST':
        url = request.POST.get('url')

       
        category_entry = Category.objects.filter(url=url).first()
        if category_entry:
         
            messages.error(request, "The URL is suspicious.")
            return redirect('admin_checkurl')

        
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

        X_new = pd.DataFrame([features])
        prediction = rf_model.predict(X_new)
        predicted_label = label_encoder.inverse_transform(prediction)[0]

        safe_browsing_url = f'https://safebrowsing.googleapis.com/v4/threatMatches:find?key={GOOGLE_SAFE_BROWSING_API_KEY}'
        payload = {
            "client": {"clientId": "your-client-id", "clientVersion": "1.0"},
            "threatInfo": {
                "threatTypes": ["MALWARE", "SOCIAL_ENGINEERING", "UNWANTED_SOFTWARE", "POTENTIALLY_HARMFUL_APPLICATION"],
                "platformTypes": ["ANY_PLATFORM"],
                "threatEntryTypes": ["URL"],
                "threatEntries": [{"url": url}]
            }
        }

        response = requests.post(safe_browsing_url, json=payload)
        result = response.json()
 
        if predicted_label == "benign" and "matches" not in result:
            
            messages.success(request, "The URL is safe to use.")
        else:
            messages.error(request, "The URL is suspicious.")
            if predicted_label != "benign":
                Category.objects.create(url=url, category=predicted_label, login_id=request.user)

        return redirect('admin_checkurl')

    return render(request, 'admin_checkurl.html')

def admin_logout(request):
     if 'admin_id' in request.session:
        del request.session['admin_id']  
     return redirect('adminlogin')

def admin_report(request):
    if request.method == 'POST':
        category = request.POST.get('category')
        page_number = request.POST.get('page', 1)  # Get the page number from the request, default to 1
        
        if category == 'all':
            category_items = Category.objects.all()
        else:
            category_items = Category.objects.filter(category=category)

        paginator = Paginator(category_items, 10)  # Paginate with 10 items per page
        page_obj = paginator.get_page(page_number)  # Get the requested page

        # Generate the HTML for the table
        html = ''
        if page_obj.object_list.exists():
            html += '<table class="table table-bordered mt-3"><thead><tr><th>Serial No.</th><th>URL</th><th>Checked By</th></tr></thead><tbody>'
            for i, item in enumerate(page_obj, start=page_obj.start_index()):
                html += f'<tr><td>{i}</td><td>{item.url}</td><td>{item.login_id}</td></tr>'
            html += '</tbody></table>'

            # Add pagination controls
            html += '<nav aria-label="Page navigation"><ul class="pagination justify-content-center">'
            if page_obj.has_previous():
                html += f'<li class="page-item"><a class="page-link" href="#" onclick="fetchCategoryData(\'{category}\', {page_obj.previous_page_number()})">Previous</a></li>'
            html += f'<li class="page-item disabled"><span class="page-link">Page {page_obj.number} of {paginator.num_pages}</span></li>'
            if page_obj.has_next():
                html += f'<li class="page-item"><a class="page-link" href="#" onclick="fetchCategoryData(\'{category}\', {page_obj.next_page_number()})">Next</a></li>'
            html += '</ul></nav>'

        else:
            html = '<p>No data available for this category.</p>'

        return JsonResponse({'html': html})
    else:
        return render(request, 'admin_report.html')
   

def download_category_data(request, category):
    # Set the response to be a CSV file
    response = HttpResponse(content_type='text/csv')
    response['Content-Disposition'] = f'attachment; filename="{category}_report.csv"'

    # Create a CSV writer
    writer = csv.writer(response)
    
    # Write the header for the CSV file
    writer.writerow(['URL', 'Login ID'])

    # Fetch the category data
    if category == 'all':
        category_items = Category.objects.all()
    else:
        category_items = Category.objects.filter(category=category)

    # Write the data rows to the CSV
    for item in category_items:
        writer.writerow([item.url, item.login_id.name])  # Assuming 'login_id' refers to a related model with 'name'

    # Return the response as a downloadable file
    return response


