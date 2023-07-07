from django.shortcuts import render, HttpResponse, redirect
from django.contrib import messages
from django.contrib.auth import authenticate, login, logout
from django.contrib.auth.models import User
import random
from django.core.mail import send_mail
from .forms import MyFileUploadForm
from django.http import HttpResponse, FileResponse, StreamingHttpResponse
from django.conf import settings
import mimetypes
import os
from wsgiref.util import FileWrapper


def downloadfile(req):
    base_dir = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    filename = 'abc_compressed.bin'
    filepath = base_dir + '/media/' + filename
    thefile = filepath
    filename = os.path.basename(thefile)
    chunk_size = 8192
    response = StreamingHttpResponse(FileWrapper(open(thefile, 'rb'), chunk_size),
        content_type = mimetypes. guess_type(thefile)[0])
    response['Content-Length'] =os.path.getsize(thefile)
    response['Content-Disposition'] = "Attachment; filename=%s" % filename
    return response

def file_upload_view(request):
    if request.method == 'POST':
        form = MyFileUploadForm(request.POST, request.FILES)
        if form.is_valid():
            uploaded_file = form.cleaned_data['file']
            # Save the uploaded file and create a model instance
            file_path = handle_uploaded_file(uploaded_file)
            print(file_path)
            out = text_compress(uploaded_file)
            return redirect('success')

    else:
        form = MyFileUploadForm()
    return render(request, 'soi2.html', {'form': form})



def handle_uploaded_file(file):
    # Save the uploaded file to a specific location
    file_path = f'media/uploads/{file.name}'
    with open(file_path, 'wb+') as destination:
        for chunk in file.chunks():
            destination.write(chunk)
    return file_path

def begin(request):
    return render(request, 'page1.html')

def success(request):
    return render(request, 'bot.html')

def new(request):
    return render(request, 'loginpage.html')

def signup(request):
    if request.method == 'POST':
        username = request.POST['username']
        email_id = request.POST['email']
        password = request.POST['pwd']
        confirmpassword = request.POST['confpwd']
        phone = request.POST['phone']

        check_user = User.objects.filter(email=email_id).first()

        if check_user:
            messages.error(request, "User already exist")
            return redirect('home')

#     Check the signup requirements
        if len(username) > 20 or len(username) < 8:
            messages.error(request, "Username must be under 20 characters and atleast 8 characters")
            return redirect('home')

        if not username.isalnum():
            messages.error(request, "Username should only contain letters and numbers")
            return redirect('home')

        if len(password) > 40 or len(password) < 8:
            messages.error(request, "Password must be under 40 characters and atleast 8 characters")
            return redirect('home')

        symbols = ['!', '@', '#', '$', '&', '*']
        numbers = ['0','1','2','3','4','5','6','7','8','9']
        letters = list(password)

        if not str(phone).isdigit() :
            messages.error(request, "Phone number should only contain numbers")
            return redirect('home')

        if len(str(phone)) != 10:
            messages.error(request, "Phone number should only 10 digits")
            return redirect('home')

        if letters[0].isupper() is False:
            messages.error(request, "The First Letter of the password must be a capital letter")
            return redirect('home')

        sym = list(set(symbols).intersection(letters))
        num = list(set(numbers).intersection(letters))

        if sym == None:
            messages.error(request, "Password must contain alteast one of the following symbols: '!', '@', '#', '$', '&', '*'")
            return redirect('home')

        if num == None:
            messages.error(request,"Password must contain alteast one digit")
            return redirect('home')

        if password != confirmpassword:
            messages.error(request, "The 2 passwords must be same")
            return redirect('home')

        myuser = User.objects.create_user(username, email_id, password)
        myuser.save()
        otp = str(random.randint(1000, 9999))
        subject = 'OTP Verification'
        message = f'Your OTP for GDriveX is: {otp}'
        from_email = settings.EMAIL_HOST
        recipient_list = [email_id]
        send_mail(subject, message, from_email, recipient_list)

        request.session['otp'] = otp
        messages.success(request, "Your account has been successfully created")
        return redirect('otp')
    else:
        return HttpResponse('404 - Not Found')


def login_(request):
    if request.method == 'POST':
        user_id = request.POST['user_id']
        password = request.POST['pwd']

        user = authenticate(username=user_id, password=password)

        if user is not None:
            login(request, user)
            messages.success(request, "Successfully Logged In")
            return redirect('afterlogin')
        else:
            messages.error(request, "Invalid Credentials, Please try again Or If you don't have an please click sign in button to create an account")
            return redirect('home')

    else:
        return HttpResponse('404 - Not Found')

def logout_(request):
    logout(request)
    messages.success(request, "Successfully Logged Out")
    return redirect('home')


def otp(request):
    otp = request.session['otp']
    context = {'otp': otp}
    if request.method == 'POST':
        _otp_ = request.POST.get('otp')

        print(otp)
        print(_otp_)

        if otp == _otp_:
            return redirect('afterlogin')
        else:
            print('Wrong OTP')
            context = {'message': 'Wrong OTP', 'class': 'danger', 'otp': otp}
            return render(request, 'otp.html', context)
    return render(request, 'otp.html', context)

def after(request):
    return render(request, 'soi2.html')

def text_compress(file_path):

    class Tree:
        def __init__(self, left, right, data):
            self.left = left
            self.right = right
            self.data = data

    class File:
        def __init__(self):
            self.freq = {}
            self.tree_list = []
            self.codes = {}
            self.reverse_codes = {}

        def frequency_dictionary(self, text):
            for ch in text:
                if ch in self.freq:
                    self.freq[ch] += 1
                else:
                    self.freq[ch] = 1

        def sort_dict(self):
            self.freq = dict(sorted(self.freq.items(), key=lambda x: x[1]))

        def merge_dict(self):
            keys = list(self.freq.keys())
            key = keys[0] + keys[1]
            value = self.freq[keys[0]] + self.freq[keys[1]]

            self.make_tree(keys, key)

            self.freq[key] = value
            self.freq.pop(keys[0])
            self.freq.pop(keys[1])
            self.sort_dict()

        def make_tree(self, keys, key):
            if len(keys[0]) == 1:
                code1 = Tree(None, None, keys[0])
            else:
                for i in self.tree_list:
                    if i.data == keys[0]:
                        code1 = i
                        self.tree_list.remove(i)
                        break

            if len(keys[1]) == 1:
                code2 = Tree(None, None, keys[1])
            else:
                for i in self.tree_list:
                    if i.data == keys[1]:
                        code2 = i
                        self.tree_list.remove(i)
                        break

            tree = Tree(code1, code2, key)
            self.tree_list.append(tree)

        def encode(self, head, current_code):
            if head == None:
                return

            if len(head.data) == 1:
                self.codes[head.data] = current_code
                self.reverse_codes[current_code] = head.data

            self.encode(head.left, current_code + '0')
            self.encode(head.right, current_code + '1')

        def encoded_text(self, text):
            encoded_text = ''
            for i in text:
                encoded_text += self.codes[i]

            return encoded_text

        def text_padding(self, text):
            padding = 8 - len(text) % 8
            for i in range(0, padding):
                text += '0'

            padded_info = "{0:08b}".format(padding)
            text = padded_info + text
            return text

        def byte_array(self, padded_text):
            b = bytearray()
            for i in range(0, len(padded_text), 8):
                byte = padded_text[i:i + 8]
                b.append(int(byte, 2))
            return b

        def compress(self, path):
            filename, extention = os.path.splitext(path)
            output_path = filename + "_compressed.bin"
            file = open(path, "r")
            compressed_file = open(output_path, "wb")

            text = file.read()
            self.frequency_dictionary(text)
            if len(self.freq) != 1:
                self.sort_dict()

                while len(self.freq) != 1:
                    self.merge_dict()

                head = self.tree_list[0]
                self.tree_list.pop()

                self.encode(head, '')
            else:
                key = list(self.freq.keys())
                self.codes[key[0]] = '0'

            encoded_text = self.encoded_text(text)
            padded_text = self.text_padding(encoded_text)

            b = self.byte_array(padded_text)
            compressed_file.write(bytes(b))

            print("compressed")
            return output_path

        def remove_padding(self, bit_string):
            padded_info = bit_string[:8]
            extra_padding = int(padded_info, 2)

            bit_string = bit_string[8:]
            encoded_text = bit_string[:-1 * extra_padding]

            return encoded_text

        def decode_text(self, encoded_text):
            binar_code = ''
            decoded_text = ''
            for b in encoded_text:
                binar_code += b
                if binar_code in self.reverse_codes:
                    decoded_text += self.reverse_codes[binar_code]
                    binar_code = ''

            return decoded_text

        def decompress(self, path):
            filename, extention = os.path.splitext(path)
            output_path = filename.replace('_compressed', '_decompressed') + ".txt"
            file = open(path, "rb")
            decompressed_file = open(output_path, "w")

            bit_string = ""
            byte = file.read(1)
            while len(byte) > 0:
                byte = ord(byte)
                bits = bin(byte)[2:].rjust(8, '0')
                bit_string += bits
                byte = file.read(1)

                # print(bit_string)

            encoded_text = self.remove_padding(bit_string)
            decoded_text = self.decode_text(encoded_text)

            decompressed_file.write(decoded_text)

            print("decompressed")

    file = File()
    output = file.compress(f'media/uploads/{file_path.name}')
    file.decompress(f'{output}')





