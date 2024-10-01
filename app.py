from flask import Flask, request, jsonify, render_template
import ssl
import socket
from cryptography import x509
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)

def get_certificate(ip_address, port=6467):
    context = ssl.create_default_context()
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    print(f"Attempting to connect to {ip_address}:{port}")
    with socket.create_connection((ip_address, port)) as sock:
        with context.wrap_socket(sock, server_hostname=ip_address) as secure_sock:
            der_cert = secure_sock.getpeercert(binary_form=True)
            return der_cert

def decode_certificate(der_cert):
    cert = x509.load_der_x509_certificate(der_cert)
    public_key = cert.public_key()
    public_numbers = public_key.public_numbers()
    modulus = public_numbers.n
    exponent = public_numbers.e
    return modulus, exponent

def format_modulus(modulus):
    hex_string = format(modulus, 'x').zfill(512)
    return ':'.join(['00'] + [hex_string[i:i+2] for i in range(0, len(hex_string), 2)])

@app.route('/', methods=['GET'])
def index():
    return render_template('index.html')

@app.route('/get_cert', methods=['POST'])
def get_cert():
    ip_address = request.json['ip_address']
    try:
        der_cert = get_certificate(ip_address)
        modulus, exponent = decode_certificate(der_cert)
        formatted_modulus = format_modulus(modulus)
        return jsonify({
            'success': True,
            'modulus': formatted_modulus,
            'exponent': exponent
        })
    except Exception as e:
        return jsonify({
            'success': False,
            'error': str(e)
        })

if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0')