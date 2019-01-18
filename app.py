import datetime
import grp

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.serialization import load_pem_public_key
from cryptography.x509.oid import NameOID
from flask import Flask
from flask import jsonify
from flask import request

PRIVATE_KEY_FILE = '/etc/ca.key'

# This can be a short duration, since getting new certs is transparent to the
# end user.
CERT_VALID_FOR = datetime.timedelta(minutes=2)

private_key = load_pem_private_key(
    data=open(PRIVATE_KEY_FILE, 'rb').read(),
    password=None,
    backend=default_backend(),
)


def user_groups(username):
    """Returns all the groups a user is in"""
    return [g.gr_name for g in grp.getgrall() if username in g.gr_mem]


app = Flask(__name__)


@app.route('/cert', methods=['POST'])
def cert():
    # TODO: figure out what this header is actually called
    username = request.headers['AUTH_USER']

    req_json = request.get_json()
    print(req_json)
    pubkey = load_pem_public_key(
        req_json['pubkey'].encode(), backend=default_backend(),
    )

    builder = x509.CertificateBuilder()

    # https://kubernetes.io/docs/reference/access-authn-authz/authentication/#x509-client-certs
    # Set the COMMON_NAME of the cert to be the username
    # and the ORGANIZATION_NAME (specified multiple times) for each group the
    # user is in
    builder = builder.subject_name(x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, username),
    ] + [
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, groupname)
        for groupname in user_groups(username)
    ]))

    builder = builder.issuer_name(x509.Name([
        x509.NameAttribute(
            NameOID.COMMON_NAME,
            'krb-kubernetes.ocf.berkeley.edu',
        ),
    ]))

    # Set the cert's expiration
    builder = builder.not_valid_before(datetime.datetime.today())
    builder = builder.not_valid_after(
        datetime.datetime.today() + CERT_VALID_FOR,
    )

    builder = builder.serial_number(x509.random_serial_number())
    builder = builder.public_key(pubkey)

    # This means the cert isn't allowed to be a CA, i.e. it cannot be used to
    # sign other certs.
    builder = builder.add_extension(
        x509.BasicConstraints(ca=False, path_length=None), critical=True,
    )

    certificate = builder.sign(
        private_key=private_key,
        algorithm=hashes.SHA256(),
        backend=default_backend(),
    )

    return jsonify(
        cert=certificate.public_bytes(serialization.Encoding.PEM).decode(),
    )
