from __future__ import annotations
from typing import List, Tuple, Dict, Callable, Type
import time
import base64
import uuid
import os
import errno
from datetime import datetime, timedelta
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID
from austin_heller_repo.socket import ClientSocketFactory, ClientSocket, ServerSocketFactory, ServerSocket, ReadWriteSocketClosedException
from austin_heller_repo.common import HostPointer


class Certificate():

	def __init__(self, *, private_key: rsa.RSAPrivateKey, signed_certificate: x509.Certificate):

		self.__private_key = private_key
		self.__signed_certificate = signed_certificate

	def get_private_key(self) -> rsa.RSAPrivateKey:
		return self.__private_key

	def get_signed_certificate(self) -> x509.Certificate:
		return self.__signed_certificate

	# private_key_file_path should be something like "certname.key"
	# signed_certificate_file_path should be something like "certname.crt"
	def save_to_file(self, *, private_key_file_path: str, signed_certificate_file_path: str):

		if not os.path.exists(os.path.dirname(private_key_file_path)):
			try:
				os.makedirs(os.path.dirname(private_key_file_path))
			except OSError as ex:
				if ex.errno != errno.EEXIST:
					raise
		with open(private_key_file_path, "wb") as file_handle:
			file_handle.write(self.__private_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()))

		if not os.path.exists(os.path.dirname(signed_certificate_file_path)):
			try:
				os.makedirs(os.path.dirname(signed_certificate_file_path))
			except OSError as ex:
				if ex.errno != errno.EEXIST:
					raise
		with open(signed_certificate_file_path, "wb") as file_handle:
			file_handle.write(self.__signed_certificate.public_bytes(serialization.Encoding.PEM))

	@staticmethod
	def load_from_file(*, private_key_file_path: str, signed_certificate_file_path: str) -> Certificate:
		with open(private_key_file_path, "rb") as file_handle:
			private_key_bytes = file_handle.read()
		with open(signed_certificate_file_path, "rb") as file_handle:
			signed_certificate_bytes = file_handle.read()
		return Certificate.load_from_bytes(
			private_key_bytes=private_key_bytes,
			signed_certificate_bytes=signed_certificate_bytes
		)

	@staticmethod
	def load_from_bytes(*, private_key_bytes: bytes, signed_certificate_bytes: bytes) -> Certificate:
		return Certificate(
			private_key=serialization.load_pem_private_key(
				data=private_key_bytes,
				password=None,
				backend=default_backend()
			),
			signed_certificate=x509.load_pem_x509_certificate(
				data=signed_certificate_bytes,
				backend=default_backend()
			)
		)

	@staticmethod
	def process_certificate_request(certificate_request: x509.CertificateSigningRequest, signing_certificate: Certificate, valid_days_total: int) -> x509.Certificate:

		builder = x509.CertificateBuilder() \
			.subject_name(certificate_request.subject) \
			.issuer_name(signing_certificate.get_signed_certificate().subject) \
			.not_valid_before(datetime.utcnow() - timedelta(days=1)) \
			.not_valid_after(datetime.utcnow() + timedelta(days=valid_days_total)) \
			.public_key(certificate_request.public_key()) \
			.serial_number(int(uuid.uuid4()))

		for extension in certificate_request.extensions:
			builder = builder.add_extension(
				extval=extension.value,
				critical=extension.critical
			)

		signed_certificate = builder.sign(
			private_key=signing_certificate.get_private_key(),
			algorithm=hashes.SHA256(),
			backend=default_backend()
		)

		return signed_certificate

	@staticmethod
	def create_self_signed_certificate(*, key_size: int, name: str, valid_days_total: int) -> Certificate:
		# https://stackoverflow.com/questions/56285000/python-cryptography-create-a-certificate-signed-by-an-existing-ca-and-export

		private_key = rsa.generate_private_key(
			public_exponent=65537,
			key_size=key_size,
			backend=default_backend()
		)

		builder = x509.CertificateBuilder() \
			.subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])) \
			.issuer_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, name)])) \
			.public_key(private_key.public_key()) \
			.not_valid_before(datetime.utcnow() - timedelta(days=1)) \
			.not_valid_after(datetime.utcnow() + timedelta(days=valid_days_total)) \
			.serial_number(int(uuid.uuid4())) \
			.add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)

		signed_certificate = builder.sign(
			private_key=private_key,
			algorithm=hashes.SHA256(),
			backend=default_backend()
		)

		return Certificate(
			private_key=private_key,
			signed_certificate=signed_certificate
		)


class CertificateManagerClient():

	def __init__(self, *, client_socket_factory: ClientSocketFactory, server_host_pointer: HostPointer):

		self.__client_socket_factory = client_socket_factory
		self.__server_host_pointer = server_host_pointer

		self.__client_socket = None  # type: ClientSocket

	def connect_to_server(self):

		if self.__client_socket is not None:
			raise Exception(f"Already connected to server")

		self.__client_socket = self.__client_socket_factory.get_client_socket()
		self.__client_socket.connect_to_server(
			ip_address=self.__server_host_pointer.get_host_address(),
			port=self.__server_host_pointer.get_host_port()
		)

	def request_certificate(self, *, key_size: int, name: str) -> Certificate:

		private_key = rsa.generate_private_key(
			public_exponent=65537,
			key_size=key_size,
			backend=default_backend()
		)

		builder = x509.CertificateSigningRequestBuilder() \
			.subject_name(x509.Name([
				x509.NameAttribute(NameOID.COMMON_NAME, name)
			])) \
			.add_extension(
				extval=x509.BasicConstraints(
					ca=False,
					path_length=None
				),
				critical=True
			)

		request = builder.sign(
			private_key=private_key,
			algorithm=hashes.SHA256(),
			backend=default_backend()
		)

		request_bytes = request.public_bytes(Encoding.PEM)
		request_base64_bytes = base64.b64encode(request_bytes)  # type: bytes
		request_base64_string = request_base64_bytes.decode()

		self.__client_socket.write(request_base64_string)

		response_base64_string = self.__client_socket.read()
		response_base64_bytes = response_base64_string.encode()
		response_bytes = base64.b64decode(response_base64_bytes)

		certificate = Certificate.load_from_bytes(
			private_key_bytes=private_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()),
			signed_certificate_bytes=response_bytes
		)

		return certificate

	def close(self):

		self.__client_socket.close()


class CertificateManagerServer():

	# private_key_file_path should be something like "certname.key"
	# public_certificate_file_path should be something like "certname.crt"
	def __init__(self, *, server_socket_factory: ServerSocketFactory, server_host_pointer: HostPointer, public_certificate_file_path: str, private_key_file_path: str, certificate_valid_days: int):

		self.__server_socket_factory = server_socket_factory
		self.__server_host_pointer = server_host_pointer
		self.__public_certificate_file_path = public_certificate_file_path
		self.__private_key_file_path = private_key_file_path
		self.__certificate_valid_days = certificate_valid_days

		self.__server_socket = None  # type: ServerSocket
		self.__server_certificate = None  # type: Certificate

		self.__initialize()

	def __initialize(self):

		self.__server_certificate = Certificate.load_from_file(
			private_key_file_path=self.__private_key_file_path,
			signed_certificate_file_path=self.__public_certificate_file_path
		)

	def __on_accepted_client_method(self, client_socket: ClientSocket):

		try:
			request_base64_string = client_socket.read()
			request_base64_bytes = request_base64_string.encode()
			request_bytes = base64.b64decode(request_base64_bytes)

			certificate_request = x509.load_pem_x509_csr(
				data=request_bytes,
				backend=default_backend()
			)

			signed_certificate = Certificate.process_certificate_request(
				certificate_request=certificate_request,
				signing_certificate=self.__server_certificate,
				valid_days_total=self.__certificate_valid_days
			)

			signed_certificate_bytes = signed_certificate.public_bytes(serialization.Encoding.PEM)
			signed_certificate_base64_bytes = base64.b64encode(signed_certificate_bytes)  # type: bytes
			signed_certificate_base64_string = signed_certificate_base64_bytes.decode()

			client_socket.write(signed_certificate_base64_string)
		except ReadWriteSocketClosedException as ex:
			print(f"{datetime.utcnow()}: CertificateManagerServer: __on_accepted_client_method: client socket closed")
			pass
		except Exception as ex:
			print(f"{datetime.utcnow()}: CertificateManagerServer: __on_accepted_client_method: ex: {ex}")
			raise ex
		finally:
			client_socket.close()

	def start_accepting_clients(self):

		if self.__server_socket is not None:
			raise Exception(f"{datetime.utcnow()}: already started accepting clients")

		self.__server_socket = self.__server_socket_factory.get_server_socket()
		self.__server_socket.start_accepting_clients(
			host_ip_address=self.__server_host_pointer.get_host_address(),
			host_port=self.__server_host_pointer.get_host_port(),
			on_accepted_client_method=self.__on_accepted_client_method
		)

	def stop_accepting_clients(self):

		self.__server_socket.stop_accepting_clients()
		self.__server_socket.close()
