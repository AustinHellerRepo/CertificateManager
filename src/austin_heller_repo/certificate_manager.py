from __future__ import annotations
from typing import List, Tuple, Dict, Callable, Type
import time
import base64
import uuid
import os
import errno
import tempfile
from datetime import datetime, timedelta
from enum import IntEnum
import re
import ipaddress
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
from cryptography.x509.oid import NameOID
from cryptography.x509.general_name import GeneralName
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
	def create_self_signed_certificate(*, name: str, valid_days_total: int = 30, key_size: int = 2048) -> Certificate:
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


class CertificateManagerClientMessageTypeEnum(IntEnum):
	RequestSignedCertificate = 1
	RequestRootCertificate = 2


class CertificateManagerClient():

	def __init__(self, *, client_socket_factory: ClientSocketFactory, server_host_pointer: HostPointer, is_debug: bool = False):

		self.__client_socket_factory = client_socket_factory
		self.__server_host_pointer = server_host_pointer
		self.__is_debug = is_debug

	def request_certificate(self, *, name: str, key_size: int = 2048) -> Certificate:

		if self.__is_debug:
			print(f"{datetime.utcnow()}: CertificateManagerClient: request_certificate: start")

		client_socket = self.__client_socket_factory.get_client_socket()
		client_socket.connect_to_server(
			ip_address=self.__server_host_pointer.get_host_address(),
			port=self.__server_host_pointer.get_host_port()
		)

		try:
			client_socket.write(str(CertificateManagerClientMessageTypeEnum.RequestSignedCertificate.value))

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

			if re.match(r"^\d{1,3}\.\d{1.3}\.\d{1,3}\.\d{1,3}$", name):
				ip_address = ipaddress.IPv4Address(name)
				builder = builder.add_extension(
					x509.SubjectAlternativeName([x509.general_name.IPAddress(ip_address)]),
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

			client_socket.write(request_base64_string)

			response_base64_string = client_socket.read()
			response_base64_bytes = response_base64_string.encode()
			response_bytes = base64.b64decode(response_base64_bytes)

			certificate = Certificate.load_from_bytes(
				private_key_bytes=private_key.private_bytes(Encoding.PEM, PrivateFormat.TraditionalOpenSSL, NoEncryption()),
				signed_certificate_bytes=response_bytes
			)

			return certificate
		except Exception as ex:
			if self.__is_debug:
				print(f"{datetime.utcnow()}: CertificateManagerClient: request_certificate: ex: {ex}")
			raise
		finally:
			client_socket.close()

			if self.__is_debug:
				print(f"{datetime.utcnow()}: CertificateManagerClient: request_certificate: end")

	def get_root_certificate(self, *, save_to_file_path: str):

		if self.__is_debug:
			print(f"{datetime.utcnow()}: CertificateManagerClient: get_root_certificate: start")

		client_socket = self.__client_socket_factory.get_client_socket()
		client_socket.connect_to_server(
			ip_address=self.__server_host_pointer.get_host_address(),
			port=self.__server_host_pointer.get_host_port()
		)

		try:
			client_socket.write(str(CertificateManagerClientMessageTypeEnum.RequestRootCertificate.value))

			response_base64_string = client_socket.read()
			response_base64_bytes = response_base64_string.encode()
			response_bytes = base64.b64decode(response_base64_bytes)

			with open(save_to_file_path, "wb") as file_handle:
				file_handle.write(response_bytes)
		except Exception as ex:
			if self.__is_debug:
				print(f"{datetime.utcnow()}: CertificateManagerClient: get_root_certificate: ex: {ex}")
			raise
		finally:
			client_socket.close()

			if self.__is_debug:
				print(f"{datetime.utcnow()}: CertificateManagerClient: get_root_certificate: end")


class CertificateManagerServer():

	# private_key_file_path should be something like "certname.key"
	# public_certificate_file_path should be something like "certname.crt"
	def __init__(self, *, server_socket_factory: ServerSocketFactory, server_host_pointer: HostPointer, public_certificate_file_path: str, private_key_file_path: str, certificate_valid_days: int, is_debug: bool = False):

		self.__server_socket_factory = server_socket_factory
		self.__server_host_pointer = server_host_pointer
		self.__public_certificate_file_path = public_certificate_file_path
		self.__private_key_file_path = private_key_file_path
		self.__certificate_valid_days = certificate_valid_days
		self.__is_debug = is_debug

		self.__server_socket = None  # type: ServerSocket
		self.__server_certificate = None  # type: Certificate

		self.__initialize()

	def __initialize(self):

		if self.__is_debug:
			print(f"{datetime.utcnow()}: CertificateManagerServer: __initialize: start")

		self.__server_certificate = Certificate.load_from_file(
			private_key_file_path=self.__private_key_file_path,
			signed_certificate_file_path=self.__public_certificate_file_path
		)

		if self.__is_debug:
			print(f"{datetime.utcnow()}: CertificateManagerServer: __initialize: end")

	def __process_signed_certificate_request(self, *, client_socket: ClientSocket):

		if self.__is_debug:
			print(f"{datetime.utcnow()}: CertificateManagerServer: __process_signed_certificate_request: start")

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

		if self.__is_debug:
			print(f"{datetime.utcnow()}: CertificateManagerServer: __process_signed_certificate_request: end")

	def __process_root_certificate_request(self, *, client_socket: ClientSocket):

		if self.__is_debug:
			print(f"{datetime.utcnow()}: CertificateManagerServer: __process_root_certificate_request: start")

		signed_certificate_bytes = self.__server_certificate.get_signed_certificate().public_bytes(serialization.Encoding.PEM)
		signed_certificate_base64_bytes = base64.b64encode(signed_certificate_bytes)  # type: bytes
		signed_certificate_base64_string = signed_certificate_base64_bytes.decode()

		client_socket.write(signed_certificate_base64_string)

		if self.__is_debug:
			print(f"{datetime.utcnow()}: CertificateManagerServer: __process_root_certificate_request: end")

	def __on_accepted_client_method(self, client_socket: ClientSocket):

		if self.__is_debug:
			print(f"{datetime.utcnow()}: CertificateManagerServer: __on_accepted_client_method: start")

		try:
			certificate_manager_client_message_type_string = client_socket.read()
			certificate_manager_client_message_type = CertificateManagerClientMessageTypeEnum(int(certificate_manager_client_message_type_string))

			if certificate_manager_client_message_type == CertificateManagerClientMessageTypeEnum.RequestSignedCertificate:
				self.__process_signed_certificate_request(
					client_socket=client_socket
				)
			elif certificate_manager_client_message_type == CertificateManagerClientMessageTypeEnum.RequestRootCertificate:
				self.__process_root_certificate_request(
					client_socket=client_socket
				)
			else:
				raise NotImplementedError()

		except ReadWriteSocketClosedException as ex:
			if self.__is_debug:
				print(f"{datetime.utcnow()}: CertificateManagerServer: __on_accepted_client_method: client socket closed")
			pass
		except Exception as ex:
			if self.__is_debug:
				print(f"{datetime.utcnow()}: CertificateManagerServer: __on_accepted_client_method: ex: {ex}")
			raise
		finally:
			client_socket.close()

			if self.__is_debug:
				print(f"{datetime.utcnow()}: CertificateManagerServer: __on_accepted_client_method: end")

	def start_accepting_clients(self):

		if self.__is_debug:
			print(f"{datetime.utcnow()}: CertificateManagerServer: start_accepting_clients: start")

		try:
			if self.__server_socket is not None:
				raise Exception(f"{datetime.utcnow()}: already started accepting clients")

			self.__server_socket = self.__server_socket_factory.get_server_socket()
			self.__server_socket.start_accepting_clients(
				host_ip_address=self.__server_host_pointer.get_host_address(),
				host_port=self.__server_host_pointer.get_host_port(),
				on_accepted_client_method=self.__on_accepted_client_method
			)
		finally:
			if self.__is_debug:
				print(f"{datetime.utcnow()}: CertificateManagerServer: start_accepting_clients: end")

	def stop_accepting_clients(self):

		if self.__is_debug:
			print(f"{datetime.utcnow()}: CertificateManagerServer: stop_accepting_clients: start")

		try:
			self.__server_socket.stop_accepting_clients()
			self.__server_socket.close()
		finally:
			if self.__is_debug:
				print(f"{datetime.utcnow()}: CertificateManagerServer: stop_accepting_clients: end")
