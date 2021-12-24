import unittest
from typing import List, Tuple, Dict, Callable, Type
import time
import tempfile
import uuid
from src.austin_heller_repo.certificate_manager import CertificateManagerClient, CertificateManagerServer, Certificate
from austin_heller_repo.threading import start_thread, Semaphore
from austin_heller_repo.socket import ClientSocketFactory, ServerSocketFactory, ClientSocket, ServerSocket
from austin_heller_repo.common import HostPointer


is_client_socket_debug = False
is_server_socket_debug = False
is_certificate_manager_client_debug = True
is_certificate_manager_server_debug = True


default_self_signed_certificate = Certificate.create_self_signed_certificate(
	name="localhost"
)
self_signed_private_key_file_path = tempfile.NamedTemporaryFile(
	delete=False
)
self_signed_signed_certificate_file_path = tempfile.NamedTemporaryFile(
	delete=False
)
default_self_signed_certificate.save_to_file(
	private_key_file_path=self_signed_private_key_file_path.name,
	signed_certificate_file_path=self_signed_signed_certificate_file_path.name
)


def get_default_public_certificate_file_path() -> str:
	return self_signed_signed_certificate_file_path.name


def get_default_private_key_file_path() -> str:
	return self_signed_private_key_file_path.name


def get_default_local_host_pointer() -> HostPointer:
	return HostPointer(
		host_address="0.0.0.0",
		host_port=32811
	)


def get_default_certificate_manager_client() -> CertificateManagerClient:
	return CertificateManagerClient(
		client_socket_factory=ClientSocketFactory(
			to_server_packet_bytes_length=4096,
			is_debug=is_client_socket_debug
		),
		server_host_pointer=get_default_local_host_pointer(),
		is_debug=is_certificate_manager_client_debug
	)


def get_default_certificate_manager_server() -> CertificateManagerServer:
	return CertificateManagerServer(
		server_socket_factory=ServerSocketFactory(
			to_client_packet_bytes_length=4096,
			listening_limit_total=10,
			accept_timeout_seconds=1.0,
			is_debug=is_server_socket_debug
		),
		server_host_pointer=get_default_local_host_pointer(),
		public_certificate_file_path=get_default_public_certificate_file_path(),
		private_key_file_path=get_default_private_key_file_path(),
		certificate_valid_days=30,
		is_debug=is_certificate_manager_server_debug
	)


class CertificateManagerTest(unittest.TestCase):

	def test_initialize(self):

		certificate_manager_client = get_default_certificate_manager_client()

		self.assertIsNotNone(certificate_manager_client)

		certificate_manager_server = get_default_certificate_manager_server()

		self.assertIsNotNone(certificate_manager_server)

	def test_request_certificate(self):

		certificate_manager_server = get_default_certificate_manager_server()

		certificate_manager_server.start_accepting_clients()

		time.sleep(1)

		certificate_manager_client = get_default_certificate_manager_client()

		certificate = certificate_manager_client.request_certificate(
			name="test"
		)

		certificate_manager_server.stop_accepting_clients()

		time.sleep(1)

		self.assertIsNotNone(certificate)

	def test_connect_with_ssl(self):

		certificate_manager_server = get_default_certificate_manager_server()

		certificate_manager_server.start_accepting_clients()

		time.sleep(1)

		certificate_manager_client = get_default_certificate_manager_client()

		client_certificate = certificate_manager_client.request_certificate(
			name="test client"
		)

		print(client_certificate.get_signed_certificate().subject)
		print(client_certificate.get_signed_certificate().issuer)
		print(client_certificate.get_private_key())

		server_certificate = certificate_manager_client.request_certificate(
			name="0.0.0.0"
		)

		print(server_certificate.get_signed_certificate().subject)
		print(server_certificate.get_signed_certificate().issuer)
		print(server_certificate.get_private_key())

		root_certificate_tempfile = tempfile.NamedTemporaryFile(
			delete=False
		)

		certificate_manager_client.get_root_certificate(
			save_to_file_path=root_certificate_tempfile.name
		)

		with open(root_certificate_tempfile.name, "rb") as file_handle:
			print(file_handle.read())

		certificate_manager_server.stop_accepting_clients()

		time.sleep(1)

		client_private_key_tempfile = tempfile.NamedTemporaryFile(
			delete=False
		)

		client_signed_certificate_tempfile = tempfile.NamedTemporaryFile(
			delete=False
		)

		client_certificate.save_to_file(
			private_key_file_path=client_private_key_tempfile.name,
			signed_certificate_file_path=client_signed_certificate_tempfile.name
		)

		server_private_key_tempfile = tempfile.NamedTemporaryFile(
			delete=False
		)

		server_signed_certificate_tempfile = tempfile.NamedTemporaryFile(
			delete=False
		)

		server_certificate.save_to_file(
			private_key_file_path=server_private_key_tempfile.name,
			signed_certificate_file_path=server_signed_certificate_tempfile.name
		)

		server_socket = ServerSocket(
			to_client_packet_bytes_length=4096,
			listening_limit_total=10,
			accept_timeout_seconds=1.0,
			ssl_private_key_file_path=server_private_key_tempfile.name,
			ssl_certificate_file_path=server_signed_certificate_tempfile.name,
			root_ssl_certificate_file_path=root_certificate_tempfile.name
		)

		expected_message = str(uuid.uuid4())

		def on_accepted_client_method(client_socket: ClientSocket):
			nonlocal expected_message
			print(f"Client connected!")
			actual_message = client_socket.read()
			self.assertEqual(expected_message, actual_message)
			client_socket.close()

		server_socket.start_accepting_clients(
			host_ip_address="0.0.0.0",
			host_port=36451,
			on_accepted_client_method=on_accepted_client_method
		)

		time.sleep(1)

		client_socket = ClientSocket(
			packet_bytes_length=4096,
			ssl_private_key_file_path=client_private_key_tempfile.name,
			ssl_certificate_file_path=client_signed_certificate_tempfile.name,
			root_ssl_certificate_file_path=root_certificate_tempfile.name
		)

		client_socket.connect_to_server(
			ip_address="0.0.0.0",
			port=36451
		)

		client_socket.write(expected_message)

		time.sleep(1)

		client_socket.close()

		server_socket.stop_accepting_clients()

		server_socket.close()

		time.sleep(5)
