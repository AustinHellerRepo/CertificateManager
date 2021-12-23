import unittest
from typing import List, Tuple, Dict, Callable, Type
import time
import tempfile
from src.austin_heller_repo.certificate_manager import CertificateManagerClient, CertificateManagerServer, Certificate
from austin_heller_repo.threading import start_thread, Semaphore
from austin_heller_repo.socket import ClientSocketFactory, ServerSocketFactory
from austin_heller_repo.common import HostPointer


default_server_certificate = Certificate.create_self_signed_certificate(
	key_size=2048,
	name="server certificate",
	valid_days_total=30
)
temp_private_key_file_path = tempfile.NamedTemporaryFile(
	delete=False
)
temp_signed_certificate_file_path = tempfile.NamedTemporaryFile(
	delete=False
)
default_server_certificate.save_to_file(
	private_key_file_path=temp_private_key_file_path.name,
	signed_certificate_file_path=temp_signed_certificate_file_path.name
)


def get_default_public_certificate_file_path() -> str:
	return temp_signed_certificate_file_path.name


def get_default_private_key_file_path() -> str:
	return temp_private_key_file_path.name


def get_default_local_host_pointer() -> HostPointer:
	return HostPointer(
		host_address="0.0.0.0",
		host_port=32811
	)


def get_default_certificate_manager_client() -> CertificateManagerClient:
	return CertificateManagerClient(
		client_socket_factory=ClientSocketFactory(
			to_server_packet_bytes_length=4096
		),
		server_host_pointer=get_default_local_host_pointer()
	)


def get_default_certificate_manager_server() -> CertificateManagerServer:
	return CertificateManagerServer(
		server_socket_factory=ServerSocketFactory(
			to_client_packet_bytes_length=4096,
			listening_limit_total=10,
			accept_timeout_seconds=1.0
		),
		server_host_pointer=get_default_local_host_pointer(),
		public_certificate_file_path=get_default_public_certificate_file_path(),
		private_key_file_path=get_default_private_key_file_path(),
		certificate_valid_days=30
	)


class CertificateManagerTest(unittest.TestCase):

	def test_initialize(self):

		certificate_manager_client = get_default_certificate_manager_client()

		self.assertIsNotNone(certificate_manager_client)

		certificate_manager_server = get_default_certificate_manager_server()

		self.assertIsNotNone(certificate_manager_server)

	def test_connect_and_close(self):

		certificate_manager_server = get_default_certificate_manager_server()

		certificate_manager_server.start_accepting_clients()

		time.sleep(1)

		certificate_manager_client = get_default_certificate_manager_client()

		certificate_manager_client.connect_to_server()

		time.sleep(1)

		certificate_manager_client.close()

		certificate_manager_server.stop_accepting_clients()

		time.sleep(1)

	def test_request_certificate(self):

		certificate_manager_server = get_default_certificate_manager_server()

		certificate_manager_server.start_accepting_clients()

		time.sleep(1)

		certificate_manager_client = get_default_certificate_manager_client()

		certificate_manager_client.connect_to_server()

		time.sleep(1)

		certificate = certificate_manager_client.request_certificate(
			key_size=2048,
			name="test"
		)

		certificate_manager_client.close()

		certificate_manager_server.stop_accepting_clients()

		time.sleep(1)

		self.assertIsNotNone(certificate)
