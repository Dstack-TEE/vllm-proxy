import json
import sys
import types
import unittest
from importlib.machinery import SourceFileLoader
from importlib.util import module_from_spec, spec_from_loader
from pathlib import Path


class TestQuote(unittest.TestCase):
    def setUp(self):
        self.mock_cc_admin = types.SimpleNamespace(
            collect_gpu_evidence_remote=lambda nonce, **kwargs: [{"mock": "gpu"}],
        )

        attestation_instance = types.SimpleNamespace(
            set_name=lambda *_: None,
            set_nonce=lambda *_: None,
            set_claims_version=lambda *_: None,
            set_ocsp_nonce_disabled=lambda *_: None,
            add_verifier=lambda **kwargs: None,
            get_evidence=lambda **kwargs: [{"mock": "gpu"}],
        )
        attestation_mod = types.SimpleNamespace(
            Attestation=lambda: attestation_instance,
            Devices=types.SimpleNamespace(GPU="GPU"),
            Environment={"REMOTE": "REMOTE"},
        )

        pynvml_mod = types.SimpleNamespace(
            nvmlInit=lambda: None,
            nvmlShutdown=lambda: None,
            nvmlDeviceGetCount=lambda: 1,
        )

        self.captured = {}

        def _get_quote(report_data):
            self.captured["report_data"] = report_data
            return types.SimpleNamespace(
                quote="mock_quote",
                event_log=json.dumps({"mock": True}),
                vm_config="mock_vm_config",
            )

        client = types.SimpleNamespace()
        client.get_quote = _get_quote
        client.info = lambda: types.SimpleNamespace(
            model_dump=lambda: {
                "compose_hash": "db669af634b75c7f298400f3b6c2aa8ba54998bac83e23d10ab4eaadc4b50ccf",
                "tcb_info": {"app_compose": "compose", "mr_config": "01db669af634b75c7f298400f3b6c2aa8ba54998bac83e23d10ab4eaadc4b50ccf"},
            }
        )
        dstack_mod = types.SimpleNamespace(DstackClient=lambda: client)

        # Stub the eth_* stack so loading quote.py stays hermetic (it imports
        # eth_utils / web3 / eth_account at module scope and builds an ECDSA
        # context on import).
        mock_account = types.SimpleNamespace(
            address="0x" + "11" * 20,
            sign_message=lambda msg: types.SimpleNamespace(signature=b"\x00" * 65),
        )
        web3_mod = types.SimpleNamespace(
            Account=object,  # referenced in a SigningContext type annotation
            Web3=lambda: types.SimpleNamespace(
                eth=types.SimpleNamespace(
                    account=types.SimpleNamespace(create=lambda: mock_account)
                )
            ),
        )
        eth_account_messages = types.ModuleType("eth_account.messages")
        eth_account_messages.encode_defunct = lambda **kwargs: None
        eth_account_mod = types.ModuleType("eth_account")
        eth_account_mod.messages = eth_account_messages

        self.original_modules = {}
        for name, module in {
            "verifier": types.SimpleNamespace(cc_admin=self.mock_cc_admin),
            "nv_attestation_sdk": types.SimpleNamespace(attestation=attestation_mod),
            "pynvml": pynvml_mod,
            "dstack_sdk": dstack_mod,
            "eth_utils": types.ModuleType("eth_utils"),
            "web3": web3_mod,
            "eth_account": eth_account_mod,
            "eth_account.messages": eth_account_messages,
        }.items():
            if name in sys.modules:
                self.original_modules[name] = sys.modules[name]
            sys.modules[name] = module

        root = Path(__file__).resolve().parents[3] / "src"
        if str(root) not in sys.path:
            sys.path.insert(0, str(root))

        if "app" not in sys.modules:
            sys.modules["app"] = types.ModuleType("app")
            sys.modules["app"].__path__ = [str(root / "app")]

        if "app.quote" not in sys.modules:
            quote_pkg = types.ModuleType("app.quote")
            quote_pkg.__path__ = [str(root / "app" / "quote")]
            sys.modules["app.quote"] = quote_pkg

        module_path = root / "app" / "quote" / "quote.py"
        loader = SourceFileLoader("app.quote.quote", str(module_path))
        spec = spec_from_loader(loader.name, loader)
        module = module_from_spec(spec)
        loader.exec_module(module)
        sys.modules["app.quote.quote"] = module

        self.quote = module

    def tearDown(self):
        sys.modules.update(self.original_modules)
        for key in [
            "verifier",
            "nv_attestation_sdk",
            "pynvml",
            "dstack_sdk",
            "eth_utils",
            "web3",
            "eth_account",
            "eth_account.messages",
            "app.quote.quote",
            "app.quote",
        ]:
            sys.modules.pop(key, None)

    def test_generate_attestation_binds_nonce(self):
        request_nonce_hex = "aa" * 32
        result = self.quote.generate_attestation(self.quote.ed25519_context, request_nonce_hex)

        self.assertEqual(result["request_nonce"], request_nonce_hex)
        # GPU should use the same request_nonce
        self.assertEqual(json.loads(result["nvidia_payload"])["nonce"], request_nonce_hex)
        # Verify signing_algo and vm_config fields
        self.assertEqual(result["signing_algo"], self.quote.ED25519)
        self.assertIn("vm_config", result)

    def test_build_report_data_layout(self):
        identifier = b"\x01" * 16
        nonce = b"\x02" * 32
        combined = self.quote._build_report_data(identifier, nonce)
        self.assertEqual(combined[:32], identifier.ljust(32, b"\x00"))
        self.assertEqual(combined[32:], nonce)

    def test_build_report_data_fingerprint_mode(self):
        import hashlib

        identifier = b"\x01" * 20
        nonce = b"\x02" * 32
        fingerprint = b"\xab" * 32
        combined = self.quote._build_report_data(identifier, nonce, fingerprint)
        expected_first = hashlib.sha256(identifier + fingerprint).digest()
        self.assertEqual(combined[:32], expected_first)
        self.assertEqual(combined[32:], nonce)
        # The fingerprint layout must differ from the legacy address layout.
        self.assertNotEqual(combined, self.quote._build_report_data(identifier, nonce))

    def test_generate_attestation_fingerprint_binding(self):
        request_nonce_hex = "aa" * 32
        fingerprint = b"\xcd" * 32
        result = self.quote.generate_attestation(
            self.quote.ecdsa_context, request_nonce_hex, cert_fingerprint=fingerprint
        )
        self.assertEqual(result["tls_cert_fingerprint"], fingerprint.hex())
        # report_data passed to get_quote uses the SHA256(addr || fp) layout.
        addr_bytes = self.quote.ecdsa_context.signing_address_bytes
        import hashlib

        expected_first = hashlib.sha256(addr_bytes + fingerprint).digest()
        report_data = self.captured["report_data"]
        self.assertEqual(report_data[:32], expected_first)
        self.assertEqual(report_data[32:].hex(), request_nonce_hex)

    def test_generate_attestation_without_fingerprint_has_no_field(self):
        result = self.quote.generate_attestation(self.quote.ed25519_context, "aa" * 32)
        self.assertNotIn("tls_cert_fingerprint", result)

    def test_random_nonce_generation(self):
        result = self.quote.generate_attestation(self.quote.ed25519_context)
        self.assertEqual(len(bytes.fromhex(result["request_nonce"])), 32)


