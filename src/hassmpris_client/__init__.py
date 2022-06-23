import logging
import os
import sys
import threading

from typing import List, Tuple, cast

# FIXME: the next line should be fixed when Fedora has
# protoc 3.19.0 or later, and the protobufs need to be recompiled
# when that happens.  Not just the hassmpris protos, also the
# cakes ones.
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"

import cakes  # noqa: E402
import blindecdh  # noqa: E402
import shortauthstrings  # noqa: E402

import grpc  # noqa: E402
from hassmpris.proto import mpris_pb2_grpc, mpris_pb2  # noqa: E402
import hassmpris.certs as certs  # noqa: E402
from hassmpris.certs import PEM  # noqa: E402

from hassmpris import config  # noqa: E402

from cryptography.x509 import CertificateSigningRequest, Certificate  # noqa: E402,E501
from cryptography.hazmat.primitives.asymmetric.rsa import (  # noqa: E402,E501
    RSAPrivateKey,
)


__version__ = "0.0.3"

_LOGGER = logging.getLogger(__name__)


class CAKESRequestor(object):
    def __init__(
        self,
        address: str,
        client_csr: CertificateSigningRequest,
    ):
        self.address = address
        self.client_csr = client_csr

    def accept_ecdh_via_console(
        self,
        unused_peer: str,
        complete: blindecdh.CompletedECDH,
    ) -> bool:
        print(
            "Key appears to be %s"
            % shortauthstrings.emoji(
                complete.derived_key,
                6,
            )
        )
        print("Accept?  [Y/N then ENTER]")
        line = sys.stdin.readline()
        result = line.lower().startswith("y")
        return result

    def run(self) -> Tuple[Certificate, List[Certificate]]:
        with grpc.insecure_channel(self.address) as channel:
            client = cakes.CAKESClient(
                channel,
                self.client_csr,
                self.accept_ecdh_via_console,
                cakes.unconditional_accept_cert,
            )
            clientcert, chain = client.run()
        return clientcert, chain


class MPRISClient(object):
    def __init__(
        self,
        address: str,
        client_cert: Certificate,
        client_key: RSAPrivateKey,
        trust_chain: List[Certificate],
    ):
        self.address = address
        self.client_cert = client_cert
        self.client_key = client_key
        self.trust_chain = trust_chain
        self.last_player = ""

    def run(self) -> None:
        trust_chain_pem = b"\n".join(
            PEM.from_rsa_certificate(c).as_bytes() for c in self.trust_chain
        )
        client_cert_pem = PEM.from_rsa_certificate(self.client_cert).as_bytes()
        client_key_pem = PEM.from_rsa_privkey(self.client_key).as_bytes()

        credentials = grpc.ssl_channel_credentials(
            trust_chain_pem,
            client_key_pem,
            client_cert_pem,
        )
        # By convention, the SSL certificate for the server always uses
        # common name "hassmpris" (see `certs.create_server_certs()`).
        channel = grpc.secure_channel(
            self.address,
            credentials,
            options=[("grpc.ssl_target_name_override", "hassmpris")],
        )
        stub = mpris_pb2_grpc.MPRISStub(channel=channel)  # type: ignore

        t = threading.Thread(target=lambda: self.async_(stub), daemon=True)
        t.start()
        self.repl(stub)
        channel.close()  # raises exception in self.async_ FIXME
        t.join()

    def async_(self, stub: mpris_pb2_grpc.MPRISStub) -> None:
        try:
            for untyped_reply in stub.Updates(mpris_pb2.MPRISUpdateRequest()):
                reply = cast(mpris_pb2.MPRISUpdateReply, untyped_reply)
                print(reply)
                self.last_player = reply.player_id
        except grpc.RpcError as e:
            if e.code() == grpc.StatusCode.CANCELLED:
                # The server may still be working, but on my side the
                # socket is closed.
                return
            else:
                raise

    def repl(self, stub: mpris_pb2_grpc.MPRISStub) -> None:
        print(
            "When you open an MPRIS-compatible player, you will see its name scroll onscreen."  # noqa: E501
        )
        print("Commands:")
        print("* play [optionally player name]  -- plays media on the player")
        print("* pause [optionally player name] -- pauses media on the player")
        print("* stop [optionally player name]  -- stops media on the player")
        print("* empty line                     -- exits the client")
        print()
        while True:
            sys.stdout.write("> ")
            sys.stdout.flush()
            s = sys.stdin.readline().strip()
            if not s:
                return
            try:
                cmd, player = s.split(" ", 1)
            except ValueError:
                cmd, player = s, self.last_player
                if not player:
                    print("There is no last player to commandeer.")
                    continue

            pbstatus = mpris_pb2.ChangePlayerStatusRequest.PlaybackStatus
            try:
                if cmd == "pause":
                    stub.ChangePlayerStatus(
                        mpris_pb2.ChangePlayerStatusRequest(
                            player_id=player,
                            status=pbstatus.PAUSED,
                        )
                    )
                elif cmd == "play":
                    stub.ChangePlayerStatus(
                        mpris_pb2.ChangePlayerStatusRequest(
                            player_id=player,
                            status=pbstatus.PLAYING,
                        )
                    )
                elif cmd == "stop":
                    stub.ChangePlayerStatus(
                        mpris_pb2.ChangePlayerStatusRequest(
                            player_id=player,
                            status=pbstatus.STOPPED,
                        )
                    )
            except Exception:
                _LOGGER.exception("Cannot commandeer player %s", player)


def client(server: str) -> None:
    try:
        (
            client_cert,
            client_key,
            trust_chain,
        ) = certs.load_client_certs_and_trust_chain(config.folder())
        cakes_needed = False
    except FileNotFoundError:
        cakes_needed = True

    if cakes_needed:
        cakes_address = server + ":" + "40052"
        client_csr, client_key = certs.create_and_load_client_key_and_csr(
            config.folder()
        )
        requestor = CAKESRequestor(cakes_address, client_csr)
        client_cert, trust_chain = requestor.run()
        certs.save_client_certs_and_trust_chain(
            config.folder(),
            client_cert,
            client_key,
            trust_chain,
        )

    mpris_address = server + ":" + "40051"
    client = MPRISClient(mpris_address, client_cert, client_key, trust_chain)
    client.run()


def main() -> None:
    if not sys.argv[1:]:
        print("usage: %s <server>" % sys.argv[0])
        sys.exit(os.EX_USAGE)
    client(sys.argv[1])


if __name__ == "__main__":
    main()
