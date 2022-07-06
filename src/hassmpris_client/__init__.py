import errno
import functools
import logging
import os
import ssl
import sys
import tempfile

import grpclib.exceptions
from grpclib.client import Channel
from grpclib.protocol import H2Protocol
import _ssl
import asyncio

from typing import List, Tuple, cast, TypeVar, Callable, Any, AsyncGenerator

from cryptography.x509 import CertificateSigningRequest, Certificate
from cryptography.hazmat.primitives.asymmetric.rsa import (
    RSAPrivateKey,
)

import shortauthstrings  # noqa: E402

# FIXME: the next line should be fixed when Fedora has
# protoc 3.19.0 or later, and the protobufs need to be recompiled
# when that happens.  Not just the hassmpris protos, also the
# cakes ones.
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"

from google.protobuf.empty_pb2 import Empty  # noqa: E402
from hassmpris.proto import mpris_grpc  # noqa: E402

import cakes  # noqa: E402
import blindecdh  # noqa: E402

from hassmpris.proto import mpris_pb2  # noqa: E402
import hassmpris.certs as certs  # noqa: E402

from hassmpris import config  # noqa: E402


__version__ = "0.0.12"

_LOGGER = logging.getLogger(__name__)

DEFAULT_TIMEOUT = 15.0


Ignored = cakes.Ignored
Rejected = cakes.Rejected
CannotDecrypt = cakes.CannotDecrypt


class ClientException(Exception):
    """
    The base class for all HASS MPRIS client exceptions.
    """


class CannotConnect(ClientException):
    """
    The remote server is not running or refuses connections.
    """

    def __str__(self) -> str:
        f = "Server is not running or refuses connections: %s"
        return f % (self.args[0],)


class Unauthenticated(ClientException):
    """
    The server has not authenticated us.
    """

    def __str__(self) -> str:
        f = "Client is not authenticated: %s"
        return f % (self.args[0],)


class Disconnected(ClientException):
    """
    The server is now gone.
    """

    def __str__(self) -> str:
        f = "Server gone: %s"
        return f % (self.args[0],)


class Timeout(ClientException):
    """
    The connection to the server timed out.
    """

    def __str__(self) -> str:
        f = "Server timed out: %s"
        return f % (self.args[0],)


def accept_ecdh_via_console(
    peer: str,
    complete: blindecdh.CompletedECDH,
) -> bool:
    msg = f"""
A notification has appeared on the remote computer {peer}.
Please use it to verify that the key matches this computer's.
""".strip()
    print(msg)
    print(
        "The key on this side appears to be %s"
        % shortauthstrings.emoji(
            complete.derived_key,
            6,
        )
    )
    print("Accept?  [Y/N then ENTER]")
    line = sys.stdin.readline()
    result = line.lower().startswith("y")
    return result


StubFunc = TypeVar("StubFunc", bound=Callable[..., Any])


def normalize_connection_errors(f: StubFunc) -> StubFunc:
    @functools.wraps(f)
    async def inner(*args: Tuple[Any]) -> Any:
        try:
            return await f(*args)
        except ssl.SSLCertVerificationError as e:
            raise Unauthenticated(e)
        except ConnectionRefusedError as e:
            raise CannotConnect(e)
        except OSError as e:
            raise CannotConnect(e)
        except grpclib.exceptions.StreamTerminatedError as e:
            raise Disconnected(e)
        except asyncio.exceptions.TimeoutError as e:
            raise Timeout(e)

    return cast(StubFunc, inner)


def normalize_connection_errors_iterable(f: StubFunc) -> StubFunc:
    @functools.wraps(f)
    async def inner(*args: Tuple[Any]) -> Any:
        try:
            async for x in f(*args):
                yield x
        except ssl.SSLCertVerificationError as e:
            raise Unauthenticated(e)
        except ConnectionRefusedError as e:
            raise CannotConnect(e)
        except OSError as e:
            raise CannotConnect(e)
        except asyncio.exceptions.CancelledError as e:
            raise Disconnected(e)
        except grpclib.exceptions.StreamTerminatedError as e:
            raise Disconnected(e)
        except asyncio.exceptions.TimeoutError as e:
            raise Timeout(e)

    return cast(StubFunc, inner)


class AsyncCAKESClient(object):
    def __init__(
        self,
        host: str,
        port: int,
        csr: CertificateSigningRequest,
    ):
        self.channel = grpclib.client.Channel(host, port)
        self.client = cakes.AsyncCAKESClient(
            self.channel,
            csr,
        )
        self.ecdh: blindecdh.CompletedECDH | None = None

    def __del__(self) -> None:
        delattr(self, "client")
        self.channel.close()
        delattr(self, "channel")

    @normalize_connection_errors
    async def obtain_verifier(self) -> blindecdh.CompletedECDH:
        """
        Obtains the verifier with the derived_key attribute.

        Compare this derived_key with the counterparty's derived_key.

        If they do not match, DO NOT call obtain_certificate() --
        your communication is compromised.

        Refer to cakes.AsyncCAKESClient for more documentation.
        """
        self.ecdh = await self.client.obtain_verifier()
        return self.ecdh

    @normalize_connection_errors
    async def obtain_certificate(
        self,
    ) -> Tuple[Certificate, List[Certificate]]:  # noqa:E501
        """
        Obtains the signed client certificate and the trust chain.

        Only call when obtain_verifier()'s result has been verified
        to match on both sides.

        Refer to cakes.AsyncCAKESClient for more documentation.
        """
        assert self.ecdh, "did not run obtain_verifier"
        return await self.client.obtain_certificate(self.ecdh)


class MPRISChannel(Channel):
    """An overridden channel to permit me to change the server hostname."""

    def __init__(
        self,
        host: str,
        port: int,
        client_cert: Certificate,
        client_key: RSAPrivateKey,
        trust_chain: List[Certificate],
    ):
        self._client_cert = client_cert
        self._client_key = client_key
        self._trust_chain = trust_chain
        Channel.__init__(self, host, port, ssl=True)

    def _get_default_ssl_context(self) -> "_ssl.SSLContext":
        with tempfile.TemporaryDirectory() as d:
            certs.save_client_certs_and_trust_chain(
                d,
                self._client_cert,
                self._client_key,
                self._trust_chain,
            )
            c = os.path.join(d, "client.crt")
            k = os.path.join(d, "client.key")
            t = os.path.join(d, "client.trust.pem")
            ctx = ssl.create_default_context(
                purpose=ssl.Purpose.SERVER_AUTH,
            )
            ctx.load_cert_chain(c, k)
            ctx.load_verify_locations(cafile=t)
            ctx.check_hostname = True
            ciphers = "ECDHE+AESGCM:ECDHE+CHACHA20:DHE+AESGCM:DHE+CHACHA20"
            ctx.set_ciphers(ciphers)
            ctx.set_alpn_protocols(["h2"])
        return ctx

    async def _create_connection(self) -> H2Protocol:
        _, protocol = await self._loop.create_connection(
            self._protocol_factory,
            self._host,
            self._port,
            ssl=self._ssl,
            server_hostname="hassmpris",
        )
        return cast(H2Protocol, protocol)


class AsyncMPRISClient(object):
    """An overridden channel to permit me to change the server hostname."""

    def __init__(
        self,
        host: str,
        port: int,
        client_cert: Certificate,
        client_key: RSAPrivateKey,
        trust_chain: List[Certificate],
    ) -> None:
        self.host = host
        self.channel = MPRISChannel(
            host,
            port,
            client_cert,
            client_key,
            trust_chain,
        )
        self.stub = mpris_grpc.MPRISStub(channel=self.channel)

    def __del__(self) -> None:
        if hasattr(self, "stub"):
            delattr(self, "stub")
        if hasattr(self, "channel"):
            self.channel.close()
            delattr(self, "channel")

    async def close(self) -> None:
        self.__del__()

    @normalize_connection_errors
    async def ping(self) -> None:
        await self.stub.Ping(Empty(), timeout=DEFAULT_TIMEOUT)

    @normalize_connection_errors_iterable
    async def stream_updates(
        self,
    ) -> AsyncGenerator[mpris_pb2.MPRISUpdateReply, None]:
        async with self.stub.Updates.open() as stream:
            await stream.send_message(mpris_pb2.MPRISUpdateRequest(), end=True)
            async for message in stream:
                yield message

    @normalize_connection_errors
    async def change_player_status(
        self,
        player_id: str,
        playback_status: int,
    ) -> None:
        await self.stub.ChangePlayerStatus(
            mpris_pb2.ChangePlayerStatusRequest(
                player_id=player_id,
                status=playback_status,
            ),
            timeout=DEFAULT_TIMEOUT,
        )

    async def pause(self, player_id: str) -> None:
        pbstatus = mpris_pb2.ChangePlayerStatusRequest.PlaybackStatus
        return await self.change_player_status(player_id, pbstatus.PAUSED)

    async def play(self, player_id: str) -> None:
        pbstatus = mpris_pb2.ChangePlayerStatusRequest.PlaybackStatus
        return await self.change_player_status(player_id, pbstatus.PLAYING)

    async def stop(self, player_id: str) -> None:
        pbstatus = mpris_pb2.ChangePlayerStatusRequest.PlaybackStatus
        return await self.change_player_status(player_id, pbstatus.STOPPED)


async def repl(stub: AsyncMPRISClient, known_players: List[str]) -> None:
    print(
        "When you open an MPRIS-compatible player, you will see its name scroll onscreen."  # noqa: E501
    )
    print("Commands:")
    print("* play [optionally player name]  -- plays media on the player")
    print("* pause [optionally player name] -- pauses media on the player")
    print("* stop [optionally player name]  -- stops media on the player")
    print("* empty line                     -- exits the client")
    print()
    loop = asyncio.get_running_loop()
    fd = sys.stdin.fileno()
    while True:
        future = asyncio.Future()  # type: ignore
        loop.add_reader(fd, future.set_result, None)
        future.add_done_callback(lambda f: loop.remove_reader(fd))
        line = await future
        line = sys.stdin.readline()
        s = line.strip()
        if not s:
            return
        try:
            cmd, player = s.split(" ", 1)
        except ValueError:
            if not known_players:
                print(
                    "There is no last player to commandeer.",
                    file=sys.stderr,
                )
                continue
            cmd, player = s, known_players[-1]

        try:
            if cmd == "pause":
                await stub.pause(player)
            elif cmd == "play":
                await stub.play(player)
            elif cmd == "stop":
                await stub.stop(player)
        except Exception as e:
            print(
                "Cannot commandeer player %s because of error %s"
                % (
                    player,
                    e,
                ),
                file=sys.stderr,
            )


async def print_updates(
    mprisclient: AsyncMPRISClient,
    players: List[str],
) -> None:
    # FIXME: the server is not sending me the status of the player
    # when it initially streams the players it knows about.
    async for update in mprisclient.stream_updates():
        print(update)
        if update.HasField("player"):
            if update.player.status == mpris_pb2.PlayerStatus.GONE:
                while update.player.player_id in players:
                    players.remove(update.player.player_id)
            elif update.player.player_id not in players:
                players.append(update.player.player_id)


def usage() -> str:
    prog = sys.argv[0]
    usage_str = f"""
usage: {prog} <server> [ping]

If ping is specified as the second parameter, then the program will simply
attempt to ping the server and exit immediately if successful.

If ping is not specified, you get a rudimentary remote control.
""".strip()
    return usage_str


async def async_main() -> int:
    if not sys.argv[1:]:
        print(usage())
        return os.EX_USAGE
    server = sys.argv[1]
    action = sys.argv[2] if sys.argv[2:] else None

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
        client_csr, client_key = certs.create_and_load_client_key_and_csr(
            config.folder()
        )
        cakesclient = AsyncCAKESClient(
            server,
            40052,
            client_csr,
        )
        try:
            ecdh = await cakesclient.obtain_verifier()
        except Rejected as e:
            print("Not authorized: %s" % e)
            return errno.EACCES

        result = accept_ecdh_via_console(server, ecdh)
        if not result:
            print("Locally rejected.")
            return errno.EACCES

        try:
            client_cert, trust_chain = await cakesclient.obtain_certificate()
        except Rejected as e:
            print("Not authorized: %s" % e)
            return errno.EACCES

        certs.save_client_certs_and_trust_chain(
            config.folder(),
            client_cert,
            client_key,
            trust_chain,
        )

    mprisclient = AsyncMPRISClient(
        server,
        40051,
        client_cert,
        client_key,
        trust_chain,
    )
    try:
        if action == "ping":
            await mprisclient.ping()
            print("Successfully pinged the server.")
        else:
            players: List[str] = []

            replfuture = asyncio.create_task(
                repl(mprisclient, players),
            )
            updatesfuture = asyncio.create_task(
                print_updates(mprisclient, players),
            )

            try:
                done, pending = await asyncio.wait(
                    [
                        replfuture,
                        updatesfuture,
                    ],
                    return_when=asyncio.FIRST_COMPLETED,
                )
                done.pop().result()
            except Exception:
                os.close(0)
                raise

    except Unauthenticated:
        print("Server has reset its certificate store.")
        print("Remove client files in ~/.config/hassmpris to reauthenticate.")
        return errno.EACCES

    return 0


def main() -> None:
    sys.exit(asyncio.run(async_main()))


if __name__ == "__main__":
    main()
