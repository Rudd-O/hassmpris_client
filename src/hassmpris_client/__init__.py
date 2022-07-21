import functools
import os
import ssl
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


__version__ = "0.0.18"

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


StubFunc = TypeVar("StubFunc", bound=Callable[..., Any])


def normalize_connection_errors(f: StubFunc) -> StubFunc:
    """
    Normalizes connection errors for easier handling.
    """

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
    """
    Normalizes connection errors in async generators for easier handling.
    """

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
    """
    The CAKES client class to securely pair an MPRIS client to the
    MPRIS desktop agent.

    This is a wrapper around cakes.client.AsyncCAKESClient that brings
    its own channel -- so you don't have to provide one.

    See file cli.py in the same folder as the file containing this class
    for a sample minimal client you can use in your own projects.
    """

    def __init__(
        self,
        host: str,
        port: int,
        csr: CertificateSigningRequest,
    ):
        """
        Initialize the CAKES client.

        Parameters:
          host: the host name to connect to
          port: the CAKES server port (customarily it is port 40052)
          csr:  a CertificateSigningRequest you provide, in order for the
                server to issue a valid certificate after successful pairing.
        """
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
    """
    A secure gRPC channel that overrides the hostname to an expected value.

    All HASS MPRIS servers use hostname 'hassmpris', because they are not
    bound to the global DNS system.  gRPC does not permit by default to
    override the server hostname, so we must add this glue to make this
    happen.
    """

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
    """
    The MPRIS client class to govern the MPRIS desktop agent remotely.

    See file cli.py in the same folder as the file containing this class
    for a sample minimal client you can use in your own projects.
    """

    def __init__(
        self,
        host: str,
        port: int,
        client_cert: Certificate,
        client_key: RSAPrivateKey,
        trust_chain: List[Certificate],
    ) -> None:
        """
        Initialize the client.

        You must already have the client_cert, client_key and trust_chain
        values.  If you don't, you must use the AsyncCAKESClient class to
        obtain it.

        Parameters:
          host: the host name to connect to
          port: the port (customarily, it is port 40051)
          client_cert, client_key, trust_chain: cryptographic material
                associated to your MPRIS agent.
        """
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
        """
        Clean up the client.

        Any concomitantly running stream_updates() will raise an exception and
        terminate execution.

        This method is called when the garbage collector disposes of the
        client, so you want to keep a reference to the client alive if you want
        this object to continue connected to the server.
        """
        self.__del__()

    @normalize_connection_errors
    async def ping(self) -> None:
        """
        Ping the server, verifying cryptography is working.

        A number of exceptions may be raised.  See the code for the function
        normalize_connection_errors to discover the most common exceptions your
        code will have to deal with.
        """
        await self.stub.Ping(Empty(), timeout=DEFAULT_TIMEOUT)

    @normalize_connection_errors_iterable
    async def stream_updates(
        self,
    ) -> AsyncGenerator[mpris_pb2.MPRISUpdateReply, None]:
        """
        Generate a stream of MPRISUpdateReply, yielding them asynchronously
        to the caller.

        This is an async generator.

        A number of exceptions may be raised.  See the code for the function
        normalize_connection_errors_iterable to discover the most common
        exceptions your code will have to deal with.
        """
        async with self.stub.Updates.open() as stream:
            await stream.send_message(mpris_pb2.MPRISUpdateRequest(), end=True)
            async for message in stream:
                yield message

    @normalize_connection_errors
    async def change_player_status(
        self,
        player_id: str,
        playback_status: int,
    ) -> mpris_pb2.ChangePlayerStatusReply:
        """
        Change player status to one of the states enumerated in
        mpris_pb2.ChangePlayerStatusRequest.PlaybackStatus.

        You want to use the direct methods pause, play or stop.
        """
        return await self.stub.ChangePlayerStatus(
            mpris_pb2.ChangePlayerStatusRequest(
                player_id=player_id,
                status=playback_status,
            ),
            timeout=DEFAULT_TIMEOUT,
        )

    async def pause(
        self,
        player_id: str,
    ) -> mpris_pb2.ChangePlayerStatusReply:
        """
        Tell the server to pause playback of one player.

        Parameters:
          player_id: a player ID as per one of the MPRISUpdateRequest received.

        A number of exceptions may be raised.  See the code for the function
        normalize_connection_errors to discover the most common exceptions your
        code will have to deal with.
        """
        pbstatus = mpris_pb2.ChangePlayerStatusRequest.PlaybackStatus
        return await self.change_player_status(player_id, pbstatus.PAUSED)

    async def play(
        self,
        player_id: str,
    ) -> mpris_pb2.ChangePlayerStatusReply:
        """
        Tell the server to begin playback in one player.

        Parameters:
          player_id: a player ID as per one of the MPRISUpdateRequest received.

        A number of exceptions may be raised.  See the code for the function
        normalize_connection_errors to discover the most common exceptions your
        code will have to deal with.
        """
        pbstatus = mpris_pb2.ChangePlayerStatusRequest.PlaybackStatus
        return await self.change_player_status(player_id, pbstatus.PLAYING)

    async def stop(
        self,
        player_id: str,
    ) -> mpris_pb2.ChangePlayerStatusReply:
        """
        Tell the server to stop playback of one player.

        Parameters:
          player_id: a player ID as per one of the MPRISUpdateRequest received.

        A number of exceptions may be raised.  See the code for the function
        normalize_connection_errors to discover the most common exceptions your
        code will have to deal with.
        """
        pbstatus = mpris_pb2.ChangePlayerStatusRequest.PlaybackStatus
        return await self.change_player_status(player_id, pbstatus.STOPPED)

    async def previous(
        self,
        player_id: str,
    ) -> mpris_pb2.PreviousReply:
        """
        Tells the server to skip one track backward in one player.

        Parameters:
          player_id: a player ID as per one of the MPRISUpdateRequest received.

        A number of exceptions may be raised.  See the code for the function
        normalize_connection_errors to discover the most common exceptions your
        code will have to deal with.
        """
        m = mpris_pb2.PreviousRequest(player_id=player_id)
        return await self.stub.Previous(m)

    async def next(
        self,
        player_id: str,
    ) -> mpris_pb2.PreviousReply:
        """
        Tells the server to skip one track forward in one player.

        Parameters:
          player_id: a player ID as per one of the MPRISUpdateRequest received.

        A number of exceptions may be raised.  See the code for the function
        normalize_connection_errors to discover the most common exceptions your
        code will have to deal with.
        """
        m = mpris_pb2.NextRequest(player_id=player_id)
        return await self.stub.Next(m)

    async def seek(
        self,
        player_id: str,
        offset: float,
    ) -> mpris_pb2.SeekReply:
        """
        Tells the server to seek within the current-playing track of a player.

        Parameters:
          player_id: a player ID as per one of the MPRISUpdateRequest received.
          offset: a positive or negative float indicating how many seconds to
            go forward or backward.

        A number of exceptions may be raised.  See the code for the function
        normalize_connection_errors to discover the most common exceptions your
        code will have to deal with.
        """
        m = mpris_pb2.SeekRequest(player_id=player_id, offset=offset)
        return await self.stub.Seek(m)

    async def set_position(
        self,
        player_id: str,
        track_id: str,
        position: float,
    ) -> mpris_pb2.SetPositionReply:
        """
        Tells the server to play the track ID from the currently playing track.

        Parameters:
          player_id: a player ID as per one of the MPRISUpdateRequest received.
          track_id: the string ID "mpris:trackid" sent by the player in the
            metadata update payload.  If this does not match the current track,
            the set position command will be ignored as stale.
          position: an absolute zero or positive float indicating how many
            seconds to go into the track from its beginning.

        See https://specifications.freedesktop.org/mpris-spec/2.2/Player_Interface.html#methods
        for more information.

        A number of exceptions may be raised.  See the code for the function
        normalize_connection_errors to discover the most common exceptions your
        code will have to deal with.
        """
        m = mpris_pb2.SetPositionRequest(
            player_id=player_id, track_id=track_id, position=position
        )
        return await self.stub.SetPosition(m)
