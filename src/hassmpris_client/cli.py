import errno
import os
import shlex
import sys

import asyncio


import shortauthstrings  # noqa: E402

# FIXME: the next line should be fixed when Fedora has
# protoc 3.19.0 or later, and the protobufs need to be recompiled
# when that happens.  Not just the hassmpris protos, also the
# cakes ones.
os.environ["PROTOCOL_BUFFERS_PYTHON_IMPLEMENTATION"] = "python"

from hassmpris_client import (  # noqa: E402
    AsyncMPRISClient,
    AsyncCAKESClient,
    Rejected,
    Unauthenticated,
)
import blindecdh  # noqa: E402

from hassmpris.proto import mpris_pb2  # noqa: E402
import hassmpris.certs as certs  # noqa: E402

from hassmpris import config  # noqa: E402


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


async def repl(stub: AsyncMPRISClient, known_players: list[str]) -> None:
    print(
        "When you open an MPRIS-compatible player, you will see its name scroll onscreen."  # noqa: E501
    )

    def help() -> None:
        print("Commands:")
        print(
            "* play [optionally player name]      \n"
            "  plays media on the player            "
        )
        print(
            "* pause [optionally player name]     \n"
            "  pauses media on the player           "
        )
        print(
            "* stop [optionally player name]      \n"
            "  stops media on the player            "
        )
        print(
            "* prev [optionally player name]      \n"
            "  skip to previous track               "
        )
        print(
            "* next [optionally player name]      \n"
            "  skip to next track                   "
        )
        print(
            "* seek <pos> [optionally player name]\n"
            "  seek player to pos (in seconds)      "
        )
        print(
            "* empty line                         \n"
            "  shows this help message              "
        )
        print(
            "* Ctrl+D / close stdin               \n"
            "  exits this client application        "
        )

    help()
    loop = asyncio.get_running_loop()
    fd = sys.stdin.fileno()
    while True:
        future = asyncio.Future()  # type: ignore
        loop.add_reader(fd, future.set_result, None)
        future.add_done_callback(lambda f: loop.remove_reader(fd))
        line = await future
        line = sys.stdin.readline()
        if not line:
            return
        s = line.strip()
        if not s:
            help()
            continue

        tokens = shlex.split(s)
        cmd, parms = tokens[0], tokens[1:]

        if cmd == "seek":
            if len(parms) == 1:
                if not known_players:
                    print(
                        "There is no last player to commandeer.",
                        file=sys.stderr,
                    )
                    continue
                offset, player = float(parms[0]), known_players[-1]
            elif len(parms) > 1:
                offset, player = float(parms[0]), parms[1]
            else:
                print(
                    "You must specify an offset to seek to",
                    file=sys.stderr,
                )
                continue
        else:
            if len(parms) == 0:
                if not known_players:
                    print(
                        "There is no last player to commandeer.",
                        file=sys.stderr,
                    )
                    continue
                player = known_players[-1]
            else:
                player = parms[0]

        try:
            if cmd == "pause":
                await stub.pause(player)
            elif cmd == "play":
                await stub.play(player)
            elif cmd == "stop":
                await stub.stop(player)
            elif cmd == "prev":
                await stub.previous(player)
            elif cmd == "next":
                await stub.next(player)
            elif cmd == "seek":
                await stub.seek(player, offset)
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
    players: list[str],
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
            players: list[str] = []

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
