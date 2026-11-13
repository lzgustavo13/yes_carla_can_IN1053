#!/usr/bin/env python

# Copyright (c) 2019 Computer Vision Center (CVC) at the Universitat Autonoma de
# Barcelona (UAB).
#
# This work is licensed under the terms of the MIT license.
# For a copy, see <https://opensource.org/licenses/MIT>.

import argparse
import glob
import logging
import os
import signal
import sys

try:
    sys.path.append(
        glob.glob(
            "../carla/dist/carla-*%d.%d-%s.egg"
            % (
                sys.version_info.major,
                sys.version_info.minor,
                "win-amd64" if os.name == "nt" else "linux-x86_64",
            )
        )[0]
    )
except IndexError:
    pass

import carla
import pygame

from can_network.network import CAN_Network, VCAN_CHANNEL
from gui import CANTrafficDisplay, HUD, KeyboardControl, World


def game_loop(args):
    pygame.init()
    pygame.font.init()

    world = None
    original_settings = None
    traffic_manager = None
    can_bus = CAN_Network(channel=args.vcan)
    can_display = CANTrafficDisplay(channel=args.vcan)

    try:
        client = carla.Client(args.host, args.port)
        client.set_timeout(2000.0)

        sim_world = client.get_world()
        if args.map:
            current_map = sim_world.get_map().name.rsplit("/", 1)[-1]
            if current_map != args.map.rsplit("/", 1)[-1]:
                layers = carla.MapLayer.NONE if args.minimal_map else carla.MapLayer.All
                sim_world = client.load_world(args.map, map_layers=layers)
        if args.minimal_map:
            if not sim_world.get_map().name.endswith("_Opt"):
                raise ValueError("--minimal-map requires a layered map, e.g. --map Town02_Opt")
            sim_world.unload_map_layer(carla.MapLayer.All)

        # Save settings before changing them, including in asynchronous mode.
        original_settings = sim_world.get_settings()
        settings = sim_world.get_settings()
        settings.no_rendering_mode = args.no_rendering

        if args.sync:
            if not settings.synchronous_mode:
                settings.synchronous_mode = True
                settings.fixed_delta_seconds = 0.05
        sim_world.apply_settings(settings)
        if args.sync:
            traffic_manager = client.get_trafficmanager()
            traffic_manager.set_synchronous_mode(True)

        if args.autopilot and not sim_world.get_settings().synchronous_mode:
            print(
                "WARNING: You are currently in asynchronous mode and could "
                "experience some issues with the traffic simulation"
            )

        display = pygame.display.set_mode(
            (args.width, args.height), pygame.HWSURFACE | pygame.DOUBLEBUF
        )
        display.fill((0, 0, 0))
        pygame.display.flip()

        hud = HUD(args.width, args.height)
        world = World(sim_world, hud, args, can_bus)
        controller = KeyboardControl(world, args.autopilot)

        if args.sync:
            sim_world.tick()
        else:
            sim_world.wait_for_tick()

        clock = pygame.time.Clock()
        while True:
            if args.sync:
                sim_world.tick()
            clock.tick(args.fps)
            if controller.parse_events(client, world, clock, args.sync, can_bus):
                return
            world.tick(clock)
            display.fill((0, 0, 0))
            world.render(display)
            can_display.render(display)
            pygame.display.flip()

    finally:
        # Stop CARLA sensor streams first so the server can close sessions cleanly
        # before any other teardown that might talk to the server or tear down the
        # CAN interface.
        if world is not None:
            try:
                world.destroy()
            except Exception:
                pass

        can_display.stop()
        can_bus.bus.shutdown()

        try:
            if original_settings:
                if traffic_manager is not None and not original_settings.synchronous_mode:
                    traffic_manager.set_synchronous_mode(False)
                sim_world.apply_settings(original_settings)
        except Exception:
            pass

        try:
            if world and world.recording_enabled:
                client.stop_recorder()
        except Exception:
            pass

        pygame.quit()


def main():
    argparser = argparse.ArgumentParser(description="CARLA Manual Control Receiver Client")
    argparser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        dest="debug",
        help="print debug information",
    )
    argparser.add_argument(
        "--host",
        metavar="H",
        default="127.0.0.1",
        help="IP of the host server (default: 127.0.0.1)",
    )
    argparser.add_argument(
        "-p",
        "--port",
        metavar="P",
        default=2000,
        type=int,
        help="TCP port to listen to (default: 2000)",
    )
    argparser.add_argument(
        "-a", "--autopilot", action="store_true", help="enable autopilot"
    )
    argparser.add_argument(
        "--res",
        metavar="WIDTHxHEIGHT",
        default="960x540",
        help="window and camera resolution (default: 960x540)",
    )
    argparser.add_argument(
        "--filter",
        metavar="PATTERN",
        default="vehicle.*",
        help='actor filter (default: "vehicle.*")',
    )
    argparser.add_argument(
        "--generation",
        metavar="G",
        default="2",
        help='restrict to certain actor generation (values: "1","2","All" - default: "2")',
    )
    argparser.add_argument(
        "--rolename",
        metavar="NAME",
        default="hero",
        help='actor role name (default: "hero")',
    )
    argparser.add_argument(
        "--gamma",
        default=2.2,
        type=float,
        help="Gamma correction of the camera (default: 2.2)",
    )
    argparser.add_argument(
        "--sync", action="store_true", help="Activate synchronous mode execution"
    )
    argparser.add_argument("--fps", type=int, default=60,
                           help="maximum client refresh rate (default: 60)")
    argparser.add_argument("--camera-fps", type=int, default=30,
                           help="maximum camera capture rate in simulation time (default: 30)")
    argparser.add_argument("--map", help="load a map before spawning, e.g. Town02_Opt")
    argparser.add_argument("--minimal-map", action="store_true",
                           help="remove optional layers from an _Opt map (keeps roads and traffic signals)")
    argparser.add_argument("--no-rendering", action="store_true",
                           help="disable graphics for CAN-only experiments; camera images will be unavailable")
    argparser.add_argument(
        "--vcan",
        default=VCAN_CHANNEL,
        help=f"Virtual CAN interface name (default: {VCAN_CHANNEL})",
    )
    args = argparser.parse_args()

    try:
        args.width, args.height = [int(x) for x in args.res.split("x")]
        if min(args.width, args.height, args.fps, args.camera_fps) <= 0:
            raise ValueError
    except ValueError:
        argparser.error("--res must be WIDTHxHEIGHT with positive dimensions; FPS values must be positive")

    log_level = logging.DEBUG if args.debug else logging.INFO
    logging.basicConfig(format="%(levelname)s: %(message)s", level=log_level)
    logging.info("listening to server %s:%s", args.host, args.port)

    print(__doc__)

    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))

    try:
        game_loop(args)
    except KeyboardInterrupt:
        print("\nCancelled by user. Bye!")


if __name__ == "__main__":
    main()
