"""Exercise client settings and map selection without a running CARLA server."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import pytest

import CARLA_client_module as client_module
from gui.camera_manager import CameraManager


@pytest.fixture
def session(monkeypatch):
    pygame = MagicMock()
    monkeypatch.setattr(client_module, "pygame", pygame)
    monkeypatch.setattr(client_module, "CAN_Network", MagicMock())
    monkeypatch.setattr(client_module, "CANTrafficDisplay", MagicMock())
    hud = MagicMock()
    monkeypatch.setattr(client_module, "HUD", hud)
    world = MagicMock()
    monkeypatch.setattr(client_module, "World", world)
    controller = MagicMock()
    # Render one frame, then exit through normal cleanup.
    controller.return_value.parse_events.side_effect = [False, True]
    monkeypatch.setattr(client_module, "KeyboardControl", controller)

    sim_world = MagicMock()
    sim_world.get_map.return_value.name = "/Game/Carla/Maps/Town02_Opt"
    original = SimpleNamespace(no_rendering_mode=True, synchronous_mode=False,
                               fixed_delta_seconds=None)
    configured = SimpleNamespace(**vars(original))
    sim_world.get_settings.side_effect = [original, configured, configured]
    client = MagicMock()
    client.get_world.return_value = sim_world
    client.load_world.return_value = sim_world
    monkeypatch.setattr(client_module.carla, "Client", MagicMock(return_value=client))
    args = SimpleNamespace(host="127.0.0.1", port=2000, vcan="vcan0", map=None,
                           minimal_map=False, no_rendering=False, sync=False,
                           autopilot=False, width=800, height=450, fps=60)
    return SimpleNamespace(args=args, client=client, sim_world=sim_world,
                           original=original, configured=configured,
                           pygame=pygame, hud=hud, world=world)


def test_requested_resolution_and_async_settings_are_restored(session):
    client_module.game_loop(session.args)
    assert session.pygame.display.set_mode.call_args.args[0] == (800, 450)
    session.hud.assert_called_once_with(800, 450)
    assert session.configured.no_rendering_mode is False
    assert session.original.no_rendering_mode is True
    assert session.sim_world.apply_settings.call_args_list[0].args[0] is session.configured
    assert session.sim_world.apply_settings.call_args_list[-1].args[0] is session.original
    session.pygame.time.Clock.return_value.tick.assert_called_with(60)
    session.pygame.time.Clock.return_value.tick_busy_loop.assert_not_called()
    session.client.load_world.assert_not_called()


def test_performance_map_loads_only_minimum_layers(session):
    session.args.map = "Town01_Opt"
    session.args.minimal_map = True
    client_module.game_loop(session.args)
    session.client.load_world.assert_called_once_with(
        "Town01_Opt", map_layers=client_module.carla.MapLayer.NONE)
    session.sim_world.unload_map_layer.assert_called_once_with(client_module.carla.MapLayer.All)


def test_current_map_is_not_reloaded(session):
    session.args.map = "Town02_Opt"
    session.args.minimal_map = True
    client_module.game_loop(session.args)
    session.client.load_world.assert_not_called()
    session.sim_world.unload_map_layer.assert_called_once()


def test_minimum_layers_reject_non_layered_map(session):
    session.args.minimal_map = True
    session.sim_world.get_map.return_value.name = "/Game/Carla/Maps/Town02"
    with pytest.raises(ValueError, match="requires a layered map"):
        client_module.game_loop(session.args)
    session.sim_world.unload_map_layer.assert_not_called()
    session.world.assert_not_called()


def test_no_rendering_is_explicit(session):
    session.args.no_rendering = True
    client_module.game_loop(session.args)
    assert session.configured.no_rendering_mode is True


def test_empty_gpu_sensor_data_does_not_attempt_image_conversion():
    manager = MagicMock()
    image = SimpleNamespace(raw_data=b"")
    CameraManager._parse_image(lambda: manager, image)
    manager.sensors.__getitem__.assert_not_called()


def test_sync_settings_and_traffic_manager_are_restored(session):
    session.args.sync = True
    client_module.game_loop(session.args)
    assert session.configured.synchronous_mode is True
    assert session.configured.fixed_delta_seconds == 0.05
    assert session.original.synchronous_mode is False
    tm_calls = session.client.get_trafficmanager.return_value.set_synchronous_mode.call_args_list
    assert [call.args[0] for call in tm_calls] == [True, False]
    assert session.sim_world.apply_settings.call_args.args[0] is session.original
