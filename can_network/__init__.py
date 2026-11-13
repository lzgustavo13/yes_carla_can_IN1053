from .constants import VCAN_CHANNEL, VCAN_ATTACKER_CHANNEL, CAN_INTERFACE


def __getattr__(name):
    # DBC tools and the security gateway do not require CARLA.
    if name == "CAN_Network":
        from .network import CAN_Network
        return CAN_Network
    raise AttributeError(name)

__all__ = [
    "CAN_Network",
    "VCAN_CHANNEL",
    "VCAN_ATTACKER_CHANNEL",
    "CAN_INTERFACE",
]
