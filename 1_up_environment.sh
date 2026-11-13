#!/bin/bash
set -eo pipefail

CARLA_FOLDER_NAME="${CARLA_FOLDER_NAME:-carla-0-9-15}"
CONDA_ENV_NAME="${CONDA_ENV_NAME:-n4s_env}"
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
DBC_PATH="${DBC_PATH:-data/carla.dbc}"
VCAN_INTERFACE="${VCAN_INTERFACE:-vcan0}"
CLIENT_RES="960x540"
CAMERA_FPS="30"
CLIENT_FPS="60"
MAP_NAME=""
MINIMAL_MAP=false
NO_RENDERING=false

usage() {
    cat <<EOF
Usage: $0 [-h|--help] [--dbc <path>] [--performance] [--res WIDTHxHEIGHT]

Start the "Yes, CARLA CAN" simulation environment.

What this script does:
  1. Checks dependencies and creates the virtual CAN interfaces and can-gw routes
  2. Launches the CARLA simulator in off-screen, low-quality mode
  3. Waits 5 seconds for CARLA to initialise
  4. Starts the CARLA client and vehicle controls modules

Options:
  -h, --help      Show this help message and exit
  --dbc <path>    Path to the DBC file defining the virtual CAN network schema
                  (default: data/carla.dbc)
  --vcan <name>   Name of the virtual CAN interface to create (default: vcan0)
  --performance  Use Town02_Opt without optional scenery, at 800x450 and camera 30 FPS
                  (apply before overrides such as --res or --map)
  --res <WxH>    Window and camera resolution (default: 960x540)
  --camera-fps N Camera capture limit in simulation time (default: 30)
  --fps N        Client refresh limit (default: 60)
  --map <name>   Load a map before spawning (default: keep current map)
  --minimal-map  Remove optional layers; requires an _Opt map
  --no-rendering Disable graphics for CAN-only experiments (no camera image)

Environment variables:
  CARLA_FOLDER_NAME     Directory where CARLA is installed (default: carla-0-9-15)
  CONDA_ENV_NAME        Conda environment to use (default: n4s_env)
  DBC_PATH              DBC file path, overridden by --dbc if provided
  VCAN_INTERFACE        Virtual CAN interface name, overridden by --vcan if provided (default: vcan0)
  VK_ICD_FILENAMES      Force a specific Vulkan ICD file (skips auto-detection)
EOF
}

# Parse and validate options before launching processes or changing CAN interfaces.
while [[ $# -gt 0 ]]; do
    case "$1" in
        --dbc|--vcan|--res|--camera-fps|--fps|--map)
            if [[ $# -lt 2 || "$2" == --* || -z "$2" ]]; then
                echo "Missing value for $1" >&2
                exit 1
            fi ;;
    esac
    case "$1" in
        -h|--help) usage; exit 0 ;;
        --dbc) DBC_PATH="$2"; shift 2 ;;
        --vcan) VCAN_INTERFACE="$2"; shift 2 ;;
        --performance) CLIENT_RES="800x450"; MAP_NAME="Town02_Opt"; MINIMAL_MAP=true; shift ;;
        --res) CLIENT_RES="$2"; shift 2 ;;
        --camera-fps) CAMERA_FPS="$2"; shift 2 ;;
        --fps) CLIENT_FPS="$2"; shift 2 ;;
        --map) MAP_NAME="$2"; shift 2 ;;
        --minimal-map) MINIMAL_MAP=true; shift ;;
        --no-rendering) NO_RENDERING=true; shift ;;
        *) echo "Unknown argument: $1"; usage; exit 1 ;;
    esac
done

if [[ ! "$CLIENT_RES" =~ ^[1-9][0-9]*x[1-9][0-9]*$ ||
      ! "$CAMERA_FPS" =~ ^[1-9][0-9]*$ || ! "$CLIENT_FPS" =~ ^[1-9][0-9]*$ ]]; then
    echo "Invalid resolution or FPS: use positive WIDTHxHEIGHT and positive integer FPS." >&2
    exit 1
fi
if [[ "$MINIMAL_MAP" == true && -n "$MAP_NAME" && "$MAP_NAME" != *_Opt ]]; then
    echo "--minimal-map requires an _Opt map, e.g. Town02_Opt." >&2
    exit 1
fi
CLIENT_ARGS=(--vcan "$VCAN_INTERFACE" --res "$CLIENT_RES" --camera-fps "$CAMERA_FPS" --fps "$CLIENT_FPS")
[[ -n "$MAP_NAME" ]] && CLIENT_ARGS+=(--map "$MAP_NAME")
[[ "$MINIMAL_MAP" == true ]] && CLIENT_ARGS+=(--minimal-map)
[[ "$NO_RENDERING" == true ]] && CLIENT_ARGS+=(--no-rendering)

for tool in conda sudo ip modprobe cangw; do
    command -v "$tool" >/dev/null || { echo "Missing command: $tool. Run 0_install_dependencies.sh first." >&2; exit 1; }
done
CARLA_DIR="$CARLA_FOLDER_NAME"
[[ "$CARLA_DIR" != /* ]] && CARLA_DIR="${SCRIPT_DIR}/${CARLA_DIR}"
[[ -x "$CARLA_DIR/CarlaUE4.sh" ]] || { echo "CARLA executable not found: $CARLA_DIR/CarlaUE4.sh" >&2; exit 1; }
[[ -f "$DBC_PATH" ]] || { echo "DBC file not found: $DBC_PATH" >&2; exit 1; }
if [[ -e results/can_gateway_state.json ]]; then
    echo "Gateway recovery is pending. Stop attacks and run security_gateway_module.py --restore first." >&2
    exit 1
fi
if [[ "$VCAN_INTERFACE" == vcan1 ]] || ip link show dev "$VCAN_INTERFACE" >/dev/null 2>&1 || ip link show dev vcan1 >/dev/null 2>&1; then
    echo "Lab interfaces already exist or overlap. Stop the gateway and use 2_down_environment.sh before restarting." >&2
    exit 1
fi
conda run -n "$CONDA_ENV_NAME" python -c 'import can, cantools, carla, pygame, numpy'
sudo -v

# On hybrid Intel/NVIDIA systems, Vulkan may default to the Intel GPU and cause
# crashes. Force the NVIDIA ICD if available; otherwise fall back to the default.
# Skip auto-detection if the user already set VK_ICD_FILENAMES explicitly.
if [[ -n "${VK_ICD_FILENAMES}" ]]; then
    echo "VK_ICD_FILENAMES already set to '${VK_ICD_FILENAMES}'. Skipping auto-detection."
else
    NVIDIA_ICD=$(find /usr/share/vulkan/icd.d /etc/vulkan/icd.d -name "nvidia_icd*.json" -print -quit 2>/dev/null || true)
    if [[ -n "${NVIDIA_ICD}" ]]; then
        echo "NVIDIA Vulkan ICD detected (${NVIDIA_ICD}). Forcing VK_ICD_FILENAMES to use NVIDIA GPU."
        export VK_ICD_FILENAMES="${NVIDIA_ICD}"
    else
        echo "No NVIDIA Vulkan ICD found. Using system default GPU."
    fi
fi

# Roll back only interfaces created by this invocation if network setup fails.
CREATED_MAIN=false
CREATED_ATTACKER=false
cleanup_setup() {
    status=$?
    trap - ERR
    if [[ "$CREATED_ATTACKER" == true ]]; then sudo ip link delete vcan1 || true; fi
    if [[ "$CREATED_MAIN" == true ]]; then sudo ip link delete "$VCAN_INTERFACE" || true; fi
    echo "Virtual CAN setup failed; CARLA was not started." >&2
    exit "$status"
}
trap cleanup_setup ERR

echo "Setting up virtual CAN bus..."
sudo modprobe vcan
sudo modprobe can-gw
sudo ip link add dev "${VCAN_INTERFACE}" type vcan
CREATED_MAIN=true
sudo ip link set up "${VCAN_INTERFACE}"

# Set up attacker CAN bus and bridge it to the main bus via can-gw.
# Frames sent on vcan1 are forwarded to vcan0 and marked 'R' (received) by candump,
# while frames sent directly on vcan0 are marked 'T' (transmitted).
echo "Setting up attacker CAN bus and can-gw bridge..."
sudo ip link add dev vcan1 type vcan
CREATED_ATTACKER=true
sudo ip link set up vcan1
sudo cangw -A -s vcan1 -d "${VCAN_INTERFACE}" -e
sudo cangw -A -s "${VCAN_INTERFACE}" -d vcan1 -e
trap - ERR

echo "Starting CARLA simulator..."
"${CARLA_DIR}/CarlaUE4.sh" -RenderOffScreen -quality-level=Low -nosound \
    -ResX="${CLIENT_RES%x*}" -ResY="${CLIENT_RES#*x}" &

# Give CARLA a moment to initialise before connecting clients
echo "Waiting for CARLA to start..."
sleep 5

# Start CARLA client module in the background
echo "Starting CARLA client module..."
conda run -n "${CONDA_ENV_NAME}" python "${SCRIPT_DIR}/CARLA_client_module.py" "${CLIENT_ARGS[@]}" &

# Start vehicle controls module in the background
echo "Starting vehicle controls module..."
conda run -n "${CONDA_ENV_NAME}" python "${SCRIPT_DIR}/vehicle_controls_module.py" --dbc "${DBC_PATH}" --vcan "${VCAN_INTERFACE}" &

echo "Environment is up!"
