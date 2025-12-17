"""Helper for collecting GPU evidence via nv-ppcie-verifier.

This is executed in a separate Python environment to avoid dependency conflicts in the main app.
"""

import argparse
import ctypes
import ctypes.util
import json
import os
import sys
import traceback
import warnings


def _log(message: str) -> None:
    print(f"[ppcie_collect] {message}", file=sys.stderr, flush=True)


def _debug_enabled() -> bool:
    return os.getenv("GPU_EVIDENCE_DEBUG", "").strip().lower() in {"1", "true", "yes", "y", "on"}


def _debug(message: str) -> None:
    if _debug_enabled():
        _log(message)


def main() -> None:
    warnings.filterwarnings("ignore", category=SyntaxWarning)

    parser = argparse.ArgumentParser()
    parser.add_argument("--nonce", required=True)
    parser.add_argument("--no-gpu-mode", action="store_true")
    parser.add_argument(
        "--ppcie-mode",
        action=argparse.BooleanOptionalAction,
        default=True,
        help="Enable PPCIE mode in the verifier (default: enabled).",
    )
    args = parser.parse_args()

    if not args.no_gpu_mode:
        _debug(f"python={sys.executable} version={sys.version.split()[0]}")
        _debug(f"NVIDIA_VISIBLE_DEVICES={os.getenv('NVIDIA_VISIBLE_DEVICES')!r}")
        _debug(f"NVIDIA_DRIVER_CAPABILITIES={os.getenv('NVIDIA_DRIVER_CAPABILITIES')!r}")
        _debug(f"CUDA_VISIBLE_DEVICES={os.getenv('CUDA_VISIBLE_DEVICES')!r}")
        _debug(f"LD_LIBRARY_PATH={os.getenv('LD_LIBRARY_PATH')!r}")
        _debug(f"find_library('nvidia-ml')={ctypes.util.find_library('nvidia-ml')!r}")
        for path in (
            "/usr/lib/x86_64-linux-gnu/libnvidia-ml.so.1",
            "/usr/lib64/libnvidia-ml.so.1",
            "/usr/local/nvidia/lib64/libnvidia-ml.so.1",
            "/usr/local/nvidia/lib/libnvidia-ml.so.1",
        ):
            _debug(f"exists {path}={os.path.exists(path)}")
        for dev in ("/dev/nvidiactl", "/dev/nvidia0", "/dev/nvidia-uvm", "/dev/nvidia-uvm-tools"):
            _debug(f"exists {dev}={os.path.exists(dev)}")

        try:
            ctypes.CDLL("libnvidia-ml.so.1")
            _debug("loaded libnvidia-ml.so.1 successfully")
        except OSError as error:
            print(
                "NVML library not found (libnvidia-ml.so.1). "
                "Run this container with the NVIDIA Container Toolkit (e.g., `docker run --gpus all ...` "
                "or `docker compose` with `runtime: nvidia`). "
                f"Original error: {error}",
                file=sys.stderr,
            )
            sys.exit(2)

    try:
        from verifier import cc_admin
    except BaseException as error:
        _log(f"failed to import nv-ppcie-verifier ({type(error).__name__}): {error}")
        if _debug_enabled():
            traceback.print_exc(file=sys.stderr)
        sys.exit(2)

    _debug("starting cc_admin.collect_gpu_evidence_remote()")
    sys.stdout.flush()
    saved_stdout = os.dup(1)
    os.dup2(2, 1)
    try:
        evidence = cc_admin.collect_gpu_evidence_remote(
            args.nonce, no_gpu_mode=args.no_gpu_mode, ppcie_mode=args.ppcie_mode
        )
    except SystemExit as error:
        _log(f"nv-ppcie-verifier triggered SystemExit(code={error.code!r})")
        if _debug_enabled():
            traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    except BaseException as error:
        _log(f"GPU evidence collection failed ({type(error).__name__}): {error}")
        if _debug_enabled():
            traceback.print_exc(file=sys.stderr)
        sys.exit(1)
    finally:
        sys.stdout.flush()
        os.dup2(saved_stdout, 1)
        os.close(saved_stdout)

    if not isinstance(evidence, list) or not evidence:
        _log(f"cc_admin.collect_gpu_evidence_remote() returned empty/invalid evidence: {evidence!r}")
        sys.exit(1)
    _debug(f"collected {len(evidence)} GPU evidence items")
    json.dump(evidence, sys.stdout)
    sys.stdout.write("\n")


if __name__ == "__main__":
    main()
