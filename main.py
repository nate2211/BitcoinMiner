from __future__ import annotations

from btc_models import BtcMinerConfig
from btc_worker import BitcoinMinerWorker


def main() -> None:
    cfg = BtcMinerConfig(
        host="btc.hiveon.com",
        port=4444,
        login="bc1qp55qrhrrqt47d62w6x3me4alx70gqqsgkaew00.rig4060",
        password="x",
        use_tls=False,
        scan_backend="opencl",
        native_dll_path="BitcoinProject.dll",
        kernel_path="btc_sha256d_scan.cl",
        opencl_loader="OpenCL.dll",
        platform_index=0,
        device_index=0,
        local_work_size=128,
        scan_window_nonces=65_536,
        max_results_per_scan=8,
        reconnect_initial_delay_s=1.0,
        reconnect_max_delay_s=30.0,
        idle_reconnect_s=300.0,
        tcp_keepalive=True,
        tcp_keepidle_s=60,
        tcp_keepintvl_s=15,
        tcp_keepcnt=4,
    )

    worker = BitcoinMinerWorker(cfg)
    worker.run()


if __name__ == "__main__":
    main()